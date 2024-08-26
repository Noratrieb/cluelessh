mod auth;
mod pty;

use std::{io, net::SocketAddr, process::ExitStatus, sync::Arc};

use auth::AuthError;
use cluelessh_keys::{private::EncryptedPrivateKeys, public::PublicKey};
use cluelessh_tokio::{server::ServerAuthVerify, Channel};
use cluelessh_transport::server::ServerConfig;
use eyre::{bail, eyre, Context, OptionExt, Result};
use pty::Pty;
use rustix::termios::Winsize;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::mpsc,
};
use tracing::{debug, error, info, info_span, warn, Instrument};

use cluelessh_protocol::{
    connection::{ChannelKind, ChannelOperationKind, ChannelRequest},
    ChannelUpdateKind, SshStatus,
};
use tracing_subscriber::EnvFilter;
use users::os::unix::UserExt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let addr = "0.0.0.0:2223".to_owned();

    let addr = addr
        .parse::<SocketAddr>()
        .wrap_err_with(|| format!("failed to parse listen addr '{addr}'"))?;

    info!(%addr, "Starting server");

    let listener = TcpListener::bind(addr).await.wrap_err("binding listener")?;

    let auth_verify = ServerAuthVerify {
        verify_password: None,
        verify_signature: Some(Arc::new(|auth| {
            Box::pin(async move {
                let Ok(public_key) = PublicKey::from_wire_encoding(&auth.pubkey) else {
                    return Ok(false);
                };
                if auth.pubkey_alg_name != public_key.algorithm_name() {
                    return Ok(false);
                }

                let result: std::result::Result<auth::UserPublicKey, AuthError> =
                    auth::UserPublicKey::for_user_and_key(auth.user.clone(), &public_key).await;

                debug!(user = %auth.user, err = ?result.as_ref().err(), "Attempting publickey signature");

                match result {
                    Ok(user_key) => {
                        // Verify signature...

                        let sign_data = cluelessh_keys::signature::signature_data(
                            auth.session_identifier,
                            &auth.user,
                            &public_key,
                        );

                        if user_key.verify_signature(&sign_data, &auth.signature) {
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    }
                    Err(
                        AuthError::UnknownUser
                        | AuthError::UnauthorizedPublicKey
                        | AuthError::NoAuthorizedKeys(_),
                    ) => Ok(false),
                    Err(AuthError::InvalidAuthorizedKeys(err)) => Err(eyre!(err)),
                }
            })
        })),
        check_pubkey: Some(Arc::new(|auth| {
            Box::pin(async move {
                let Ok(public_key) = PublicKey::from_wire_encoding(&auth.pubkey) else {
                    return Ok(false);
                };
                if auth.pubkey_alg_name != public_key.algorithm_name() {
                    return Ok(false);
                }
                let result =
                    auth::UserPublicKey::for_user_and_key(auth.user.clone(), &public_key).await;

                debug!(user = %auth.user, err = ?result.as_ref().err(), "Attempting publickey check");

                match result {
                    Ok(_) => Ok(true),
                    Err(
                        AuthError::UnknownUser
                        | AuthError::UnauthorizedPublicKey
                        | AuthError::NoAuthorizedKeys(_),
                    ) => Ok(false),
                    Err(AuthError::InvalidAuthorizedKeys(err)) => Err(eyre!(err)),
                }
            })
        })),
        auth_banner: Some("welcome to my server!!!\r\ni hope you enjoy your stay.\r\n".to_owned()),
    };

    let mut host_keys = Vec::new();

    let host_key_locations = ["/etc/ssh/ssh_host_ed25519_key", "./test_ed25519_key"];

    for host_key_location in host_key_locations {
        match tokio::fs::read_to_string(host_key_location).await {
            Ok(key) => {
                let key = EncryptedPrivateKeys::parse(key.as_bytes())
                    .wrap_err_with(|| format!("invalid {host_key_location}"))?;
                if key.requires_passphrase() {
                    bail!("{host_key_location} must not require a passphrase");
                }
                let mut key = key
                    .decrypt(None)
                    .wrap_err_with(|| format!("invalid {host_key_location}"))?;
                if key.len() != 1 {
                    bail!("{host_key_location} must contain a single key");
                }
                host_keys.push(key.remove(0));

                info!(?host_key_location, "Loaded host key")
            }
            Err(err) => {
                debug!(?err, ?host_key_location, "Failed to load host key")
            }
        }
    }

    if host_keys.is_empty() {
        bail!("no host keys found");
    }

    let config = ServerConfig { host_keys };

    let mut listener = cluelessh_tokio::server::ServerListener::new(listener, auth_verify, config);

    loop {
        let next = listener.accept().await?;
        let span = info_span!("connection", addr = %next.peer_addr());
        tokio::spawn(
            async move {
                if let Err(err) = handle_connection(next).await {
                    if let Some(err) = err.downcast_ref::<std::io::Error>() {
                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                            return;
                        }
                    }

                    error!(?err, "error handling connection");
                }
                info!("Finished connection");
            }
            .instrument(span),
        );
    }
}

async fn handle_connection(
    mut conn: cluelessh_tokio::server::ServerConnection<TcpStream>,
) -> Result<()> {
    info!(addr = %conn.peer_addr(), "Received a new connection");

    let mut channel_tasks = Vec::new();

    loop {
        tokio::select! {
            step = conn.progress() => match step {
                Ok(()) => {}
                Err(cluelessh_tokio::server::Error::ServerError(err)) => {
                    return Err(err.wrap_err("encountered server error during connection"));
                }
                Err(cluelessh_tokio::server::Error::SshStatus(status)) => match status {
                    SshStatus::PeerError(err) => {
                        info!(?err, "disconnecting client after invalid operation");
                        return Ok(());
                    }
                    SshStatus::Disconnect => {
                        info!("Received disconnect from client");
                        return Ok(());
                    }
                },
            },
            result = futures::future::try_join_all(&mut channel_tasks), if !channel_tasks.is_empty() => {
                match result {
                    Ok(_) => channel_tasks.clear(),
                    Err(err) => return Err((err as eyre::Report).wrap_err("channel task failed")),
                }
            },
        }

        while let Some(channel) = conn.next_new_channel() {
            let user = conn.inner().authenticated_user().unwrap().to_owned();
            if *channel.kind() == ChannelKind::Session {
                let channel_task = tokio::spawn(handle_session_channel(user, channel));
                channel_tasks.push(Box::pin(async {
                    let result = channel_task.await;
                    result.wrap_err("task panicked").and_then(|result| result)
                }));
            } else {
                warn!("Trying to open non-session channel");
            }
        }
    }
}

struct SessionState {
    user: String,
    pty: Option<Pty>,
    channel: Channel,
    process_exit_send: mpsc::Sender<Result<ExitStatus, io::Error>>,
    process_exit_recv: mpsc::Receiver<Result<ExitStatus, io::Error>>,

    writer: Option<File>,
    reader: Option<File>,
}

async fn handle_session_channel(user: String, channel: Channel) -> Result<()> {
    let (process_exit_send, process_exit_recv) = tokio::sync::mpsc::channel(1);

    let mut state = SessionState {
        user,
        pty: None,
        channel,
        process_exit_send,
        process_exit_recv,
        writer: None,
        reader: None,
    };

    let mut read_buf = [0; 1024];

    loop {
        let read = async {
            match &mut state.reader {
                Some(file) => file.read(&mut read_buf).await,
                // Ensure that if this is None, the future never finishes so the state update and process exit can progress.
                None => loop {
                    tokio::task::yield_now().await;
                },
            }
        };
        tokio::select! {
            update = state.channel.next_update() => {
                match update {
                    Ok(update) => state.handle_channel_update(update).await?,
                    Err(err) => return Err(err),
                }
            }
            exit = state.process_exit_recv.recv() => {
                if let Some(exit) = exit {
                    let exit = exit?;
                    state.channel.send(ChannelOperationKind::Eof).await?;
                    // TODO: also handle exit-signal
                    state.channel
                        .send(ChannelOperationKind::Request(ChannelRequest::ExitStatus {
                            status: exit.code().unwrap_or(0) as u32,
                        }))
                    .await?;
                    state.channel.send(ChannelOperationKind::Close).await?;
                    return Ok(());
                }
            }
            read = read => {
                let Ok(read) = read else {
                    bail!("failed to read");
                };
                let _ = state.channel.send(ChannelOperationKind::Data(read_buf[..read].to_vec())).await;
            }
        }
    }
}

impl SessionState {
    async fn handle_channel_update(&mut self, update: ChannelUpdateKind) -> Result<()> {
        match update {
            ChannelUpdateKind::Request(req) => {
                match req {
                    ChannelRequest::PtyReq {
                        want_reply,
                        term,
                        width_chars,
                        height_rows,
                        width_px,
                        height_px,
                        term_modes,
                    } => {
                        match self
                            .pty_req(
                                term,
                                Winsize {
                                    ws_row: height_rows as u16,
                                    ws_col: width_chars as u16,
                                    ws_xpixel: width_px as u16,
                                    ws_ypixel: height_px as u16,
                                },
                                term_modes,
                            )
                            .await
                        {
                            Ok(()) => {
                                if want_reply {
                                    self.channel.send(ChannelOperationKind::Success).await?;
                                }
                            }
                            Err(err) => {
                                debug!(%err, "Failed to open PTY");
                                if want_reply {
                                    self.channel.send(ChannelOperationKind::Failure).await?;
                                }
                            }
                        }
                    }
                    ChannelRequest::Shell { want_reply } => match self.shell().await {
                        Ok(()) => {
                            if want_reply {
                                self.channel.send(ChannelOperationKind::Success).await?;
                            }
                        }
                        Err(err) => {
                            debug!(%err, "Failed to spawn shell");
                            if want_reply {
                                self.channel.send(ChannelOperationKind::Failure).await?;
                            }
                        }
                    },
                    ChannelRequest::Exec { .. } => {
                        todo!()
                    }
                    ChannelRequest::ExitStatus { .. } => {}
                    ChannelRequest::Env { .. } => {}
                };
            }
            ChannelUpdateKind::OpenFailed { .. } => todo!(),
            ChannelUpdateKind::Data { data } => {
                if let Some(writer) = &mut self.writer {
                    writer.write_all(&data).await?;
                }
            }
            ChannelUpdateKind::Open(_)
            | ChannelUpdateKind::Closed
            | ChannelUpdateKind::ExtendedData { .. }
            | ChannelUpdateKind::Eof
            | ChannelUpdateKind::Success
            | ChannelUpdateKind::Failure => { /* ignore */ }
        }
        Ok(())
    }

    async fn pty_req(&mut self, term: String, winsize: Winsize, term_modes: Vec<u8>) -> Result<()> {
        let pty = pty::Pty::new(term, winsize, term_modes).await?;
        let controller = pty.controller().try_clone_to_owned()?;

        self.pty = Some(pty);
        self.writer = Some(File::from_std(std::fs::File::from(controller.try_clone()?)));
        self.reader = Some(File::from_std(std::fs::File::from(controller)));
        Ok(())
    }

    async fn shell(&mut self) -> Result<()> {
        let user = self.user.clone();
        let user = tokio::task::spawn_blocking(move || users::get_user_by_name(&user))
            .await?
            .ok_or_eyre("failed to find user")?;

        let shell = user.shell();

        let mut cmd = Command::new(shell);
        cmd.env_clear();

        if let Some(pty) = &self.pty {
            pty.start_session_for_command(&mut cmd)?;
        }

        // TODO: **user** home directory
        cmd.current_dir(user.home_dir());
        cmd.env("USER", user.name());
        cmd.uid(user.uid());
        cmd.gid(user.primary_group_id());

        debug!(cmd = %shell.display(), uid = %user.uid(), gid = %user.primary_group_id(), "Executing process");

        let mut shell = cmd.spawn()?;

        let process_exit_send = self.process_exit_send.clone();
        tokio::spawn(async move {
            let result = shell.wait().await;
            let _ = process_exit_send.send(result).await;
        });
        debug!("Successfully spawned shell");
        Ok(())
    }
}
