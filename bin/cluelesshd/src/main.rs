mod pty;

use std::{io, net::SocketAddr, process::ExitStatus, sync::Arc};

use cluelessh_tokio::{server::ServerAuthVerify, Channel};
use eyre::{bail, Context, OptionExt, Result};
use pty::Pty;
use rustix::termios::Winsize;
use tokio::{
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

    let addr = "0.0.0.0:2222".to_owned();

    let addr = addr
        .parse::<SocketAddr>()
        .wrap_err_with(|| format!("failed to parse listen addr '{addr}'"))?;

    info!(%addr, "Starting server");

    let listener = TcpListener::bind(addr).await.wrap_err("binding listener")?;

    let auth_verify = ServerAuthVerify {
        verify_password: None,
        verify_signature: Some(Arc::new(|auth| {
            Box::pin(async move {
                debug!(user = %auth.user, "Attempting publickey login");
                warn!("Letting in unauthenticated user");
                Ok(true)
            })
        })),
        check_pubkey: Some(Arc::new(|auth| {
            Box::pin(async move {
                debug!(user = %auth.user, "Attempting publickey check");
                warn!("Letting in unauthenticated user");
                Ok(true)
            })
        })),
        auth_banner: Some("welcome to my server!!!\r\ni hope you enjoy your stay.\r\n".to_owned()),
    };

    let mut listener = cluelessh_tokio::server::ServerListener::new(listener, auth_verify);

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

    loop {
        match conn.progress().await {
            Ok(()) => {}
            Err(cluelessh_tokio::server::Error::ServerError(err)) => {
                return Err(err);
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
        }

        while let Some(channel) = conn.next_new_channel() {
            let user = conn.inner().authenticated_user().unwrap().to_owned();
            if *channel.kind() == ChannelKind::Session {
                tokio::spawn(async move {
                    let _ = handle_session_channel(user, channel).await;
                });
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
}

async fn handle_session_channel(user: String, channel: Channel) -> Result<()> {
    let (process_exit_send, process_exit_recv) = tokio::sync::mpsc::channel(1);

    let mut state = SessionState {
        user,
        pty: None,
        channel,
        process_exit_send,
        process_exit_recv,
    };

    loop {
        let pty_read = async {
            match &mut state.pty {
                Some(pty) => pty.ctrl_read_recv.recv().await,
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
                match exit {
                    Some(exit) => {
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
                    None => {}
                }
            }
            read = pty_read => {
                let Some(read) = read else {
                    bail!("failed to read");
                };
                let _ = state.channel.send(ChannelOperationKind::Data(read)).await;
            }
        }
    }
}

impl SessionState {
    async fn handle_channel_update(&mut self, update: ChannelUpdateKind) -> Result<()> {
        match update {
            ChannelUpdateKind::Request(req) => {
                let success = ChannelOperationKind::Success;
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
                        self.pty = Some(
                            pty::Pty::new(
                                term,
                                Winsize {
                                    ws_row: height_rows as u16,
                                    ws_col: width_chars as u16,
                                    ws_xpixel: width_px as u16,
                                    ws_ypixel: height_px as u16,
                                },
                                term_modes,
                            )
                            .await?,
                        );
                        if want_reply {
                            self.channel.send(success).await?;
                        }
                    }
                    ChannelRequest::Shell { want_reply } => {
                        let user = self.user.clone();
                        let user =
                            tokio::task::spawn_blocking(move || users::get_user_by_name(&user))
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

                        let mut shell = cmd.spawn()?;
                        let process_exit_send = self.process_exit_send.clone();
                        tokio::spawn(async move {
                            let result = shell.wait().await;
                            let _ = process_exit_send.send(result).await;
                        });
                        if want_reply {
                            self.channel.send(success).await?;
                        }
                    }
                    ChannelRequest::Exec { .. } => {
                        todo!()
                    }
                    ChannelRequest::ExitStatus { .. } => {}
                    ChannelRequest::Env { .. } => {}
                };
            }
            ChannelUpdateKind::OpenFailed { .. } => todo!(),
            ChannelUpdateKind::Data { data } => match &mut self.pty {
                Some(pty) => {
                    pty.ctrl_write_send.send(data).await?;
                }
                None => {}
            },
            ChannelUpdateKind::Open(_)
            | ChannelUpdateKind::Closed
            | ChannelUpdateKind::ExtendedData { .. }
            | ChannelUpdateKind::Eof
            | ChannelUpdateKind::Success
            | ChannelUpdateKind::Failure => { /* ignore */ }
        }
        Ok(())
    }
}
