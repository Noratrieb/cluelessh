use std::{
    os::fd::{FromRawFd, OwnedFd},
    path::Path,
    pin::Pin,
    sync::Arc,
};

use crate::{
    rpc, MemFd, SerializedConnectionState, PRIVSEP_CONNECTION_RPC_CLIENT_FD,
    PRIVSEP_CONNECTION_STATE_FD, PRIVSEP_CONNECTION_STREAM_FD,
};
use cluelessh_protocol::{
    connection::{ChannelKind, ChannelOperationKind, ChannelRequest},
    ChannelUpdateKind, SshStatus,
};
use cluelessh_tokio::{
    server::{ServerAuth, ServerConnection},
    Channel,
};
use eyre::{bail, ensure, Result, WrapErr};
use rustix::{
    fs::UnmountFlags,
    process::WaitOptions,
    thread::{Pid, UnshareFlags},
};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
use tracing::{debug, error, info, info_span, warn, Instrument};

pub async fn connection() -> Result<()> {
    let mut memfd =
        unsafe { MemFd::<SerializedConnectionState>::from_raw_fd(PRIVSEP_CONNECTION_STATE_FD) }
            .wrap_err("failed to open memfd")?;
    let state = memfd.read().wrap_err("failed to read state")?;

    crate::setup_tracing(&state.config);

    let span = info_span!("connection", addr = %state.peer_addr);

    connection_inner(state).instrument(span).await
}

async fn connection_inner(state: SerializedConnectionState) -> Result<()> {
    let config = state.config;

    if rustix::process::getuid().is_root() {
        unshare_namespaces()?;
    }

    if let Some(uid) = state.setgid {
        debug!(?uid, "Setting GID to drop privileges");
        let result = unsafe { libc::setgid(uid) };
        if result == -1 {
            return Err(std::io::Error::last_os_error()).wrap_err("failed to setgid");
        }
    }
    if let Some(uid) = state.setuid {
        debug!(?uid, "Setting UID to drop privileges");
        let result = unsafe { libc::setuid(uid) };
        if result == -1 {
            return Err(std::io::Error::last_os_error()).wrap_err("failed to setuid");
        }
    }

    let stream = unsafe { std::net::TcpStream::from_raw_fd(PRIVSEP_CONNECTION_STREAM_FD) };
    let stream = TcpStream::from_std(stream)?;

    let host_keys = state.pub_host_keys;
    let transport_config = cluelessh_transport::server::ServerConfig { host_keys };

    let rpc_client = unsafe { OwnedFd::from_raw_fd(PRIVSEP_CONNECTION_RPC_CLIENT_FD) };
    let rpc_client1 = Arc::new(rpc::Client::from_fd(rpc_client)?);
    let rpc_client2 = rpc_client1.clone();
    let rpc_client3 = rpc_client1.clone();
    let rpc_client4 = rpc_client1.clone();

    let auth_verify = ServerAuth {
        verify_password: config.auth.password_login.then(|| todo!("password login")),
        verify_signature: Some(Arc::new(move |msg| {
            let rpc_client = rpc_client1.clone();
            Box::pin(async move {
                rpc_client
                    .verify_signature(
                        msg.user,
                        msg.session_identifier,
                        msg.pubkey_alg_name,
                        msg.pubkey,
                        msg.signature,
                    )
                    .await
            })
        })),
        check_pubkey: Some(Arc::new(move |msg| {
            let rpc_client = rpc_client2.clone();
            Box::pin(async move {
                rpc_client
                    .check_pubkey(
                        msg.user,
                        msg.session_identifier,
                        msg.pubkey_alg_name,
                        msg.pubkey,
                    )
                    .await
            })
        })),
        auth_banner: config.auth.banner,
        sign_with_hostkey: Arc::new(move |msg| {
            let rpc_client = rpc_client3.clone();
            Box::pin(async move { rpc_client.sign(msg.hash, msg.public_key).await })
        }),
    };

    let server_conn = ServerConnection::new(stream, state.peer_addr, auth_verify, transport_config);

    if let Err(err) = handle_connection(server_conn, rpc_client4).await {
        if let Some(err) = err.downcast_ref::<std::io::Error>() {
            if err.kind() == std::io::ErrorKind::ConnectionReset {
                return Ok(());
            }
        }

        error!(?err, "error handling connection");
    }
    info!("Finished connection");

    Ok(())
}

fn unshare_namespaces() -> Result<()> {
    // The complicated incarnation to get a mount namespace working.
    rustix::thread::unshare(
        UnshareFlags::NEWNS
            | UnshareFlags::NEWNET
            | UnshareFlags::NEWIPC
            | UnshareFlags::NEWPID
            | UnshareFlags::NEWTIME,
    )
    .wrap_err("unsharing namespaces")?;

    // After creating the PID namespace, we fork immediately so we can get PID 1.
    // We never exec, we just let the child live on happily.
    // The parent immediately waits for it, and then doesn't do anything really.
    // TODO: this is a bit sus....
    unsafe {
        let result = libc::fork();
        if result == -1 {
            return Err(std::io::Error::last_os_error()).wrap_err("setting propagation flags")?;
        }
        if result > 0 {
            // Parent
            let code = rustix::process::waitpid(
                Some(Pid::from_raw_unchecked(result)),
                WaitOptions::empty(),
            );
            match code {
                Err(_) => libc::exit(2),
                Ok(None) => libc::exit(1),
                Ok(Some(code)) => libc::exit(code.as_raw() as i32),
            }
        }
    }

    let result = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error()).wrap_err("setting propagation flags")?;
    }

    let new_root = Path::new("empty-new-root");
    let old_root = &new_root.join("old-root");

    std::fs::create_dir_all(new_root)?;
    std::fs::create_dir_all(&old_root)?;

    rustix::fs::bind_mount(new_root, new_root).wrap_err("bind mount the empty dir")?;

    rustix::process::pivot_root(new_root, old_root).wrap_err("pivoting root")?;

    // TODO: can we get rid of it entirely?
    rustix::fs::unmount("/old-root", UnmountFlags::DETACH).wrap_err("unmounting old root")?;

    Ok(())
}

async fn handle_connection(
    mut conn: cluelessh_tokio::server::ServerConnection<TcpStream>,
    rpc_client: Arc<rpc::Client>,
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
                        debug!("Received disconnect from client");
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
            let _user = conn.inner().authenticated_user().unwrap().to_owned();
            if *channel.kind() == ChannelKind::Session {
                let channel_task =
                    tokio::spawn(handle_session_channel(channel, rpc_client.clone()));
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
    pty_term: Option<String>,
    channel: Channel,
    process_exit_send: mpsc::Sender<Result<Option<i32>>>,
    process_exit_recv: mpsc::Receiver<Result<Option<i32>>>,

    envs: Vec<(String, String)>,

    rpc_client: Arc<rpc::Client>,

    //// stdin
    writer: Option<Pin<Box<dyn AsyncWrite + Send + Sync>>>,
    /// stdout
    reader: Option<Pin<Box<dyn AsyncRead + Send + Sync>>>,
    /// stderr
    reader_ext: Option<Pin<Box<dyn AsyncRead + Send + Sync>>>,
}

async fn handle_session_channel(channel: Channel, rpc_client: Arc<rpc::Client>) -> Result<()> {
    let (process_exit_send, process_exit_recv) = tokio::sync::mpsc::channel(1);

    let mut state = SessionState {
        pty_term: None,
        channel,
        process_exit_send,
        process_exit_recv,
        envs: Vec::new(),

        rpc_client,

        writer: None,
        reader: None,
        reader_ext: None,
    };

    let mut read_buf = [0; 1024];
    let mut read_ext_buf = [0; 1024];

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
        let read_ext = async {
            match &mut state.reader_ext {
                Some(file) => file.read(&mut read_ext_buf).await,
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
                            status: exit.unwrap_or(1) as u32,
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
                if read == 0 {
                    // EOF, close the stream.
                    state.reader = None;
                } else {
                    let _ = state.channel.send(ChannelOperationKind::Data(read_buf[..read].to_vec())).await;
                }
            }
            read = read_ext => {
                let Ok(read) = read else {
                    bail!("failed to read");
                };
                if read == 0 {
                    // EOF, close the stream.
                    state.reader_ext = None;
                } else {
                    let _ = state.channel.send(ChannelOperationKind::ExtendedData(1, read_ext_buf[..read].to_vec())).await;
                }
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
                                height_rows,
                                width_chars,
                                width_px,
                                height_px,
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
                    ChannelRequest::Shell { want_reply } => match self.shell(None).await {
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
                    ChannelRequest::Exec {
                        want_reply,
                        command,
                    } => match String::from_utf8(command) {
                        Ok(command) => match self.shell(Some(&command)).await {
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
                        Err(err) => {
                            debug!(%err, "Exec command is invalid UTF-8");

                            if want_reply {
                                self.channel.send(ChannelOperationKind::Failure).await?;
                            }
                        }
                    },
                    ChannelRequest::Env {
                        name,
                        value,
                        want_reply,
                    } => match String::from_utf8(value) {
                        Ok(value) => {
                            self.envs.push((name, value));
                            if want_reply {
                                self.channel.send(ChannelOperationKind::Success).await?;
                            }
                        }
                        Err(_) => {
                            debug!("Trying to set");
                            if want_reply {
                                self.channel.send(ChannelOperationKind::Failure).await?;
                            }
                        }
                    },
                    ChannelRequest::ExitStatus { .. } => unreachable!("forbidden"),
                };
            }
            ChannelUpdateKind::OpenFailed { .. } => todo!(),
            ChannelUpdateKind::Data { data } => {
                if let Some(writer) = &mut self.writer {
                    writer.write_all(&data).await?;
                }
            }
            ChannelUpdateKind::Eof => {
                if let Some(writer) = &mut self.writer {
                    writer.shutdown().await?;
                }
                self.writer = None;
            }
            ChannelUpdateKind::Open(_)
            | ChannelUpdateKind::Closed
            | ChannelUpdateKind::ExtendedData { .. }
            | ChannelUpdateKind::Success
            | ChannelUpdateKind::Failure => { /* ignore */ }
        }
        Ok(())
    }

    async fn pty_req(
        &mut self,
        term: String,

        width_chars: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
        term_modes: Vec<u8>,
    ) -> Result<()> {
        let mut fd = self
            .rpc_client
            .pty_req(width_chars, height_rows, width_px, height_px, term_modes)
            .await?;

        ensure!(
            fd.len() == 1,
            "Incorrect amount of FDs received: {}",
            fd.len()
        );

        self.pty_term = Some(term);

        let controller = fd.remove(0);
        self.writer = Some(Box::pin(File::from_std(std::fs::File::from(
            controller.try_clone()?,
        ))));
        self.reader = Some(Box::pin(File::from_std(std::fs::File::from(controller))));
        Ok(())
    }

    async fn shell(&mut self, shell_command: Option<&str>) -> Result<()> {
        let mut fds = self
            .rpc_client
            .shell(
                shell_command.map(ToOwned::to_owned),
                self.pty_term.clone(),
                self.envs.clone(),
            )
            .await?;

        if self.pty_term.is_some() {
            ensure!(
                fds.len() == 0,
                "RPC Server sent back FDs despite being in PTY mode"
            );
        } else {
            ensure!(
                fds.len() == 3,
                "RPC Server sent back the wrong amount of FDs: {}",
                fds.len()
            );

            let stdin = File::from_std(std::fs::File::from(fds.remove(0)));
            let stdout = File::from_std(std::fs::File::from(fds.remove(0)));
            let stderr = File::from_std(std::fs::File::from(fds.remove(0)));

            self.writer = Some(Box::pin(stdin));
            self.reader = Some(Box::pin(stdout));
            self.reader_ext = Some(Box::pin(stderr));
        }

        let process_exit_send = self.process_exit_send.clone();
        let client = self.rpc_client.clone();
        tokio::spawn(async move {
            let result = client.wait().await;
            let _ = process_exit_send.send(result).await;
        });
        debug!("Successfully spawned shell");
        Ok(())
    }
}
