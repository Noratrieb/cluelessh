mod auth;
mod config;
mod pty;
mod rpc;

use std::{
    io::{self, Read, Seek, SeekFrom},
    marker::PhantomData,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    pin::Pin,
    process::{ExitStatus, Stdio},
    sync::Arc,
};

use clap::Parser;
use cluelessh_keys::{host_keys::HostKeySet, private::EncryptedPrivateKeys, public::PublicKey};
use cluelessh_tokio::{
    server::{ServerAuth, ServerConnection, SignWithHostKey},
    Channel,
};
use config::Config;
use eyre::{bail, Context, OptionExt, Result};
use pty::Pty;
use rustix::{fs::MemfdFlags, termios::Winsize};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::mpsc,
};
use tracing::{debug, error, info, info_span, warn, Instrument};

use cluelessh_protocol::{
    auth::{CheckPubkey, VerifySignature},
    connection::{ChannelKind, ChannelOperationKind, ChannelRequest},
    ChannelUpdateKind, SshStatus,
};
use tracing_subscriber::EnvFilter;
use users::os::unix::UserExt;

#[derive(clap::Parser)]
struct Args {
    /// The path to the config file
    #[arg(long)]
    config: Option<PathBuf>,
}

struct MemFd<T> {
    fd: std::fs::File,
    _data: PhantomData<T>,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> MemFd<T> {
    fn new(data: &T) -> Result<Self> {
        let fd = rustix::fs::memfd_create("cluelesshd.toml", MemfdFlags::empty())
            .wrap_err("failed to memfd memfd")?;
        let mut fd: std::fs::File = std::fs::File::from(fd);
        std::io::Write::write_all(&mut fd, &postcard::to_allocvec(data)?)
            .wrap_err("failed to write config")?;

        Ok(Self {
            fd,
            _data: PhantomData,
        })
    }

    unsafe fn from_raw_fd(fd: RawFd) -> Result<Self> {
        let fd = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Self {
            fd,
            _data: PhantomData,
        })
    }

    fn read(&mut self) -> Result<T> {
        self.fd.seek(SeekFrom::Start(0))?;
        let mut data = Vec::new();
        self.fd.read_to_end(&mut data).wrap_err("reading data")?;
        postcard::from_bytes(&data).wrap_err("failed to deserialize")
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    match std::env::var("CLUELESSH_PRIVSEP_PROCESS") {
        Ok(privsep_process) => match privsep_process.as_str() {
            "connection" => connnection().await,
            _ => bail!("unknown CLUELESSH_PRIVSEP_PROCESS: {privsep_process}"),
        },
        Err(_) => {
            // Initial setup
            let args = Args::parse();

            let config = config::Config::find(&args)?;

            let env_filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

            tracing_subscriber::fmt().with_env_filter(env_filter).init();
            let addr: SocketAddr = SocketAddr::new(config.net.ip, config.net.port);
            info!(%addr, "Starting server");

            let listener = TcpListener::bind(addr)
                .await
                .wrap_err_with(|| format!("trying to listen on {addr}"))?;

            main_process(config, listener).await
        }
    }
}

const PRIVSEP_CONNECTION_STATE_FD: RawFd = 3;

/// The connection state passed to the child in the STATE_FD
#[derive(Serialize, Deserialize)]
struct SerializedConnectionState {
    stream_fd: RawFd,
    peer_addr: SocketAddr,
    pub_host_keys: Vec<PublicKey>,
    config: Config,
    rpc_client_fd: RawFd,
}

async fn connnection() -> Result<()> {
    rustix::fs::fcntl_getfd(unsafe { BorrowedFd::borrow_raw(PRIVSEP_CONNECTION_STATE_FD) })
        .unwrap();
    let mut memfd =
        unsafe { MemFd::<SerializedConnectionState>::from_raw_fd(PRIVSEP_CONNECTION_STATE_FD) }
            .wrap_err("failed to open memfd")?;
    let state = memfd.read().wrap_err("failed to read state")?;

    let config = state.config;

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let span = info_span!("connection", addr = %state.peer_addr);

    let stream = unsafe { std::net::TcpStream::from_raw_fd(state.stream_fd) };
    let stream = TcpStream::from_std(stream)?;

    let host_keys = state.pub_host_keys;
    let transport_config = cluelessh_transport::server::ServerConfig { host_keys };

    let rpc_client = unsafe { OwnedFd::from_raw_fd(state.rpc_client_fd) };
    let rpc_client1 = Arc::new(rpc::Client::from_fd(rpc_client)?);
    let rpc_client2 = rpc_client1.clone();
    let rpc_client3 = rpc_client1.clone();

    let auth_verify = ServerAuth {
        verify_password: config.auth.password_login.then(|| todo!("password login")),
        verify_signature: Some(Arc::new(move |msg: VerifySignature| {
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
        check_pubkey: Some(Arc::new(move |msg: CheckPubkey| {
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
        sign_with_hostkey: Arc::new(move |msg: SignWithHostKey| {
            let rpc_client = rpc_client3.clone();
            Box::pin(async move { rpc_client.sign(msg.hash, msg.public_key).await })
        }),
    };

    let server_conn = ServerConnection::new(stream, state.peer_addr, auth_verify, transport_config);

    connection_inner(server_conn).instrument(span).await;

    Ok(())
}

async fn connection_inner(server_conn: ServerConnection<TcpStream>) {
    if let Err(err) = handle_connection(server_conn).await {
        if let Some(err) = err.downcast_ref::<std::io::Error>() {
            if err.kind() == std::io::ErrorKind::ConnectionReset {
                return;
            }
        }

        error!(?err, "error handling connection");
    }
    info!("Finished connection");
}

async fn main_process(config: Config, listener: TcpListener) -> Result<()> {
    let host_keys = load_host_keys(&config.auth.host_keys).await?.into_keys();

    if host_keys.is_empty() {
        bail!("no host keys found");
    }

    let pub_host_keys = host_keys
        .iter()
        .map(|key| key.private_key.public_key())
        .collect::<Vec<_>>();

    let auth_operations = ServerAuth {
        verify_password: config
            .auth
            .clone()
            .password_login
            .then(|| todo!("password login")),
        verify_signature: Some(Arc::new(|auth| Box::pin(auth::verify_signature(auth)))),
        check_pubkey: Some(Arc::new(|auth| Box::pin(auth::check_pubkey(auth)))),
        auth_banner: config.auth.clone().banner,
        sign_with_hostkey: Arc::new(move |msg: SignWithHostKey| {
            let host_keys = host_keys.clone();
            Box::pin(async move {
                let private = host_keys
                    .iter()
                    .find(|privkey| privkey.private_key.public_key() == msg.public_key)
                    .ok_or_eyre("missing private key")?;

                Ok(private.private_key.sign(&msg.hash))
            })
        }),
    };

    // let server_config = ServerConfig {
    //     host_keys: pub_host_keys,
    // };

    loop {
        let (next_stream, peer_addr) = listener.accept().await?;

        // let server_conn = cluelessh_tokio::server::ServerConnection::new(
        //     next_stream,
        //     peer_addr,
        //     auth_verify.clone(),
        //     server_config.clone(),
        // );

        let config = config.clone();
        let pub_host_keys = pub_host_keys.clone();
        let auth_operations = auth_operations.clone();
        tokio::spawn(async move {
            let err = spawn_connection_child(
                next_stream,
                peer_addr,
                pub_host_keys,
                config,
                auth_operations,
            )
            .await;
            if let Err(err) = err {
                error!(?err, "child failed");
            }
        });

        //tokio::spawn(
        //    async move {
        //        if let Err(err) = handle_connection(server_conn).await {
        //            if let Some(err) = err.downcast_ref::<std::io::Error>() {
        //                if err.kind() == std::io::ErrorKind::ConnectionReset {
        //                    return;
        //                }
        //            }
        //
        //            error!(?err, "error handling connection");
        //        }
        //        info!("Finished connection");
        //    }
        //    .instrument(span),
        //);
    }
}

async fn spawn_connection_child(
    stream: TcpStream,
    peer_addr: SocketAddr,
    pub_host_keys: Vec<PublicKey>,
    config: Config,
    auth_operations: ServerAuth,
) -> Result<()> {
    let stream_fd = stream.as_fd();

    let rpc_server = rpc::Server::new(auth_operations).wrap_err("creating RPC server")?;

    // dup to avoid cloexec
    // TODO: we should probably do this in the child? not that it matters that much.
    let stream_fd = rustix::io::dup(stream_fd).wrap_err("duping tcp stream")?;
    let rpc_client_fd = rustix::io::dup(rpc_server.client_fd()).wrap_err("duping tcp stream")?;

    let config_fd = MemFd::new(&SerializedConnectionState {
        stream_fd: stream_fd.as_raw_fd(),
        peer_addr,
        pub_host_keys,
        config,
        rpc_client_fd: rpc_client_fd.as_raw_fd(),
    })?;

    let exe = std::env::current_exe().wrap_err("failed to get current executable path")?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.env("CLUELESSH_PRIVSEP_PROCESS", "connection")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    unsafe {
        let fd = config_fd.fd.as_raw_fd();
        cmd.pre_exec(move || {
            let mut state_fd = OwnedFd::from_raw_fd(PRIVSEP_CONNECTION_STATE_FD);
            rustix::io::dup2(BorrowedFd::borrow_raw(fd), &mut state_fd)?;
            // Ensure that it stays open in the child.
            std::mem::forget(state_fd);
            Ok(())
        });
    }

    let mut listen_child = cmd.spawn().wrap_err("failed to spawn listener process")?;

    loop {
        tokio::select! {
            server_err = rpc_server.process() => {
                error!(err = ?server_err, "RPC server error");
            }
            status = listen_child.wait() => {
                let status = status?;
                if !status.success() {
                    bail!("connection child process failed: {}", status);
                }
                break;
            }
        }
    }

    Ok(())
}

async fn load_host_keys(keys: &[PathBuf]) -> Result<HostKeySet> {
    let mut host_keys = HostKeySet::new();

    for key_path in keys {
        load_host_key(key_path, &mut host_keys)
            .await
            .wrap_err_with(|| format!("loading host key at '{}'", key_path.display()))?;
    }

    Ok(host_keys)
}

async fn load_host_key(key_path: &PathBuf, host_keys: &mut HostKeySet) -> Result<()> {
    let key = tokio::fs::read_to_string(key_path)
        .await
        .wrap_err("failed to open")?;
    let key = EncryptedPrivateKeys::parse(key.as_bytes()).wrap_err("failed to parse")?;

    if key.requires_passphrase() {
        bail!("host key requires a passphrase, which is not allowed");
    }
    let mut key = key.decrypt(None).wrap_err("failed to parse")?;
    if key.len() != 1 {
        bail!("host key must contain a single key");
    }
    let key = key.remove(0);
    let algorithm = key.private_key.algorithm_name();
    host_keys.insert(key)?;

    info!(?key_path, ?algorithm, "Loaded host key");
    Ok(())
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

    envs: Vec<(String, String)>,

    //// stdin
    writer: Option<Pin<Box<dyn AsyncWrite + Send + Sync>>>,
    /// stdout
    reader: Option<Pin<Box<dyn AsyncRead + Send + Sync>>>,
    /// stderr
    reader_ext: Option<Pin<Box<dyn AsyncRead + Send + Sync>>>,
}

async fn handle_session_channel(user: String, channel: Channel) -> Result<()> {
    let (process_exit_send, process_exit_recv) = tokio::sync::mpsc::channel(1);

    let mut state = SessionState {
        user,
        pty: None,
        channel,
        process_exit_send,
        process_exit_recv,
        envs: Vec::new(),
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

    async fn pty_req(&mut self, term: String, winsize: Winsize, term_modes: Vec<u8>) -> Result<()> {
        let pty = pty::Pty::new(term, winsize, term_modes).await?;
        let controller = pty.controller().try_clone_to_owned()?;

        self.pty = Some(pty);
        self.writer = Some(Box::pin(File::from_std(std::fs::File::from(
            controller.try_clone()?,
        ))));
        self.reader = Some(Box::pin(File::from_std(std::fs::File::from(controller))));
        Ok(())
    }

    async fn shell(&mut self, shell_command: Option<&str>) -> Result<()> {
        let user = self.user.clone();
        let user = tokio::task::spawn_blocking(move || users::get_user_by_name(&user))
            .await?
            .ok_or_eyre("failed to find user")?;

        let shell = user.shell();

        let mut cmd = Command::new(shell);
        if let Some(shell_command) = shell_command {
            cmd.arg("-c");
            cmd.arg(shell_command);
        }
        cmd.env_clear();

        if let Some(pty) = &self.pty {
            pty.start_session_for_command(&mut cmd)?;
        } else {
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        // TODO: **user** home directory
        cmd.current_dir(user.home_dir());
        cmd.env("USER", user.name());
        cmd.uid(user.uid());
        cmd.gid(user.primary_group_id());

        for (k, v) in &self.envs {
            cmd.env(k, v);
        }

        debug!(cmd = %shell.display(), uid = %user.uid(), gid = %user.primary_group_id(), "Executing process");

        let mut shell = cmd.spawn()?;

        if self.pty.is_none() {
            let stdin = shell.stdin.take().unwrap();
            let stdout = shell.stdout.take().unwrap();
            let stderr = shell.stderr.take().unwrap();

            self.writer = Some(Box::pin(stdin));
            self.reader = Some(Box::pin(stdout));
            self.reader_ext = Some(Box::pin(stderr));
        }

        let process_exit_send = self.process_exit_send.clone();
        tokio::spawn(async move {
            let result = shell.wait().await;
            let _ = process_exit_send.send(result).await;
        });
        debug!("Successfully spawned shell");
        Ok(())
    }
}
