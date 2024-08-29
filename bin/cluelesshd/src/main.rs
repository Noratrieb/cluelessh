mod auth;
mod config;
mod connection;
mod pty;
mod rpc;
mod sandbox;

use std::{
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
    net::SocketAddr,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    process::Stdio,
};

use clap::Parser;
use cluelessh_keys::{
    host_keys::HostKeySet,
    private::{EncryptedPrivateKeys, PlaintextPrivateKey},
    public::PublicKey,
};
use config::Config;
use eyre::{bail, eyre, Context, Result};
use rustix::fs::MemfdFlags;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use tracing_subscriber::EnvFilter;

#[derive(clap::Parser)]
struct Args {
    /// The path to the config file
    #[arg(long)]
    config: Option<PathBuf>,
}

fn main() -> eyre::Result<()> {
    match std::env::var("CLUELESSH_PRIVSEP_PROCESS") {
        Ok(privsep_process) => match privsep_process.as_str() {
            "connection" => {
                if let Err(err) = connection::connection() {
                    error!(?err, "Error in connection child process");
                }
                Ok(())
            }
            _ => bail!("unknown CLUELESSH_PRIVSEP_PROCESS: {privsep_process}"),
        },
        Err(_) => {
            // Initial setup
            let args = Args::parse();

            let config = config::Config::find(&args)?;

            setup_tracing(&config);

            if !rustix::process::getuid().is_root() {
                warn!("Daemon not started as root. This disables several security mitigations and permits logging in as any other user");
            }

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(main_process(config))
        }
    }
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

const PRIVSEP_CONNECTION_STATE_FD: RawFd = 3;
const PRIVSEP_CONNECTION_STREAM_FD: RawFd = 4;
const PRIVSEP_CONNECTION_RPC_CLIENT_FD: RawFd = 5;

/// The connection state passed to the child in the STATE_FD
#[derive(Serialize, Deserialize)]
struct SerializedConnectionState {
    peer_addr: SocketAddr,
    pub_host_keys: Vec<PublicKey>,
    config: Config,

    setuid: Option<u32>,
    setgid: Option<u32>,
}

async fn main_process(config: Config) -> Result<()> {
    let user = match &config.security.unprivileged_user {
        Some(user) => Some(
            users::get_user_by_name(user).ok_or_else(|| eyre!("unprivileged {user} not found"))?,
        ),
        None => None,
    };

    let is_root = rustix::process::getuid().is_root();

    if !is_root {
        info!("Not running as root, disabling unprivileged setuid");
    }

    let setuid = match (is_root, &config.security.unprivileged_uid, &user) {
        (false, _, _) => None,
        (true, Some(uid), _) => Some(*uid),
        (true, None, Some(user)) => Some(user.uid()),
        (true, None, None) => None,
    };
    let setgid = match (is_root, &config.security.unprivileged_gid, &user) {
        (false, _, _) => None,
        (true, Some(uid), _) => Some(*uid),
        (true, None, Some(user)) => Some(user.primary_group_id()),
        (true, None, None) => None,
    };

    let host_keys = load_host_keys(&config.auth.host_keys).await?.into_keys();

    if host_keys.is_empty() {
        bail!("no host keys found");
    }

    let pub_host_keys = host_keys
        .iter()
        .map(|key| key.private_key.public_key())
        .collect::<Vec<_>>();

    let addr: SocketAddr = SocketAddr::new(config.net.ip, config.net.port);
    info!(%addr, "Starting server");

    let listener = TcpListener::bind(addr)
        .await
        .wrap_err_with(|| format!("trying to listen on {addr}"))?;

    loop {
        let (next_stream, peer_addr) = listener.accept().await?;

        let config = config.clone();
        let pub_host_keys = pub_host_keys.clone();
        let host_keys = host_keys.clone();
        tokio::spawn(async move {
            let err = spawn_connection_child(
                next_stream,
                peer_addr,
                pub_host_keys,
                config,
                host_keys,
                setuid,
                setgid,
            )
            .await;
            if let Err(err) = err {
                error!(?err, "child failed");
            }
        });
    }
}

async fn spawn_connection_child(
    stream: TcpStream,
    peer_addr: SocketAddr,
    pub_host_keys: Vec<PublicKey>,
    config: Config,
    host_keys: Vec<PlaintextPrivateKey>,
    setuid: Option<u32>,
    setgid: Option<u32>,
) -> Result<()> {
    let stream_fd = stream.as_raw_fd();

    let mut rpc_server = rpc::Server::new(host_keys).wrap_err("creating RPC server")?;

    let rpc_client_fd = rpc_server.client_fd().as_raw_fd();

    let state_fd = MemFd::new(&SerializedConnectionState {
        peer_addr,
        pub_host_keys,
        config,
        setuid,
        setgid,
    })?;

    let exe = std::env::current_exe().wrap_err("failed to get current executable path")?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.env("CLUELESSH_PRIVSEP_PROCESS", "connection")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    unsafe {
        let state_fd = state_fd.fd.as_raw_fd();
        cmd.pre_exec(move || {
            let mut new_state_fd = OwnedFd::from_raw_fd(PRIVSEP_CONNECTION_STATE_FD);
            let mut new_stream_fd = OwnedFd::from_raw_fd(PRIVSEP_CONNECTION_STREAM_FD);
            let mut new_rpc_client_fd = OwnedFd::from_raw_fd(PRIVSEP_CONNECTION_RPC_CLIENT_FD);

            rustix::io::dup2(BorrowedFd::borrow_raw(state_fd), &mut new_state_fd)?;
            rustix::io::dup2(BorrowedFd::borrow_raw(stream_fd), &mut new_stream_fd)?;
            rustix::io::dup2(
                BorrowedFd::borrow_raw(rpc_client_fd),
                &mut new_rpc_client_fd,
            )?;

            // Ensure that all FDs are closed except stdout (for logging), and the 3 arguments.
            drop(rustix::stdio::take_stdin());
            // libc close_range is not async-signal-safe, so syscall directly.
            let result = libc::syscall(
                libc::SYS_close_range,
                (PRIVSEP_CONNECTION_RPC_CLIENT_FD as u32) + 1,
                std::ffi::c_uint::MAX,
                0,
            );
            if result.is_negative() {
                return Err(std::io::Error::from_raw_os_error(-(result as i32)));
            }

            // Ensure our new FDs stay open, as they will be acquired in the new process.
            std::mem::forget((new_state_fd, new_stream_fd, new_rpc_client_fd));
            Ok(())
        });
    }

    let mut listen_child = cmd.spawn().wrap_err("failed to spawn listener process")?;

    let mut exited = false;

    tokio::select! {
        server_err = rpc_server.process() => {
            error!(err = ?server_err, "RPC server error");
        }
        status = listen_child.wait() => {
            let status = status?;
            if !status.success() {
                bail!("connection child process failed: {}", status);
            }
            exited = true;
        }
    }

    if !exited {
        let status = listen_child.wait().await?;
        if !status.success() {
            bail!("connection child process failed: {}", status);
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

fn setup_tracing(config: &Config) {
    // Log to stdout
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
