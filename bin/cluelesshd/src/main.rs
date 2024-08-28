mod auth;
mod config;
mod connection;
mod pty;
mod rpc;

use std::{
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    process::Stdio,
    sync::Arc,
};

use clap::Parser;
use cluelessh_keys::{host_keys::HostKeySet, private::EncryptedPrivateKeys, public::PublicKey};
use cluelessh_tokio::server::{ServerAuth, SignWithHostKey};
use config::Config;
use eyre::{bail, Context, OptionExt, Result};
use rustix::fs::MemfdFlags;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use tracing_subscriber::EnvFilter;

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
            "connection" => connection::connection().await,
            _ => bail!("unknown CLUELESSH_PRIVSEP_PROCESS: {privsep_process}"),
        },
        Err(_) => {
            // Initial setup
            let args = Args::parse();

            let config = config::Config::find(&args)?;

            setup_tracing(&config);

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

    loop {
        let (next_stream, peer_addr) = listener.accept().await?;

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

fn setup_tracing(config: &Config) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
