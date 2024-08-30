//! [`postcard`]-based RPC between the different processes.

use std::fmt::Debug;
use std::io;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::process::Stdio;

use cluelessh_keys::private::PlaintextPrivateKey;
use cluelessh_keys::public::PublicKey;
use cluelessh_keys::signature::Signature;
use cluelessh_protocol::auth::VerifySignature;
use cluelessh_transport::crypto::AlgorithmName;
use cluelessh_transport::SessionId;
use eyre::bail;
use eyre::ensure;
use eyre::eyre;
use eyre::Context;
use eyre::Result;
use rustix::net::RecvAncillaryBuffer;
use rustix::net::RecvAncillaryMessage;
use rustix::net::RecvFlags;
use rustix::net::SendAncillaryBuffer;
use rustix::net::SendAncillaryMessage;
use rustix::net::SendFlags;
use rustix::termios::Winsize;
use secrecy::ExposeSecret;
use secrecy::Secret;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::Interest;
use tokio::net::UnixDatagram;
use tokio::process::Child;
use tokio::process::Command;
use tracing::debug;
use tracing::trace;
use users::os::unix::UserExt;
use users::User;
use zeroize::Zeroizing;

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    /// Performs the key exchange by generating a private key, deriving the shared secret,
    /// computing the hash and signing it.
    /// This is combined into one operation to ensure that no signature forgery can happen,
    /// as the only thing we sign here is a hash, and this hash is guaranteed to contain
    /// some random bytes from us, making it entirely unpredictable and useless to forge anything.
    KeyExchange(KeyExchangeRequest),
    CheckPublicKey {
        user: String,
        pubkey: PublicKey,
    },
    /// Verify that the public key signature for the user is okay.
    /// If it is okay, store the user so we can later spawn a process as them.
    VerifySignature {
        user: String,
        session_id: SessionId,
        public_key: PublicKey,
        signature: Signature,
    },
    /// Request a PTY. We create a new PTY and give the client an FD to the controller.
    PtyReq(PtyRequest),
    /// Executes a command on the host.
    /// IMPORTANT: This is the critical operation, and we must ensure that it is secure.
    /// To ensure that even a compromised auth process cannot escalate privileges via this RPC,
    /// the RPC server keeps track of the authenciated user
    Shell(ShellRequest),
    /// Wait for the currently running command to finish.
    Wait,
}

#[derive(Serialize, Deserialize)]
pub struct KeyExchangeRequest {
    pub client_ident: Vec<u8>,
    pub server_ident: Vec<u8>,
    pub client_kexinit: Vec<u8>,
    pub server_kexinit: Vec<u8>,
    pub eph_client_public_key: Vec<u8>,
    pub server_host_key: PublicKey,
    pub kex_algorithm: String,
}

impl Debug for KeyExchangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyExchangeRequest")
            .field("client_ident", &"[...]")
            .field("server_ident", &"[...]")
            .field("client_kexinit", &"[...]")
            .field("server_kexinit", &"[...]")
            .field("eph_client_public_key", &self.eph_client_public_key)
            .field("server_host_key", &self.server_host_key)
            .field("kex_algorithm", &self.kex_algorithm)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableSharedSecret(Vec<u8>);
impl zeroize::Zeroize for SerializableSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}
impl Debug for SerializableSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerializableSharedSecret")
            .finish_non_exhaustive()
    }
}
impl secrecy::CloneableSecret for SerializableSharedSecret {}
impl secrecy::SerializableSecret for SerializableSharedSecret {}
impl secrecy::DebugSecret for SerializableSharedSecret {}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchangeResponse {
    pub hash: SessionId,
    pub server_ephemeral_public_key: Vec<u8>,
    pub shared_secret: secrecy::Secret<SerializableSharedSecret>,
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize)]
struct PtyRequest {
    height_rows: u32,
    width_chars: u32,
    width_px: u32,
    height_px: u32,
    term_modes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShellRequest {
    /// Whether a PTY is used and if yes, the TERM env var.
    pty_term: Option<String>,
    command: Option<String>,
    subsystem: Option<String>,
    env: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShellRequestPty {
    term: String,
}

type VerifySignatureResponse = bool;
type CheckPublicKeyResponse = bool;
type ShellResponse = ();
type PtyReqResponse = ();
type WaitResponse = Option<i32>;

type ResponseResult<T> = Result<T, String>;

pub struct Client {
    socket: UnixDatagram,
}

pub struct Server {
    server: UnixDatagram,
    client: UnixDatagram,
    host_keys: Vec<PlaintextPrivateKey>,
    authenticated_user: Option<users::User>,

    config: Config,

    pty_user: Option<OwnedFd>,
    shell_process: Option<Child>,
}

impl Server {
    pub fn new(config: Config, host_keys: Vec<PlaintextPrivateKey>) -> Result<Self> {
        let (server, client) = UnixDatagram::pair().wrap_err("creating socketpair")?;

        Ok(Self {
            server,
            client,
            config,
            host_keys,
            authenticated_user: None,
            pty_user: None,
            shell_process: None,
        })
    }

    pub fn client_fd(&self) -> BorrowedFd<'_> {
        self.client.as_fd()
    }

    pub async fn process(&mut self) -> Result<()> {
        loop {
            let (recv, fds) = receive_with_fds::<Request>(&self.server)
                .await
                .wrap_err("parsing request from client")?;
            ensure!(fds.is_empty(), "Client sent FDs in request");
            self.receive_message(recv).await?;
        }
    }

    async fn receive_message(&mut self, req: Request) -> Result<()> {
        trace!(?req, "Received RPC message");

        match req {
            Request::KeyExchange(req) => {
                let Some(private) = self
                    .host_keys
                    .iter()
                    .find(|privkey| privkey.private_key.public_key() == req.server_host_key)
                else {
                    self.respond_err("missing private key".to_owned()).await?;
                    return Ok(());
                };

                let Some(kex_algorithm) =
                    cluelessh_transport::crypto::kex_algorithm_by_name(&req.kex_algorithm)
                else {
                    self.respond_err("invalid kex algorithm".to_owned()).await?;
                    return Ok(());
                };

                let req = cluelessh_transport::server::KeyExchangeParameters {
                    client_ident: req.client_ident,
                    server_ident: req.server_ident,
                    client_kexinit: req.client_kexinit,
                    server_kexinit: req.server_kexinit,
                    eph_client_public_key: req.eph_client_public_key,
                    server_host_key_algorithm:
                        cluelessh_transport::crypto::HostKeySigningAlgorithm::new(
                            req.server_host_key,
                        ),
                    kex_algorithm,
                };

                let Ok(resp) = cluelessh_transport::server::do_key_exchange(
                    req,
                    private,
                    &mut cluelessh_protocol::OsRng,
                ) else {
                    self.respond_err("key exchange failed".to_owned()).await?;
                    return Ok(());
                };

                let resp = KeyExchangeResponse {
                    hash: resp.hash,
                    server_ephemeral_public_key: resp.server_ephemeral_public_key,
                    shared_secret: Secret::new(SerializableSharedSecret(
                        resp.shared_secret.expose_secret().0.to_vec(),
                    )),
                    signature: resp.signature,
                };

                self.respond::<KeyExchangeResponse>(Ok(resp)).await?;
            }
            Request::CheckPublicKey {
                user,
                pubkey: public_key,
            } => {
                let is_ok = crate::auth::check_pubkey(user, public_key)
                    .await
                    .map_err(|err| err.to_string());

                self.respond::<CheckPublicKeyResponse>(is_ok).await?;
            }
            Request::VerifySignature {
                user,
                session_id,
                public_key,
                signature,
            } => {
                if self.authenticated_user.is_some() {
                    self.respond_err("user already authenticated".to_owned())
                        .await?;
                }
                let is_ok = crate::auth::verify_signature(VerifySignature {
                    user,
                    session_id,
                    public_key,
                    signature,
                })
                .await
                .map_err(|err| err.to_string())
                .map(|user| match user {
                    Some(user) => {
                        self.authenticated_user = Some(user);
                        true
                    }
                    None => false,
                });

                self.respond::<VerifySignatureResponse>(is_ok).await?;
            }
            Request::PtyReq(req) => {
                if self.pty_user.is_some() {
                    self.respond_err("already requests pty".to_owned()).await?;

                    return Ok(());
                }

                let result = crate::pty::Pty::new(
                    Winsize {
                        ws_row: req.width_chars as u16,
                        ws_col: req.height_rows as u16,
                        ws_xpixel: req.width_px as u16,
                        ws_ypixel: req.height_px as u16,
                    },
                    req.term_modes,
                )
                .await;

                let (controller, user) = match &result {
                    Ok(pty) => (vec![pty.controller.as_fd()], Ok(pty.user_pty.try_clone()?)),
                    Err(err) => (vec![], Err(err)),
                };

                self.respond_ancillary::<PtyReqResponse>(
                    user.as_ref().map(drop).map_err(ToString::to_string),
                    &controller,
                )
                .await?;

                self.pty_user = user.ok();
            }
            Request::Shell(req) => {
                if self.shell_process.is_some() {
                    self.respond_err("process already running".to_owned())
                        .await?;

                    return Ok(());
                }

                let Some(user) = self.authenticated_user.clone() else {
                    self.respond_err("unauthenticated".to_owned()).await?;

                    return Ok(());
                };

                let result = self.shell(&user, req).await.map_err(|err| err.to_string());

                self.respond_ancillary::<ShellResponse>(
                    result.as_ref().map(drop).map_err(Clone::clone),
                    &result
                        .unwrap_or_default()
                        .iter()
                        .map(|fd| fd.as_fd())
                        .collect::<Vec<_>>(),
                )
                .await?;
            }
            Request::Wait => match &mut self.shell_process {
                None => {
                    self.respond_err("no child running".to_owned()).await?;
                }
                Some(child) => {
                    let result = child.wait().await;

                    self.respond::<WaitResponse>(
                        result
                            .map(|status| status.code())
                            .map_err(|err| err.to_string()),
                    )
                    .await?;

                    // implicitly drop stdio
                    self.shell_process = None;
                }
            },
        }
        Ok(())
    }

    async fn shell(&mut self, user: &User, req: ShellRequest) -> Result<Vec<OwnedFd>> {
        let subsystem = match req.subsystem.as_deref() {
            Some(subsystem) => match self.config.subsystem.get(subsystem) {
                Some(system) => Some(system.path.clone()),
                None => bail!("unsupported subsystem: {subsystem}"),
            },
            None => None,
        };

        let shell = user.shell();

        let cmd_arg0 = subsystem.as_deref().unwrap_or(shell);

        // TODO: the SSH RFC mentions subsystems going through shell... should we?
        let mut cmd = Command::new(cmd_arg0);

        if subsystem.is_none() {
            if let Some(shell_command) = req.command {
                cmd.arg("-c");
                cmd.arg(shell_command);
            }
        };

        cmd.env_clear();

        let has_pty = req.pty_term.is_some();

        ensure!(
            has_pty == self.pty_user.is_some(),
            "Mismatch between client and server PTY requests"
        );

        if let Some(term) = req.pty_term {
            let Some(pty_fd) = &self.pty_user else {
                bail!("no pty requested before");
            };
            let pty_fd = pty_fd.try_clone()?;

            crate::pty::start_session_for_command(pty_fd, term, &mut cmd)?;
        } else {
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        cmd.current_dir(user.home_dir());
        cmd.env("USER", user.name());
        cmd.uid(user.uid());
        cmd.gid(user.primary_group_id());

        for (k, v) in req.env {
            cmd.env(k, v);
        }

        debug!(cmd = %cmd_arg0.display(), uid = %user.uid(), gid = %user.primary_group_id(), "Executing process");

        let mut shell = cmd.spawn()?;

        // See Server::shell_process
        let mut fds1 = Vec::new();

        if !has_pty {
            let stdin = shell.stdin.take().unwrap().into_owned_fd()?;
            let stdout = shell.stdout.take().unwrap().into_owned_fd()?;
            let stderr = shell.stderr.take().unwrap().into_owned_fd()?;

            fds1.push(stdin);
            fds1.push(stdout);
            fds1.push(stderr);
        }

        self.shell_process = Some(shell);

        Ok(fds1)
    }

    async fn respond_err(&self, resp: String) -> Result<()> {
        self.respond::<()>(Err(resp)).await
    }

    async fn respond<T: Serialize>(&self, resp: ResponseResult<T>) -> Result<()> {
        self.respond_ancillary(resp, &[]).await
    }

    async fn respond_ancillary<T: Serialize>(
        &self,
        resp: ResponseResult<T>,
        fds: &[BorrowedFd<'_>],
    ) -> Result<()> {
        let data = Zeroizing::new(postcard::to_allocvec(&resp)?);
        send_with_fds(&self.server, &data, fds).await?;

        Ok(())
    }
}

impl Client {
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        let socket = UnixDatagram::from_std(std::os::unix::net::UnixDatagram::from(fd))?;
        Ok(Self { socket })
    }

    pub async fn kex_exchange(
        &self,
        params: cluelessh_transport::server::KeyExchangeParameters,
    ) -> Result<cluelessh_transport::server::KeyExchangeResponse> {
        let resp = self
            .request_response::<KeyExchangeResponse>(&Request::KeyExchange(KeyExchangeRequest {
                client_ident: params.client_ident,
                server_ident: params.server_ident,
                client_kexinit: params.client_kexinit,
                server_kexinit: params.server_kexinit,
                eph_client_public_key: params.eph_client_public_key,
                server_host_key: params.server_host_key_algorithm.public_key(),
                kex_algorithm: params.kex_algorithm.name().to_owned(),
            }))
            .await?;

        Ok(cluelessh_transport::server::KeyExchangeResponse {
            hash: resp.hash,
            server_ephemeral_public_key: resp.server_ephemeral_public_key,
            shared_secret: cluelessh_transport::crypto::SharedSecret::new(
                cluelessh_transport::crypto::SharedSecretInner(
                    resp.shared_secret.expose_secret().0.clone(),
                ),
            ),
            signature: resp.signature,
        })
    }

    pub async fn check_public_key(&self, user: String, pubkey: PublicKey) -> Result<bool> {
        self.request_response::<CheckPublicKeyResponse>(&Request::CheckPublicKey { user, pubkey })
            .await
    }

    pub async fn verify_signature(
        &self,
        user: String,
        session_id: SessionId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Result<bool> {
        self.request_response::<VerifySignatureResponse>(&Request::VerifySignature {
            user,
            session_id,
            public_key,
            signature,
        })
        .await
    }

    pub async fn pty_req(
        &self,
        width_chars: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
        term_modes: Vec<u8>,
    ) -> Result<OwnedFd> {
        self.send_request(&Request::PtyReq(PtyRequest {
            height_rows,
            width_chars,
            width_px,
            height_px,
            term_modes,
        }))
        .await?;

        let (_, mut fds) = self.recv_response_ancillary::<PtyReqResponse>().await?;
        ensure!(
            fds.len() == 1,
            "Incorrect amount of FDs received: {}",
            fds.len()
        );

        let controller = fds.remove(0);

        Ok(controller)
    }

    pub async fn shell(
        &self,
        command: Option<String>,
        subsystem: Option<String>,
        pty_term: Option<String>,
        env: Vec<(String, String)>,
    ) -> Result<Vec<OwnedFd>> {
        self.send_request(&Request::Shell(ShellRequest {
            pty_term,
            command,
            subsystem,
            env,
        }))
        .await?;

        let (_, fds) = self.recv_response_ancillary::<ShellResponse>().await?;

        Ok(fds)
    }

    pub async fn wait(&self) -> Result<Option<i32>> {
        self.request_response::<WaitResponse>(&Request::Wait).await
    }

    async fn request_response<R: DeserializeOwned + Debug + Send + 'static>(
        &self,
        req: &Request,
    ) -> Result<R> {
        self.send_request(req).await?;
        Ok(self.recv_response_ancillary::<R>().await?.0)
    }

    async fn send_request(&self, req: &Request) -> Result<()> {
        trace!(?req, "Sending RPC request");

        let data = postcard::to_allocvec(&req)?;

        send_with_fds(&self.socket, &data, &[]).await?;
        Ok(())
    }

    async fn recv_response_ancillary<R: DeserializeOwned + Debug + Send + 'static>(
        &self,
    ) -> Result<(R, Vec<OwnedFd>)> {
        let (resp, fds) = receive_with_fds::<ResponseResult<R>>(&self.socket)
            .await
            .wrap_err("parsing response from server")?;

        trace!(?resp, ?fds, "Received RPC response");

        let resp = resp.map_err(|err| eyre!(err))?;

        Ok((resp, fds))
    }
}

const MAX_DATA_SIZE: usize = 4048;

async fn send_with_fds(socket: &UnixDatagram, data: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
    ensure!(
        data.len() <= MAX_DATA_SIZE,
        "Trying to send too much data: {} > {MAX_DATA_SIZE}",
        data.len()
    );

    socket
        .async_io(Interest::WRITABLE, || {
            let mut space = [0; rustix::cmsg_space!(ScmRights(3))]; //we send up to 3 fds at once
            let mut ancillary = SendAncillaryBuffer::new(&mut space);

            ancillary.push(SendAncillaryMessage::ScmRights(fds));
            rustix::net::sendmsg(
                socket,
                &[IoSlice::new(data)],
                &mut ancillary,
                SendFlags::empty(),
            )
            .map_err(|errno| io::Error::from(errno))?;
            Ok(())
        })
        .await
        .wrap_err("failed to write to socket")
}

async fn receive_with_fds<R: DeserializeOwned>(socket: &UnixDatagram) -> Result<(R, Vec<OwnedFd>)> {
    let mut data = Zeroizing::new([0; MAX_DATA_SIZE]);
    let mut space = [0; rustix::cmsg_space!(ScmRights(3))]; // maximum size
    let mut cmesg_buf = RecvAncillaryBuffer::new(&mut space);

    let read = socket
        .async_io(Interest::READABLE, || {
            rustix::net::recvmsg(
                socket,
                &mut [IoSliceMut::new(&mut *data)],
                &mut cmesg_buf,
                RecvFlags::empty(),
            )
            .map_err(|errno| io::Error::from(errno))
        })
        .await?;

    let mut fds = Vec::new();

    let data_parsed = postcard::from_bytes::<R>(&data[..read.bytes]).wrap_err("invalid request")?;

    for msg in cmesg_buf.drain() {
        match msg {
            RecvAncillaryMessage::ScmRights(fd) => fds.extend(fd),
            _ => bail!("unexpected ancillery msg"),
        }
    }

    Ok((data_parsed, fds))
}
