//! [`postcard`]-based RPC between the different processes.

use std::fmt::Debug;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::process::Stdio;

use cluelessh_keys::private::PlaintextPrivateKey;
use cluelessh_keys::public::PublicKey;
use cluelessh_keys::signature::Signature;
use cluelessh_protocol::auth::CheckPubkey;
use cluelessh_protocol::auth::VerifySignature;
use eyre::bail;
use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;
use eyre::Result;
use rustix::net::RecvAncillaryBuffer;
use rustix::net::RecvAncillaryMessage;
use rustix::net::RecvFlags;
use rustix::net::SendAncillaryBuffer;
use rustix::net::SendAncillaryMessage;
use rustix::net::SendFlags;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::debug;
use tracing::error;
use tracing::trace;
use users::os::unix::UserExt;
use users::User;

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Sign {
        hash: [u8; 32],
        public_key: PublicKey,
    },
    VerifySignature {
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    CheckPubkey {
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
    },
    /// Executes a command on the host.
    /// IMPORTANT: This is the critical operation, and we must ensure that it is secure.
    /// To ensure that even a compromised auth process cannot escalate privileges via this RPC,
    /// the RPC server keeps track of the authenciated user
    Shell(ShellRequest),
    Wait,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShellRequest {
    /// Whether a PTY is used.
    /// If true, the PTY fd is passed as ancillary data.
    /// If false, the response will contain the 3 stdio fds
    /// as ancillary data.
    pty: Option<ShellRequestPty>,
    command: Option<String>,
    env: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]

struct ShellRequestPty {
    term: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignResponse {
    signature: Result<Signature, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifySignatureResponse {
    is_ok: Result<bool, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckPubkeyResponse {
    is_ok: Result<bool, String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct ShellResponse {
    result: Result<(), String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WaitResponse {
    result: Result<Option<i32>, String>,
}

pub struct Client {
    socket: UnixDatagram,
}

pub struct Server {
    server: UnixDatagram,
    client: UnixDatagram,
    server_recv_recv: mpsc::Receiver<(Request, Vec<OwnedFd>)>,
    host_keys: Vec<PlaintextPrivateKey>,
    authenticated_user: Option<users::User>,
    /// We keep the owned FDs here around to avoid a race condition where the child would
    /// think stdout is closed before the client process opens it.
    shell_process: Option<(Child, Vec<OwnedFd>)>,
}

fn server_thread(
    socket: OwnedFd,
    server_recv_send: mpsc::Sender<(Request, Vec<OwnedFd>)>,
) -> Result<()> {
    let socket = std::os::unix::net::UnixDatagram::from(socket);
    socket.set_nonblocking(false)?;

    loop {
        let (req, fds) = blocking_receive_with_fds::<Request>(socket.as_fd())?;
        server_recv_send.blocking_send((req, fds))?;
    }
}

impl Server {
    pub fn new(host_keys: Vec<PlaintextPrivateKey>) -> Result<Self> {
        let (server, client) = UnixDatagram::pair().wrap_err("creating socketpair")?;

        let (server_recv_send, server_recv_recv) = mpsc::channel(3);

        let server_for_thread = server.as_fd().try_clone_to_owned()?;

        std::thread::spawn(move || {
            if let Err(err) = server_thread(server_for_thread, server_recv_send) {
                error!(?err, "Server RPC recv thread error");
            }
        });

        Ok(Self {
            server,
            client,
            host_keys,
            server_recv_recv,
            authenticated_user: None,
            shell_process: None,
        })
    }

    pub fn client_fd(&self) -> BorrowedFd<'_> {
        self.client.as_fd()
    }

    pub async fn process(&mut self) -> Result<()> {
        loop {
            let recv = self
                .server_recv_recv
                .recv()
                .await
                .ok_or_eyre("RPC thread error")?;
            self.receive_message(recv.0, recv.1).await?;
        }
    }

    async fn receive_message(&mut self, req: Request, mut fds: Vec<OwnedFd>) -> Result<()> {
        trace!(?req, ?fds, "Received RPC message");

        match req {
            Request::Sign { hash, public_key } => {
                let Some(private) = self
                    .host_keys
                    .iter()
                    .find(|privkey| privkey.private_key.public_key() == public_key)
                else {
                    self.respond(SignResponse {
                        signature: Err("missing private key".to_owned()),
                    })
                    .await?;

                    return Ok(());
                };

                let signature = private.private_key.sign(&hash);

                self.respond(SignResponse {
                    signature: Ok(signature),
                })
                .await?;
            }
            Request::VerifySignature {
                user,
                session_identifier,
                pubkey_alg_name,
                pubkey,
                signature,
            } => {
                if self.authenticated_user.is_some() {
                    self.respond(VerifySignatureResponse {
                        is_ok: Err("user already authenticated".to_owned()),
                    })
                    .await?;
                }
                let is_ok = crate::auth::verify_signature(VerifySignature {
                    user,
                    session_identifier,
                    pubkey_alg_name,
                    pubkey,
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

                self.respond(VerifySignatureResponse { is_ok }).await?;
            }
            Request::CheckPubkey {
                user,
                session_identifier,
                pubkey_alg_name,
                pubkey,
            } => {
                let is_ok = crate::auth::check_pubkey(CheckPubkey {
                    user,
                    session_identifier,
                    pubkey_alg_name,
                    pubkey,
                })
                .await
                .map_err(|err| err.to_string());

                self.respond(CheckPubkeyResponse { is_ok }).await?;
            }
            Request::Shell(req) => {
                if self.shell_process.is_some() {
                    self.respond(ShellResponse {
                        result: Err("process already running".to_owned()),
                    })
                    .await?;

                    return Ok(());
                }

                let Some(user) = self.authenticated_user.clone() else {
                    self.respond(ShellResponse {
                        result: Err("unauthenticated".to_owned()),
                    })
                    .await?;

                    return Ok(());
                };

                let result = self
                    .shell(&mut fds, &user, req)
                    .await
                    .map_err(|err| err.to_string());

                self.respond_ancillary(
                    ShellResponse {
                        result: result.as_ref().map(drop).map_err(Clone::clone),
                    },
                    result.unwrap_or_default(),
                )
                .await?;
            }
            Request::Wait => match &mut self.shell_process {
                None => {
                    self.respond(WaitResponse {
                        result: Err("no child running".to_owned()),
                    })
                    .await?;
                }
                Some(child) => {
                    let result = child.0.wait().await;

                    self.respond(WaitResponse {
                        result: result
                            .map(|status| status.code())
                            .map_err(|err| err.to_string()),
                    })
                    .await?;

                    // implicitly drop stdio
                    self.shell_process = None;
                }
            },
        }
        Ok(())
    }

    async fn shell(
        &mut self,
        fds: &mut Vec<OwnedFd>,
        user: &User,
        req: ShellRequest,
    ) -> Result<Vec<OwnedFd>> {
        let shell = user.shell();

        let mut cmd = Command::new(shell);
        if let Some(shell_command) = req.command {
            cmd.arg("-c");
            cmd.arg(shell_command);
        }
        cmd.env_clear();

        let has_pty = req.pty.is_some();

        if let Some(pty) = req.pty {
            if fds.len() != 1 {
                bail!("invalid request: shell with PTY must send one FD");
            }
            let user_pty = fds.remove(0);
            crate::pty::start_session_for_command(user_pty, pty.term, &mut cmd)?;
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

        debug!(cmd = %shell.display(), uid = %user.uid(), gid = %user.primary_group_id(), "Executing process");

        let mut shell = cmd.spawn()?;

        // See Server::shell_process
        let mut fds1 = Vec::new();
        let mut fds2 = Vec::new();

        if !has_pty {
            let stdin = shell.stdin.take().unwrap().into_owned_fd()?;
            let stdout = shell.stdout.take().unwrap().into_owned_fd()?;
            let stderr = shell.stderr.take().unwrap().into_owned_fd()?;

            fds1.push(stdin.try_clone()?);
            fds2.push(stdin);
            fds1.push(stdout.try_clone()?);
            fds2.push(stdout);
            fds1.push(stderr.try_clone()?);
            fds2.push(stderr);
        }

        self.shell_process = Some((shell, vec![]));

        Ok(fds1)
    }

    async fn respond(&self, resp: impl Serialize) -> Result<()> {
        self.respond_ancillary(resp, vec![]).await
    }

    async fn respond_ancillary(&self, resp: impl Serialize, fds: Vec<OwnedFd>) -> Result<()> {
        send_with_fds(
            self.server.as_fd().try_clone_to_owned()?,
            postcard::to_allocvec(&resp)?,
            fds,
        )
        .await?;

        Ok(())
    }
}

impl Client {
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        let socket = std::os::unix::net::UnixDatagram::from(fd);
        Ok(Self { socket })
    }

    pub async fn sign(&self, hash: [u8; 32], public_key: PublicKey) -> Result<Signature> {
        let resp = self
            .request_response::<SignResponse>(&Request::Sign { hash, public_key }, vec![])
            .await?;

        resp.signature.map_err(|err| eyre!(err))
    }

    pub async fn check_pubkey(
        &self,
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
    ) -> Result<bool> {
        let resp = self
            .request_response::<CheckPubkeyResponse>(
                &Request::CheckPubkey {
                    user,
                    session_identifier,
                    pubkey_alg_name,
                    pubkey,
                },
                vec![],
            )
            .await?;

        resp.is_ok.map_err(|err| eyre!(err))
    }

    pub async fn verify_signature(
        &self,
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool> {
        let resp = self
            .request_response::<VerifySignatureResponse>(
                &Request::VerifySignature {
                    user,
                    session_identifier,
                    pubkey_alg_name,
                    pubkey,
                    signature,
                },
                vec![],
            )
            .await?;

        resp.is_ok.map_err(|err| eyre!(err))
    }

    pub async fn exec(
        &self,
        command: Option<String>,
        pty: Option<OwnedFd>,
        term: String,
        env: Vec<(String, String)>,
    ) -> Result<Vec<OwnedFd>> {
        let has_pty = pty.is_some();
        let fds = match pty {
            Some(fd) => vec![fd],
            None => vec![],
        };

        self.send_request(
            &Request::Shell(ShellRequest {
                pty: has_pty.then_some(ShellRequestPty { term }),
                command,
                env,
            }),
            fds,
        )
        .await?;

        let (resp, fds) = self.recv_response_ancillary::<ShellResponse>().await?;
        resp.result.map_err(|err| eyre!(err))?;

        Ok(fds)
    }

    pub async fn wait(&self) -> Result<Option<i32>> {
        self.request_response::<WaitResponse>(&Request::Wait, vec![])
            .await
            .and_then(|resp| resp.result.map_err(|err| eyre!(err)))
    }

    async fn request_response<R: DeserializeOwned + Debug + Send + 'static>(
        &self,
        req: &Request,
        fds: Vec<OwnedFd>,
    ) -> Result<R> {
        self.send_request(req, fds).await?;
        Ok(self.recv_response_ancillary::<R>().await?.0)
    }

    async fn send_request(&self, req: &Request, fds: Vec<OwnedFd>) -> Result<()> {
        let data = postcard::to_allocvec(&req)?;

        let socket = self.socket.as_fd().try_clone_to_owned()?;

        send_with_fds(socket, data, fds).await?;
        Ok(())
    }

    async fn recv_response_ancillary<R: DeserializeOwned + Debug + Send + 'static>(
        &self,
    ) -> Result<(R, Vec<OwnedFd>)> {
        let socket =
            std::os::unix::net::UnixDatagram::from(self.socket.as_fd().try_clone_to_owned()?);

        let (resp, fds) =
            tokio::task::spawn_blocking(move || blocking_receive_with_fds(socket.as_fd()))
                .await?
                .wrap_err("failed to recv")?;

        trace!(?resp, ?fds, "Received RPC response");

        Ok((resp, fds))
    }
}

async fn send_with_fds(socket: OwnedFd, data: Vec<u8>, fds: Vec<OwnedFd>) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut space = [0; rustix::cmsg_space!(ScmRights(3))]; //we send up to 3 fds at once
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let fds = fds.iter().map(|fd| fd.as_fd()).collect::<Vec<_>>();

        ancillary.push(SendAncillaryMessage::ScmRights(fds.as_slice()));
        rustix::net::sendmsg(
            socket,
            &[IoSlice::new(&data)],
            &mut ancillary,
            SendFlags::empty(),
        )
    })
    .await?
    .wrap_err("failed to send")
    .map(drop)
}

fn blocking_receive_with_fds<R: DeserializeOwned>(
    blocking_socket: BorrowedFd<'_>,
) -> Result<(R, Vec<OwnedFd>)> {
    let mut data = [0; 1024];
    let mut space = [0; rustix::cmsg_space!(ScmRights(3))]; // maximum size
    let mut cmesg_buf = RecvAncillaryBuffer::new(&mut space);

    let mut fds = Vec::new();

    let read = rustix::net::recvmsg(
        blocking_socket,
        &mut [IoSliceMut::new(&mut data)],
        &mut cmesg_buf,
        RecvFlags::empty(),
    )?;
    let data = postcard::from_bytes::<R>(&data[..read.bytes]).wrap_err("invalid request")?;

    for msg in cmesg_buf.drain() {
        match msg {
            RecvAncillaryMessage::ScmRights(fd) => fds.extend(fd),
            _ => bail!("unexpected ancillery msg"),
        }
    }

    Ok((data, fds))
}
