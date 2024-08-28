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
use cluelessh_protocol::auth::CheckPubkey;
use cluelessh_protocol::auth::VerifySignature;
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
    PtyReq(PtyRequest),
    /// Executes a command on the host.
    /// IMPORTANT: This is the critical operation, and we must ensure that it is secure.
    /// To ensure that even a compromised auth process cannot escalate privileges via this RPC,
    /// the RPC server keeps track of the authenciated user
    Shell(ShellRequest),
    Wait,
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
struct PtyResponse {
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
    host_keys: Vec<PlaintextPrivateKey>,
    authenticated_user: Option<users::User>,

    pty_user: Option<OwnedFd>,
    shell_process: Option<Child>,
}

impl Server {
    pub fn new(host_keys: Vec<PlaintextPrivateKey>) -> Result<Self> {
        let (server, client) = UnixDatagram::pair().wrap_err("creating socketpair")?;

        Ok(Self {
            server,
            client,
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
            let recv = receive_with_fds::<Request>(&self.server).await?;
            self.receive_message(recv.0, recv.1).await?;
        }
    }

    async fn receive_message(&mut self, req: Request, fds: Vec<OwnedFd>) -> Result<()> {
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
            Request::PtyReq(req) => {
                if self.pty_user.is_some() {
                    self.respond(ShellResponse {
                        result: Err("already requests pty".to_owned()),
                    })
                    .await?;

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

                self.respond_ancillary(
                    ShellResponse {
                        result: user.as_ref().map(drop).map_err(ToString::to_string),
                    },
                    &controller,
                )
                .await?;

                self.pty_user = user.ok();
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

                let result = self.shell(&user, req).await.map_err(|err| err.to_string());

                self.respond_ancillary(
                    ShellResponse {
                        result: result.as_ref().map(drop).map_err(Clone::clone),
                    },
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
                    self.respond(WaitResponse {
                        result: Err("no child running".to_owned()),
                    })
                    .await?;
                }
                Some(child) => {
                    let result = child.wait().await;

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

    async fn shell(&mut self, user: &User, req: ShellRequest) -> Result<Vec<OwnedFd>> {
        let shell = user.shell();

        let mut cmd = Command::new(shell);
        if let Some(shell_command) = req.command {
            cmd.arg("-c");
            cmd.arg(shell_command);
        }
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

        debug!(cmd = %shell.display(), uid = %user.uid(), gid = %user.primary_group_id(), "Executing process");

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

    async fn respond(&self, resp: impl Serialize) -> Result<()> {
        self.respond_ancillary(resp, &[]).await
    }

    async fn respond_ancillary(&self, resp: impl Serialize, fds: &[BorrowedFd<'_>]) -> Result<()> {
        send_with_fds(&self.server, &postcard::to_allocvec(&resp)?, fds).await?;

        Ok(())
    }
}

impl Client {
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        let socket = UnixDatagram::from_std(std::os::unix::net::UnixDatagram::from(fd))?;
        Ok(Self { socket })
    }

    pub async fn sign(&self, hash: [u8; 32], public_key: PublicKey) -> Result<Signature> {
        let resp = self
            .request_response::<SignResponse>(&Request::Sign { hash, public_key })
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
            .request_response::<CheckPubkeyResponse>(&Request::CheckPubkey {
                user,
                session_identifier,
                pubkey_alg_name,
                pubkey,
            })
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
            .request_response::<VerifySignatureResponse>(&Request::VerifySignature {
                user,
                session_identifier,
                pubkey_alg_name,
                pubkey,
                signature,
            })
            .await?;

        resp.is_ok.map_err(|err| eyre!(err))
    }

    pub async fn pty_req(
        &self,
        width_chars: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
        term_modes: Vec<u8>,
    ) -> Result<Vec<OwnedFd>> {
        self.send_request(&Request::PtyReq(PtyRequest {
            height_rows,
            width_chars,
            width_px,
            height_px,
            term_modes,
        }))
        .await?;

        let (resp, fds) = self.recv_response_ancillary::<PtyResponse>().await?;
        resp.result.map_err(|err| eyre!(err))?;

        Ok(fds)
    }

    pub async fn shell(
        &self,
        command: Option<String>,
        pty_term: Option<String>,
        env: Vec<(String, String)>,
    ) -> Result<Vec<OwnedFd>> {
        self.send_request(&Request::Shell(ShellRequest {
            pty_term,
            command,
            env,
        }))
        .await?;

        let (resp, fds) = self.recv_response_ancillary::<ShellResponse>().await?;
        resp.result.map_err(|err| eyre!(err))?;

        Ok(fds)
    }

    pub async fn wait(&self) -> Result<Option<i32>> {
        self.request_response::<WaitResponse>(&Request::Wait)
            .await
            .and_then(|resp| resp.result.map_err(|err| eyre!(err)))
    }

    async fn request_response<R: DeserializeOwned + Debug + Send + 'static>(
        &self,
        req: &Request,
    ) -> Result<R> {
        self.send_request(req).await?;
        Ok(self.recv_response_ancillary::<R>().await?.0)
    }

    async fn send_request(&self, req: &Request) -> Result<()> {
        let data = postcard::to_allocvec(&req)?;

        send_with_fds(&self.socket, &data, &[]).await?;
        Ok(())
    }

    async fn recv_response_ancillary<R: DeserializeOwned + Debug + Send + 'static>(
        &self,
    ) -> Result<(R, Vec<OwnedFd>)> {
        let (resp, fds) = receive_with_fds(&self.socket)
            .await
            .wrap_err("failed to recv")?;

        trace!(?resp, ?fds, "Received RPC response");

        Ok((resp, fds))
    }
}

async fn send_with_fds(socket: &UnixDatagram, data: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
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
    let mut data = [0; 1024];
    let mut space = [0; rustix::cmsg_space!(ScmRights(3))]; // maximum size
    let mut cmesg_buf = RecvAncillaryBuffer::new(&mut space);

    let read = socket
        .async_io(Interest::READABLE, || {
            rustix::net::recvmsg(
                socket,
                &mut [IoSliceMut::new(&mut data)],
                &mut cmesg_buf,
                RecvFlags::empty(),
            )
            .map_err(|errno| io::Error::from(errno))
        })
        .await?;

    let mut fds = Vec::new();

    let data = postcard::from_bytes::<R>(&data[..read.bytes]).wrap_err("invalid request")?;

    for msg in cmesg_buf.drain() {
        match msg {
            RecvAncillaryMessage::ScmRights(fd) => fds.extend(fd),
            _ => bail!("unexpected ancillery msg"),
        }
    }

    Ok((data, fds))
}
