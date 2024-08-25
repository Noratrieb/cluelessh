use cluelessh_connection::{ChannelKind, ChannelNumber, ChannelOperation};
use futures::future::BoxFuture;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use cluelessh_protocol::{
    auth::{AuthOption, VerifyPassword, VerifyPubkey},
    ChannelUpdateKind, SshStatus,
};
use eyre::{eyre, ContextCompat, OptionExt, Result, WrapErr};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::{Channel, ChannelState, PendingChannel};

pub struct ServerListener {
    listener: TcpListener,
    auth_verify: ServerAuthVerify,
    // TODO ratelimits etc
}

pub struct ServerConnection<S> {
    stream: Pin<Box<S>>,
    peer_addr: SocketAddr,
    buf: [u8; 1024],

    proto: cluelessh_protocol::ServerConnection,
    operations_send: tokio::sync::mpsc::Sender<Operation>,
    operations_recv: tokio::sync::mpsc::Receiver<Operation>,

    /// Cloned and passed on to channels.
    channel_ops_send: tokio::sync::mpsc::Sender<ChannelOperation>,
    channel_ops_recv: tokio::sync::mpsc::Receiver<ChannelOperation>,

    channels: HashMap<ChannelNumber, ChannelState>,

    /// New channels opened by the peer.
    new_channels: VecDeque<Channel>,

    auth_verify: ServerAuthVerify,
}

enum Operation {
    VerifyPassword(Result<()>),
    VerifyPubkey(Result<()>),
}

#[derive(Clone)]
pub struct ServerAuthVerify {
    pub verify_password:
        Option<Arc<dyn Fn(VerifyPassword) -> BoxFuture<'static, Result<()>> + Send + Sync>>,
    pub verify_pubkey:
        Option<Arc<dyn Fn(VerifyPubkey) -> BoxFuture<'static, Result<()>> + Send + Sync>>,
}
fn _assert_send_sync() {
    fn send<T: Send + Sync>() {}
    send::<ServerAuthVerify>();
}

pub enum Error {
    SshStatus(SshStatus),
    ServerError(eyre::Report),
}
impl From<eyre::Report> for Error {
    fn from(value: eyre::Report) -> Self {
        Self::ServerError(value)
    }
}

impl ServerListener {
    pub fn new(listener: TcpListener, auth_verify: ServerAuthVerify) -> Self {
        Self {
            listener,
            auth_verify,
        }
    }

    pub async fn accept(&mut self) -> Result<ServerConnection<TcpStream>> {
        let (conn, peer_addr) = self.listener.accept().await?;

        Ok(ServerConnection::new(
            conn,
            peer_addr,
            self.auth_verify.clone(),
        ))
    }
}

impl<S: AsyncRead + AsyncWrite> ServerConnection<S> {
    pub fn new(stream: S, peer_addr: SocketAddr, auth_verify: ServerAuthVerify) -> Self {
        let (operations_send, operations_recv) = tokio::sync::mpsc::channel(15);
        let (channel_ops_send, channel_ops_recv) = tokio::sync::mpsc::channel(15);

        let mut options = HashSet::new();
        if auth_verify.verify_password.is_some() {
            options.insert(AuthOption::Password);
        }
        if auth_verify.verify_pubkey.is_some() {
            options.insert(AuthOption::PublicKey);
        }

        if options.is_empty() {
            panic!("no auth options provided");
        }

        Self {
            stream: Box::pin(stream),
            peer_addr,
            buf: [0; 1024],
            operations_send,
            operations_recv,
            channel_ops_send,
            channel_ops_recv,
            channels: HashMap::new(),
            proto: cluelessh_protocol::ServerConnection::new(
                cluelessh_transport::server::ServerConnection::new(
                    cluelessh_protocol::ThreadRngRand,
                ),
                options,
            ),
            new_channels: VecDeque::new(),
            auth_verify,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Executes one loop iteration of the main loop.
    // IMPORTANT: no operations on this struct should ever block the main loop, except this one.
    pub async fn progress(&mut self) -> Result<(), Error> {
        if let Some(auth) = self.proto.auth() {
            for req in auth.server_requests() {
                match req {
                    cluelessh_protocol::auth::ServerRequest::VerifyPassword(password_verify) => {
                        let send = self.operations_send.clone();
                        let verify = self
                            .auth_verify
                            .verify_password
                            .clone()
                            .ok_or_eyre("password auth not supported")?;
                        tokio::spawn(async move {
                            let result = verify(password_verify).await;
                            let _ = send.send(Operation::VerifyPassword(result)).await;
                        });
                    }
                    cluelessh_protocol::auth::ServerRequest::VerifyPubkey(pubkey_verify) => {
                        let send = self.operations_send.clone();
                        let verify = self
                            .auth_verify
                            .verify_pubkey
                            .clone()
                            .ok_or_eyre("pubkey auth not supported")?;
                        tokio::spawn(async move {
                            let result = verify(pubkey_verify).await;
                            let _ = send.send(Operation::VerifyPubkey(result)).await;
                        });
                    }
                }
            }
        }

        if let Some(channels) = self.proto.channels() {
            while let Some(update) = channels.next_channel_update() {
                match &update.kind {
                    ChannelUpdateKind::Open(channel_kind) => {
                        let channel = self.channels.get_mut(&update.number);

                        match channel {
                            // We opened.
                            Some(ChannelState::Pending { updates_send, .. }) => {
                                let updates_send = updates_send.clone();
                                let old = self
                                    .channels
                                    .insert(update.number, ChannelState::Ready(updates_send));
                                match old.unwrap() {
                                    ChannelState::Pending { ready_send, .. } => {
                                        let _ = ready_send.send(Ok(()));
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            Some(ChannelState::Ready(_)) => {
                                return Err(Error::ServerError(eyre!(
                                    "attemping to open channel twice: {}",
                                    update.number
                                )))
                            }
                            // They opened.
                            None => {
                                let (updates_send, updates_recv) = tokio::sync::mpsc::channel(10);

                                let number = update.number;

                                self.channels
                                    .insert(number, ChannelState::Ready(updates_send));

                                let channel = Channel {
                                    number,
                                    updates_recv,
                                    ops_send: self.channel_ops_send.clone(),
                                    kind: channel_kind.clone(),
                                };
                                self.new_channels.push_back(channel);
                            }
                        }
                    }
                    ChannelUpdateKind::OpenFailed { message, .. } => {
                        let channel = self
                            .channels
                            .get_mut(&update.number)
                            .wrap_err("unknown channel")?;
                        match channel {
                            ChannelState::Pending { .. } => {
                                let old = self.channels.remove(&update.number);
                                match old.unwrap() {
                                    ChannelState::Pending { ready_send, .. } => {
                                        let _ = ready_send.send(Err(message.clone()));
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            ChannelState::Ready(_) => {
                                return Err(Error::ServerError(eyre!(
                                    "attemping to open channel twice: {}",
                                    update.number
                                )))
                            }
                        }
                    }
                    _ => {
                        let channel = self
                            .channels
                            .get_mut(&update.number)
                            .wrap_err("unknown channel")?;
                        match channel {
                            ChannelState::Pending { .. } => {
                                return Err(Error::ServerError(eyre!("channel not ready yet")))
                            }
                            ChannelState::Ready(updates_send) => {
                                let _ = updates_send.send(update.kind).await;
                            }
                        }
                    }
                }
            }
        }

        // Make sure that we send all queued messages before going into the select, waiting for things to happen.
        self.send_off_data().await?;

        tokio::select! {
            read = self.stream.read(&mut self.buf) => {
                let read = read.wrap_err("reading from connection")?;
                if read == 0 {
                    info!("Did not read any bytes from TCP stream, EOF");
                    return Err(Error::SshStatus(SshStatus::Disconnect));
                }
                if let Err(err) = self.proto.recv_bytes(&self.buf[..read]) {
                    return Err(Error::SshStatus(err));
                }
            }
            channel_op = self.channel_ops_recv.recv() => {
                let channels = self.proto.channels().expect("connection not ready");
                if let Some(channel_op) = channel_op {
                    channels.do_operation(channel_op);
                }
            }
            op = self.operations_recv.recv() => {
                match op {
                    Some(Operation::VerifyPubkey(result)) => if let Some(auth) = self.proto.auth() {
                        auth.verification_result(result.is_ok());
                    },
                    Some(Operation::VerifyPassword(result)) => if let Some(auth) = self.proto.auth() {
                        auth.verification_result(result.is_ok());
                    },
                    None => {}
                }
                self.send_off_data().await?;
            }
        }

        Ok(())
    }

    async fn send_off_data(&mut self) -> Result<()> {
        self.proto.progress();
        while let Some(msg) = self.proto.next_msg_to_send() {
            self.stream
                .write_all(&msg.to_bytes())
                .await
                .wrap_err("writing response")?;
        }
        Ok(())
    }

    pub fn open_channel(&mut self, kind: ChannelKind) -> PendingChannel {
        let Some(channels) = self.proto.channels() else {
            panic!("connection not ready yet")
        };
        let (updates_send, updates_recv) = tokio::sync::mpsc::channel(10);
        let (ready_send, ready_recv) = tokio::sync::oneshot::channel();

        let number = channels.create_channel(kind.clone());

        self.channels.insert(
            number,
            ChannelState::Pending {
                ready_send,
                updates_send,
            },
        );

        PendingChannel {
            ready_recv,
            channel: Channel {
                number,
                updates_recv,
                ops_send: self.channel_ops_send.clone(),
                kind,
            },
        }
    }

    pub fn next_new_channel(&mut self) -> Option<Channel> {
        self.new_channels.pop_front()
    }
}
