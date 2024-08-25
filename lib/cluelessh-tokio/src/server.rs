use cluelessh_connection::{ChannelKind, ChannelNumber, ChannelOperation};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    pin::Pin,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use cluelessh_protocol::{ChannelUpdateKind, SshStatus};
use eyre::{eyre, ContextCompat, Result, WrapErr};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::Channel;

pub struct ServerListener {
    listener: TcpListener,
    // todo ratelimits etc
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
}

enum ChannelState {
    Pending {
        ready_send: tokio::sync::oneshot::Sender<Result<(), String>>,
        updates_send: tokio::sync::mpsc::Sender<ChannelUpdateKind>,
    },
    Ready(tokio::sync::mpsc::Sender<ChannelUpdateKind>),
}

enum Operation {
    VerifyPassword {
        user: String,
        password: String,
    },
    VerifyPubkey {
        session_identifier: [u8; 32],
        user: String,
        pubkey: Vec<u8>,
    },
}

pub struct SignatureResult {
    pub key_alg_name: &'static str,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct PendingChannel {
    ready_recv: tokio::sync::oneshot::Receiver<Result<(), String>>,
    channel: Channel,
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
    pub fn new(listener: TcpListener) -> Self {
        Self { listener }
    }

    pub async fn accept(&mut self) -> Result<ServerConnection<TcpStream>> {
        let (conn, peer_addr) = self.listener.accept().await?;

        Ok(ServerConnection::new(conn, peer_addr))
    }
}

impl<S: AsyncRead + AsyncWrite> ServerConnection<S> {
    pub fn new(stream: S, peer_addr: SocketAddr) -> Self {
        let (operations_send, operations_recv) = tokio::sync::mpsc::channel(15);
        let (channel_ops_send, channel_ops_recv) = tokio::sync::mpsc::channel(15);

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
            ),
            new_channels: VecDeque::new(),
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
                    cluelessh_protocol::auth::ServerRequest::VerifyPassword { user, password } => {
                        let send = self.operations_send.clone();
                        tokio::spawn(async move {
                            let _ = send
                                .send(Operation::VerifyPassword { user, password })
                                .await;
                        });
                    }
                    cluelessh_protocol::auth::ServerRequest::VerifyPubkey {
                        session_identifier,
                        pubkey,
                        user,
                    } => {
                        let send = self.operations_send.clone();
                        tokio::spawn(async move {
                            let _ = send
                                .send(Operation::VerifyPubkey {
                                    session_identifier,
                                    user,
                                    pubkey,
                                })
                                .await;
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
                    return Ok(());
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
                    Some(Operation::VerifyPubkey { .. }) => todo!(),
                    Some(Operation::VerifyPassword { .. }) => todo!(),
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

impl PendingChannel {
    pub async fn wait_ready(self) -> Result<Channel, Option<String>> {
        match self.ready_recv.await {
            Ok(Ok(())) => Ok(self.channel),
            Ok(Err(err)) => Err(Some(err)),
            Err(_) => Err(None),
        }
    }
}
