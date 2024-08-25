use cluelessh_connection::{ChannelKind, ChannelNumber, ChannelOperation};
use std::{collections::HashMap, pin::Pin, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use cluelessh_protocol::{ChannelUpdateKind, SshStatus};
use eyre::{bail, ContextCompat, Result, WrapErr};
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::{Channel, ChannelState, PendingChannel};

pub struct ClientConnection<S> {
    stream: Pin<Box<S>>,
    buf: [u8; 1024],

    proto: cluelessh_protocol::ClientConnection,
    operations_send: tokio::sync::mpsc::Sender<Operation>,
    operations_recv: tokio::sync::mpsc::Receiver<Operation>,

    /// Cloned and passed on to channels.
    channel_ops_send: tokio::sync::mpsc::Sender<ChannelOperation>,
    channel_ops_recv: tokio::sync::mpsc::Receiver<ChannelOperation>,

    channels: HashMap<ChannelNumber, ChannelState>,

    auth: ClientAuth,
}

pub struct ClientAuth {
    pub username: String,
    pub prompt_password: Arc<dyn Fn() -> BoxFuture<'static, Result<String>> + Send + Sync>,
    pub sign_pubkey:
        Arc<dyn Fn([u8; 32]) -> BoxFuture<'static, Result<SignatureResult>> + Send + Sync>,
}

enum Operation {
    PasswordEntered(Result<String>),
    Signature(Result<SignatureResult>),
}

pub struct SignatureResult {
    pub key_alg_name: &'static str,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite> ClientConnection<S> {
    pub async fn connect(stream: S, auth: ClientAuth) -> Result<Self> {
        let (operations_send, operations_recv) = tokio::sync::mpsc::channel(15);
        let (channel_ops_send, channel_ops_recv) = tokio::sync::mpsc::channel(15);

        let mut this = Self {
            stream: Box::pin(stream),
            buf: [0; 1024],
            operations_send,
            operations_recv,
            channel_ops_send,
            channel_ops_recv,
            channels: HashMap::new(),
            proto: cluelessh_protocol::ClientConnection::new(
                cluelessh_transport::client::ClientConnection::new(
                    cluelessh_protocol::ThreadRngRand,
                ),
                cluelessh_protocol::auth::ClientAuth::new(auth.username.as_bytes().to_vec()),
            ),
            auth,
        };

        while !this.proto.is_open() {
            this.progress().await?;
        }

        Ok(this)
    }

    /// Executes one loop iteration of the main loop.
    // IMPORTANT: no operations on this struct should ever block the main loop, except this one.
    pub async fn progress(&mut self) -> Result<()> {
        if let Some(auth) = self.proto.auth() {
            for req in auth.user_requests() {
                match req {
                    cluelessh_protocol::auth::ClientUserRequest::Password => {
                        let send = self.operations_send.clone();
                        let prompt_password = self.auth.prompt_password.clone();
                        tokio::spawn(async move {
                            let password = prompt_password().await;
                            let _ = send.send(Operation::PasswordEntered(password)).await;
                        });
                    }
                    cluelessh_protocol::auth::ClientUserRequest::PrivateKeySign {
                        session_identifier,
                    } => {
                        let send = self.operations_send.clone();
                        let sign_pubkey = self.auth.sign_pubkey.clone();
                        tokio::spawn(async move {
                            let signature_result = sign_pubkey(session_identifier).await;
                            let _ = send.send(Operation::Signature(signature_result)).await;
                        });
                    }
                    cluelessh_protocol::auth::ClientUserRequest::Banner(_) => {
                        warn!("ignoring banner as it's not implemented...");
                    }
                }
            }
        }

        if let Some(channels) = self.proto.channels() {
            while let Some(update) = channels.next_channel_update() {
                match &update.kind {
                    ChannelUpdateKind::Open(_) => {
                        let channel = self
                            .channels
                            .get_mut(&update.number)
                            .wrap_err("unknown channel")?;
                        match channel {
                            ChannelState::Pending { updates_send, .. } => {
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
                            ChannelState::Ready(_) => {
                                bail!("attemping to open channel twice: {}", update.number);
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
                                bail!("attemping to open channel twice: {}", update.number);
                            }
                        }
                    }
                    _ => {
                        let channel = self
                            .channels
                            .get_mut(&update.number)
                            .wrap_err("unknown channel")?;
                        match channel {
                            ChannelState::Pending { .. } => bail!("channel not ready yet"),
                            ChannelState::Ready(updates_send) => {
                                let _ = updates_send.send(update.kind).await;
                            }
                        }
                    }
                }
            }
        }

        // Make sure that we send all queues messages before going into the select, waiting for things to happen.
        self.send_off_data().await?;

        tokio::select! {
            read = self.stream.read(&mut self.buf) => {
                let read = read.wrap_err("reading from connection")?;
                if read == 0 {
                    info!("Did not read any bytes from TCP stream, EOF");
                    return Ok(());
                }
                if let Err(err) = self.proto.recv_bytes(&self.buf[..read]) {
                    match err {
                        SshStatus::PeerError(err) => {
                            bail!("disconnecting client after invalid operation: {err}");
                        }
                        SshStatus::Disconnect => {
                            bail!("Received disconnect from server");
                        }
                    }
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
                    Some(Operation::PasswordEntered(password)) => {
                        if let Some(auth) = self.proto.auth() {
                            auth.send_password(&password?);
                        } else {
                            debug!("Ignoring entered password as the state has moved on");
                        }
                    }
                    Some(Operation::Signature(result)) => {
                        let result = result?;
                        if let Some(auth) = self.proto.auth() {
                            auth.send_signature(result.key_alg_name, &result.public_key, &result.signature);
                        } else {
                            debug!("Ignoring signature as the state has moved on");
                        }
                    }
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
}
