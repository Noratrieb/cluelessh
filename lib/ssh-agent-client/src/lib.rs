use eyre::{bail, eyre, Context};
use ssh_transport::{
    packet::PacketParser,
    parse::{Parser, Writer},
    SshStatus,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace};

/// A message to send to the byte stream.
pub enum Request {
    AddIdentity {
        key_type: String,
        key_contents: Vec<u8>,
        key_comment: String,
    },
    RemoveAllIdentities,
    ListIdentities,
    Sign {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    Lock {
        passphrase: String,
    },
    Unlock {
        passphrase: String,
    },
    Extension(ExtensionRequest),
}

pub enum ExtensionRequest {
    Query,
}

impl Request {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut p = Writer::new();
        match self {
            Self::AddIdentity {
                key_type,
                key_contents,
                key_comment,
            } => {
                p.u8(numbers::SSH_AGENTC_ADD_IDENTITY);
                p.string(key_type.as_bytes());
                p.write(&key_contents);
                p.string(key_comment.as_bytes());
            }
            Self::RemoveAllIdentities => p.u8(numbers::SSH_AGENTC_REMOVE_ALL_IDENTITIES),
            Self::ListIdentities => p.u8(numbers::SSH_AGENTC_REQUEST_IDENTITIES),
            Self::Sign {
                key_blob,
                data,
                flags,
            } => {
                p.u8(numbers::SSH_AGENTC_SIGN_REQUEST);
                p.string(&key_blob);
                p.string(&data);
                p.u32(*flags);
            }
            Self::Lock { passphrase } => {
                p.u8(numbers::SSH_AGENTC_LOCK);
                p.string(passphrase.as_bytes());
            }
            Self::Unlock { passphrase } => {
                p.u8(numbers::SSH_AGENTC_UNLOCK);
                p.string(passphrase.as_bytes());
            }
            Self::Extension(ext) => {
                p.u8(numbers::SSH_AGENTC_EXTENSION);
                match ext {
                    ExtensionRequest::Query => {
                        p.string(b"query");
                    }
                }
            }
        }

        let mut buf = p.finish();
        let len = u32::try_from(buf.len()).unwrap();
        buf.splice(0..0, len.to_be_bytes());
        buf
    }
}

/// A server response for an agent message.
#[derive(Debug)]
pub enum ServerResponse {
    /// SSH_AGENT_SUCCESS
    Success,
    /// SSH_AGENT_FAILURE
    Failure,

    IdentitiesAnswer {
        identities: Vec<IdentityAnswer>,
    },

    /// SSH_AGENT_SIGN_RESPONSE
    SignResponse {
        signature: Vec<u8>,
    },

    Extension(ExtensionResponse),
}

#[derive(Debug)]
pub enum ExtensionResponse {
    Query { types: Vec<String> },
}

/// A single identity in SSH_AGENT_IDENTITIES_ANSWER.
#[derive(Debug)]
pub struct IdentityAnswer {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

impl ServerResponse {
    pub fn parse(bytes: &[u8]) -> eyre::Result<Self> {
        let bytes = &bytes[4..];
        let mut p = Parser::new(bytes);
        let msg_type = p.u8()?;
        trace!(%msg_type, msg_type_str = %numbers::server_response_type_to_string(msg_type), "Received message");
        let resp = match msg_type {
            numbers::SSH_AGENT_FAILURE => Self::Failure,
            numbers::SSH_AGENT_SUCCESS => Self::Success,
            numbers::SSH_AGENT_IDENTITIES_ANSWER => {
                let nkeys = p.u32()?;
                let mut identities = Vec::new();
                for _ in 0..nkeys {
                    let key_blob = p.string()?;
                    let comment = p.utf8_string()?;
                    identities.push(IdentityAnswer {
                        key_blob: key_blob.to_owned(),
                        comment: comment.to_owned(),
                    });
                }
                Self::IdentitiesAnswer { identities }
            }
            numbers::SSH_AGENT_SIGN_RESPONSE => {
                let signature = p.string()?;
                Self::SignResponse {
                    signature: signature.to_owned(),
                }
            }
            numbers::SSH_AGENT_EXTENSION_RESPONSE => {
                let ext_type = p.utf8_string()?;
                trace!(?ext_type, "Received extension response");
                match ext_type {
                    "query" => {
                        let mut types = Vec::new();
                        while p.has_data() {
                            let name = p.utf8_string()?;
                            types.push(name.to_owned());
                        }
                        Self::Extension(ExtensionResponse::Query { types })
                    }
                    _ => bail!("unknown extension response type: {ext_type}"),
                }
            }
            _ => bail!(
                "unknown server message: {msg_type} ({})",
                numbers::server_response_type_to_string(msg_type)
            ),
        };
        Ok(resp)
    }
}

pub struct AgentConnection {
    packets: PacketParser,
}

impl AgentConnection {
    pub fn new() -> Self {
        Self {
            packets: PacketParser::new(),
        }
    }

    pub fn recv_bytes<'a>(
        &'a mut self,
        mut bytes: &'a [u8],
    ) -> impl Iterator<Item = eyre::Result<ServerResponse>> + 'a {
        std::iter::from_fn(move || -> Option<eyre::Result<ServerResponse>> {
            if bytes.len() == 0 {
                return None;
            }
            match self.packets.recv_plaintext_bytes(bytes) {
                Err(err) => Some(Err(match err {
                    SshStatus::PeerError(err) => eyre!(err),
                    SshStatus::Disconnect => unreachable!(),
                })),
                Ok(None) => None,
                Ok(Some((consumed, data))) => {
                    bytes = &bytes[consumed..];
                    self.packets = PacketParser::new();
                    Some(ServerResponse::parse(&data))
                }
            }
        })
    }
}

pub struct SocketAgentConnection {
    conn: AgentConnection,
    uds: tokio::net::UnixStream,
}

impl SocketAgentConnection {
    pub async fn from_env() -> eyre::Result<Self> {
        let sock = std::env::var("SSH_AUTH_SOCK").wrap_err("$SSH_AUTH_SOCK not found")?;

        debug!(%sock, "Connecting to SSH agent");

        let socket = tokio::net::UnixSocket::new_stream()
            .wrap_err("creating unix stream socket")?
            .connect(&sock)
            .await
            .wrap_err_with(|| format!("connecting to Unix stream socket on {sock}"))?;

        Ok(Self {
            conn: AgentConnection::new(),
            uds: socket,
        })
    }

    pub async fn add_identitity(
        &mut self,
        key_type: &str,
        key_contents: &[u8],
        key_comment: &str,
    ) -> eyre::Result<()> {
        self.send(Request::AddIdentity {
            key_type: key_type.to_owned(),
            key_contents: key_contents.to_owned(),
            key_comment: key_comment.to_owned(),
        })
        .await?;
        self.generic_response().await
    }

    pub async fn remove_all_identities(&mut self) -> eyre::Result<()> {
        self.send(Request::RemoveAllIdentities).await?;
        self.generic_response().await
    }

    pub async fn list_identities(&mut self) -> eyre::Result<Vec<IdentityAnswer>> {
        self.send(Request::ListIdentities).await?;

        let resp = self.get_response().await?;
        match resp {
            ServerResponse::IdentitiesAnswer { identities } => Ok(identities),
            _ => bail!("unexpected response: {resp:?}"),
        }
    }

    pub async fn sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> eyre::Result<Vec<u8>> {
        self.send(Request::Sign {
            key_blob: key_blob.to_owned(),
            data: data.to_owned(),
            flags,
        })
        .await?;

        let resp = self.get_response().await?;
        match resp {
            ServerResponse::SignResponse { signature } => Ok(signature),
            _ => bail!("unexpected response: {resp:?}"),
        }
    }

    pub async fn lock(&mut self, passphrase: &str) -> eyre::Result<()> {
        self.send(Request::Lock {
            passphrase: passphrase.to_owned(),
        })
        .await?;
        self.generic_response().await
    }

    pub async fn unlock(&mut self, passphrase: &str) -> eyre::Result<()> {
        self.send(Request::Unlock {
            passphrase: passphrase.to_owned(),
        })
        .await?;
        self.generic_response().await
    }

    pub async fn extension_query(&mut self) -> eyre::Result<Vec<String>> {
        self.send(Request::Extension(ExtensionRequest::Query))
            .await?;
        let resp = self.get_response().await?;
        match resp {
            ServerResponse::Extension(ExtensionResponse::Query { types }) => Ok(types),
            _ => bail!("unexpected response: {resp:?}"),
        }
    }

    async fn generic_response(&mut self) -> eyre::Result<()> {
        let resp = self.get_response().await?;

        match resp {
            ServerResponse::Success => Ok(()),
            ServerResponse::Failure => bail!("agent operation failed"),
            _ => bail!("unexpected response: {resp:?}"),
        }
    }

    async fn send(&mut self, msg: Request) -> eyre::Result<()> {
        self.uds.write_all(&msg.to_bytes()).await?;
        Ok(())
    }

    async fn get_response(&mut self) -> eyre::Result<ServerResponse> {
        let mut buf = [0_u8; 1024];
        loop {
            let read = self.uds.read(&mut buf).await?;
            let bytes = &buf[..read];
            // In practice, the server won't send more than one packet.
            if let Some(resp) = self.conn.recv_bytes(bytes).next() {
                return resp;
            }
        }
    }
}

pub mod numbers {
    pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
    pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
    pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
    pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
    pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
    pub const SSH_AGENTC_LOCK: u8 = 22;
    pub const SSH_AGENTC_UNLOCK: u8 = 23;
    pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
    pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
    pub const SSH_AGENTC_EXTENSION: u8 = 27;

    pub const SSH_AGENT_FAILURE: u8 = 5;
    pub const SSH_AGENT_SUCCESS: u8 = 6;
    pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
    pub const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;

    pub fn server_response_type_to_string(response_type: u8) -> &'static str {
        match response_type {
            SSH_AGENT_FAILURE => "SSH_AGENT_FAILURE",
            SSH_AGENT_SUCCESS => "SSH_AGENT_SUCCESS",
            SSH_AGENT_IDENTITIES_ANSWER => "SSH_AGENT_IDENTITIES_ANSWER",
            SSH_AGENT_SIGN_RESPONSE => "SSH_AGENT_SIGN_RESPONSE",
            SSH_AGENT_EXTENSION_FAILURE => "SSH_AGENT_EXTENSION_FAILURE",
            SSH_AGENT_EXTENSION_RESPONSE => "SSH_AGENT_EXTENSION_RESPONSE",
            _ => "<unknown>",
        }
    }
}
