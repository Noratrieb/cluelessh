use std::mem;

pub use cluelessh_connection as connection;
use cluelessh_connection::ChannelOperation;
pub use cluelessh_connection::{ChannelUpdate, ChannelUpdateKind};
pub use cluelessh_transport as transport;
pub use cluelessh_transport::{Result, SshStatus};
use tracing::debug;

pub struct ThreadRngRand;
impl transport::SshRng for ThreadRngRand {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(dest);
    }
}

pub struct ServerConnection {
    transport: cluelessh_transport::server::ServerConnection,
    state: ServerConnectionState,
}

enum ServerConnectionState {
    Auth(auth::BadAuth),
    Open(cluelessh_connection::ChannelsState),
}

impl ServerConnection {
    pub fn new(transport: cluelessh_transport::server::ServerConnection) -> Self {
        Self {
            transport,
            state: ServerConnectionState::Auth(auth::BadAuth::new()),
        }
    }

    pub fn recv_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.transport.recv_bytes(bytes)?;

        while let Some(packet) = self.transport.next_plaintext_packet() {
            match &mut self.state {
                ServerConnectionState::Auth(auth) => {
                    auth.recv_packet(packet)?;
                    for to_send in auth.packets_to_send() {
                        self.transport.send_plaintext_packet(to_send);
                    }
                    if auth.is_authenticated() {
                        self.state = ServerConnectionState::Open(
                            cluelessh_connection::ChannelsState::new(true),
                        );
                    }
                }
                ServerConnectionState::Open(con) => {
                    con.recv_packet(packet)?;
                }
            }

            self.progress();
        }

        Ok(())
    }

    pub fn next_msg_to_send(&mut self) -> Option<cluelessh_transport::Msg> {
        self.transport.next_msg_to_send()
    }

    pub fn next_channel_update(&mut self) -> Option<cluelessh_connection::ChannelUpdate> {
        match &mut self.state {
            ServerConnectionState::Auth(_) => None,
            ServerConnectionState::Open(con) => con.next_channel_update(),
        }
    }

    pub fn do_operation(&mut self, op: ChannelOperation) {
        match &mut self.state {
            ServerConnectionState::Auth(_) => panic!("tried to get connection during auth"),
            ServerConnectionState::Open(con) => {
                con.do_operation(op);
                self.progress();
            }
        }
    }

    pub fn progress(&mut self) {
        match &mut self.state {
            ServerConnectionState::Auth(auth) => {
                for to_send in auth.packets_to_send() {
                    self.transport.send_plaintext_packet(to_send);
                }
            }
            ServerConnectionState::Open(con) => {
                for to_send in con.packets_to_send() {
                    self.transport.send_plaintext_packet(to_send);
                }
            }
        }
    }

    pub fn channels(&mut self) -> Option<&mut cluelessh_connection::ChannelsState> {
        match &mut self.state {
            ServerConnectionState::Open(channels) => Some(channels),
            _ => None,
        }
    }

    pub fn auth(&mut self) -> Option<&mut auth::BadAuth> {
        match &mut self.state {
            ServerConnectionState::Auth(auth) => Some(auth),
            _ => None,
        }
    }
}

pub struct ClientConnection {
    transport: cluelessh_transport::client::ClientConnection,
    state: ClientConnectionState,
}

enum ClientConnectionState {
    Setup(Option<auth::ClientAuth>),
    Auth(auth::ClientAuth),
    Open(cluelessh_connection::ChannelsState),
}

impl ClientConnection {
    pub fn new(
        transport: cluelessh_transport::client::ClientConnection,
        auth: auth::ClientAuth,
    ) -> Self {
        Self {
            transport,
            state: ClientConnectionState::Setup(Some(auth)),
        }
    }

    pub fn recv_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.transport.recv_bytes(bytes)?;

        if let ClientConnectionState::Setup(auth) = &mut self.state {
            if let Some(session_ident) = self.transport.is_open() {
                let mut auth = mem::take(auth).unwrap();
                auth.set_session_identifier(session_ident);
                for to_send in auth.packets_to_send() {
                    self.transport.send_plaintext_packet(to_send);
                }
                debug!("Connection has been opened");
                self.state = ClientConnectionState::Auth(auth);
            }
        }

        while let Some(packet) = self.transport.next_plaintext_packet() {
            match &mut self.state {
                ClientConnectionState::Setup(_) => unreachable!("handled above"),
                ClientConnectionState::Auth(auth) => {
                    auth.recv_packet(packet)?;
                    for to_send in auth.packets_to_send() {
                        self.transport.send_plaintext_packet(to_send);
                    }
                    if auth.is_authenticated() {
                        self.state = ClientConnectionState::Open(
                            cluelessh_connection::ChannelsState::new(false),
                        );
                    }
                }
                ClientConnectionState::Open(con) => {
                    con.recv_packet(packet)?;
                    for to_send in con.packets_to_send() {
                        self.transport.send_plaintext_packet(to_send);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn auth(&mut self) -> Option<&mut auth::ClientAuth> {
        match &mut self.state {
            ClientConnectionState::Auth(auth) => Some(auth),
            _ => None,
        }
    }

    pub fn channels(&mut self) -> Option<&mut cluelessh_connection::ChannelsState> {
        match &mut self.state {
            ClientConnectionState::Open(channels) => Some(channels),
            _ => None,
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, ClientConnectionState::Open(_))
    }

    pub fn next_msg_to_send(&mut self) -> Option<cluelessh_transport::Msg> {
        self.transport.next_msg_to_send()
    }

    pub fn next_channel_update(&mut self) -> Option<cluelessh_connection::ChannelUpdate> {
        match &mut self.state {
            ClientConnectionState::Setup(_) => None,
            ClientConnectionState::Auth(_) => None,
            ClientConnectionState::Open(con) => con.next_channel_update(),
        }
    }

    pub fn do_operation(&mut self, op: ChannelOperation) {
        match &mut self.state {
            ClientConnectionState::Setup(_) | ClientConnectionState::Auth(_) => {
                panic!("tried to get connection during auth")
            }
            ClientConnectionState::Open(con) => {
                con.do_operation(op);
                self.progress();
            }
        }
    }

    pub fn progress(&mut self) {
        match &mut self.state {
            ClientConnectionState::Setup(_) => {}
            ClientConnectionState::Auth(auth) => {
                for to_send in auth.packets_to_send() {
                    self.transport.send_plaintext_packet(to_send);
                }
            }
            ClientConnectionState::Open(con) => {
                for to_send in con.packets_to_send() {
                    self.transport.send_plaintext_packet(to_send);
                }
            }
        }
    }
}

/// <https://datatracker.ietf.org/doc/html/rfc4252>
pub mod auth {
    use std::collections::VecDeque;

    use cluelessh_transport::{numbers, packet::Packet, parse::NameList, peer_error, Result};
    use tracing::{debug, info};

    pub struct BadAuth {
        has_failed: bool,
        packets_to_send: VecDeque<Packet>,
        is_authenticated: bool,
    }

    pub enum ServerRequest {
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

    impl BadAuth {
        pub fn new() -> Self {
            Self {
                has_failed: false,
                packets_to_send: VecDeque::new(),
                is_authenticated: false,
            }
        }

        pub fn recv_packet(&mut self, packet: Packet) -> Result<()> {
            assert!(!self.is_authenticated, "Must not feed more packets to authentication after authentication is been completed, check with .is_authenticated()");

            // This is a super simplistic implementation of RFC4252 SSH authentication.
            // We ask for a public key, and always let that one pass.
            // The reason for this is that this makes it a lot easier to test locally.
            // It's not very good, but it's good enough for now.
            let mut auth_req = packet.payload_parser();

            if auth_req.u8()? != numbers::SSH_MSG_USERAUTH_REQUEST {
                return Err(peer_error!("did not send SSH_MSG_SERVICE_REQUEST"));
            }
            let username = auth_req.utf8_string()?;
            let service_name = auth_req.utf8_string()?;
            let method_name = auth_req.utf8_string()?;

            if method_name != "none" {
                info!(
                    %username,
                    %service_name,
                    %method_name,
                    "User trying to authenticate"
                );
            }

            if service_name != "ssh-connection" {
                return Err(peer_error!(
                    "client tried to unsupported service: {service_name}"
                ));
            }

            match method_name {
                "password" => {
                    let change_password = auth_req.bool()?;
                    if change_password {
                        return Err(peer_error!("client tried to change password unprompted"));
                    }
                    let password = auth_req.utf8_string()?;

                    info!(%password, "Got password");
                    // Don't worry queen, your password is correct!
                    self.queue_packet(Packet::new_msg_userauth_success());
                    self.is_authenticated = true;
                }
                "publickey" => {
                    info!("Got public key");
                    // Don't worry queen, your key is correct!
                    self.queue_packet(Packet::new_msg_userauth_success());
                    self.is_authenticated = true;
                }
                _ if self.has_failed => {
                    return Err(peer_error!(
                        "client tried unsupported method twice: {method_name}"
                    ));
                }
                _ => {
                    // Initial.

                    self.queue_packet(Packet::new_msg_userauth_banner(
                                b"!! this system ONLY allows catgirls to enter !!\r\n\
                                !! all other attempts WILL be prosecuted to the full extent of the rawr !!\r\n\
                                !! THIS SYTEM WILL LOG AND STORE YOUR CLEARTEXT PASSWORD !!\r\n\
                                !! DO NOT ENTER PASSWORDS YOU DON'T WANT STOLEN !!\r\n",
                                b"",
                            ));

                    self.queue_packet(Packet::new_msg_userauth_failure(
                        NameList::one("password"),
                        false,
                    ));
                    // Stay in the same state
                }
            }
            Ok(())
        }

        pub fn packets_to_send(&mut self) -> impl Iterator<Item = Packet> + '_ {
            self.packets_to_send.drain(..)
        }

        pub fn is_authenticated(&self) -> bool {
            self.is_authenticated
        }

        pub fn server_requests(&mut self) -> impl Iterator<Item = ServerRequest> + '_ {
            [].into_iter()
        }

        fn queue_packet(&mut self, packet: Packet) {
            self.packets_to_send.push_back(packet);
        }
    }

    pub struct ClientAuth {
        username: Vec<u8>,
        packets_to_send: VecDeque<Packet>,
        user_requests: VecDeque<ClientUserRequest>,
        is_authenticated: bool,
        session_identifier: Option<[u8; 32]>,
    }

    pub enum ClientUserRequest {
        Password,
        PrivateKeySign { session_identifier: [u8; 32] },
        Banner(Vec<u8>),
    }

    impl ClientAuth {
        pub fn new(username: Vec<u8>) -> Self {
            let mut packets_to_send = VecDeque::new();
            let initial_useruath_req =
                Packet::new_msg_userauth_request_none(&username, b"ssh-connection", b"none");
            packets_to_send.push_back(initial_useruath_req);

            Self {
                packets_to_send,
                username,
                user_requests: VecDeque::new(),
                is_authenticated: false,
                session_identifier: None,
            }
        }

        pub fn set_session_identifier(&mut self, ident: [u8; 32]) {
            assert!(self.session_identifier.is_none());
            self.session_identifier = Some(ident);
        }

        pub fn is_authenticated(&self) -> bool {
            self.is_authenticated
        }

        pub fn packets_to_send(&mut self) -> impl Iterator<Item = Packet> + '_ {
            self.packets_to_send.drain(..)
        }

        pub fn user_requests(&mut self) -> impl Iterator<Item = ClientUserRequest> + '_ {
            self.user_requests.drain(..)
        }

        pub fn send_password(&mut self, password: &str) {
            let packet = Packet::new_msg_userauth_request_password(
                &self.username,
                b"ssh-connection",
                b"password",
                false,
                password.as_bytes(),
            );
            self.packets_to_send.push_back(packet);
        }

        pub fn send_signature(&mut self, key_alg_name: &str, public_key: &[u8], signature: &[u8]) {
            let packet = Packet::new_msg_userauth_request_publickey(
                &self.username,
                b"ssh-connection",
                b"publickey",
                true,
                key_alg_name.as_bytes(),
                public_key,
                signature,
            );
            self.packets_to_send.push_back(packet);
        }

        pub fn recv_packet(&mut self, packet: Packet) -> Result<()> {
            assert!(!self.is_authenticated, "Must not feed more packets to authentication after authentication is been completed, check with .is_authenticated()");

            let mut p = packet.payload_parser();
            let packet_type = p.u8()?;

            match packet_type {
                numbers::SSH_MSG_USERAUTH_BANNER => {
                    let banner = p.string()?;
                    let _lang = p.string()?;

                    self.user_requests
                        .push_back(ClientUserRequest::Banner(banner.to_vec()));
                }
                numbers::SSH_MSG_USERAUTH_FAILURE => {
                    let authentications = p.name_list()?;
                    let _partial_success = p.bool()?;

                    if authentications.iter().any(|item| item == "password") {
                        debug!("Received authentication failure, trying password");
                        self.user_requests.push_back(ClientUserRequest::Password);
                    } else if authentications.iter().any(|item| item == "publickey") {
                        debug!("Received authentication failure, trying publickey");
                        // <https://datatracker.ietf.org/doc/html/rfc4252#section-7>
                        // TODO: Ask the server whether there are any keys we can use instead of just yoloing the signature.
                        self.user_requests
                            .push_back(ClientUserRequest::PrivateKeySign {
                                session_identifier: self
                                    .session_identifier
                                    .expect("set_session_identifier has not been called"),
                            });
                    } else {
                        return Err(peer_error!(
                            "server does not support password authentication"
                        ));
                    }
                }
                numbers::SSH_MSG_USERAUTH_SUCCESS => {
                    self.is_authenticated = true;
                }
                _ => {
                    return Err(peer_error!(
                        "unexpected packet: {}",
                        numbers::packet_type_to_string(packet_type)
                    ))
                }
            }

            Ok(())
        }
    }
}
