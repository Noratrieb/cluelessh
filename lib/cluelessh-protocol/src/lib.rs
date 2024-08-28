use core::panic;
use std::collections::HashSet;
use std::mem;

use auth::AuthOption;
use cluelessh_connection::ChannelOperation;
use cluelessh_keys::public::PublicKey;
use cluelessh_keys::signature::Signature;
use tracing::debug;

// Re-exports
pub use cluelessh_connection as connection;
pub use cluelessh_connection::{ChannelUpdate, ChannelUpdateKind};
pub use cluelessh_transport as transport;
pub use cluelessh_transport::{Result, SshStatus};

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
    Setup(HashSet<AuthOption>, Option<String>),
    Auth(auth::ServerAuth),
    Open(cluelessh_connection::ChannelsState, String),
}

impl ServerConnection {
    pub fn new(
        transport: cluelessh_transport::server::ServerConnection,
        auth_options: HashSet<AuthOption>,
        auth_banner: Option<String>,
    ) -> Self {
        Self {
            transport,
            state: ServerConnectionState::Setup(auth_options, auth_banner),
        }
    }

    pub fn recv_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.transport.recv_bytes(bytes)?;

        if let ServerConnectionState::Setup(options, auth_banner) = &mut self.state {
            if let Some(session_ident) = self.transport.is_open() {
                self.state = ServerConnectionState::Auth(auth::ServerAuth::new(
                    mem::take(options),
                    auth_banner.take(),
                    session_ident,
                ));
            }
        }

        while let Some(packet) = self.transport.next_plaintext_packet() {
            match &mut self.state {
                ServerConnectionState::Setup(_, _) => unreachable!(),
                ServerConnectionState::Auth(auth) => {
                    auth.recv_packet(packet)?;
                    for to_send in auth.packets_to_send() {
                        self.transport.send_plaintext_packet(to_send);
                    }
                }
                ServerConnectionState::Open(con, _) => {
                    con.recv_packet(packet)?;
                }
            }

            self.progress();
        }

        Ok(())
    }

    pub fn is_waiting_on_signature(&self) -> Option<(&PublicKey, [u8; 32])> {
        self.transport.is_waiting_on_signature()
    }

    pub fn do_signature(&mut self, signature: Signature) {
        self.transport.do_signature(signature);
    }

    pub fn next_msg_to_send(&mut self) -> Option<cluelessh_transport::Msg> {
        self.transport.next_msg_to_send()
    }

    pub fn next_channel_update(&mut self) -> Option<cluelessh_connection::ChannelUpdate> {
        match &mut self.state {
            ServerConnectionState::Setup(..) | ServerConnectionState::Auth(_) => None,
            ServerConnectionState::Open(con, _) => con.next_channel_update(),
        }
    }

    pub fn do_operation(&mut self, op: ChannelOperation) {
        match &mut self.state {
            ServerConnectionState::Setup(..) | ServerConnectionState::Auth(_) => {
                panic!("tried to get connection before it is ready")
            }
            ServerConnectionState::Open(con, _) => {
                con.do_operation(op);
                self.progress();
            }
        }
    }

    pub fn progress(&mut self) {
        match &mut self.state {
            ServerConnectionState::Setup(..) => {}
            ServerConnectionState::Auth(auth) => {
                for to_send in auth.packets_to_send() {
                    self.transport.send_plaintext_packet(to_send);
                }
                if let Some(user) = auth.authenticated_user() {
                    self.state = ServerConnectionState::Open(
                        cluelessh_connection::ChannelsState::new(true),
                        user.to_owned(),
                    );
                }
            }
            ServerConnectionState::Open(con, _) => {
                for to_send in con.packets_to_send() {
                    self.transport.send_plaintext_packet(to_send);
                }
            }
        }
    }

    pub fn channels(&mut self) -> Option<&mut cluelessh_connection::ChannelsState> {
        match &mut self.state {
            ServerConnectionState::Open(channels, _) => Some(channels),
            _ => None,
        }
    }

    pub fn auth(&mut self) -> Option<&mut auth::ServerAuth> {
        match &mut self.state {
            ServerConnectionState::Auth(auth) => Some(auth),
            _ => None,
        }
    }

    pub fn authenticated_user(&self) -> Option<&str> {
        match &self.state {
            ServerConnectionState::Open(_, user) => Some(user),
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

                debug!("Connection has been opened");
                self.state = ClientConnectionState::Auth(auth);
                self.progress();
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
    use std::collections::{HashSet, VecDeque};

    use cluelessh_format::{numbers, NameList};
    use cluelessh_transport::{packet::Packet, peer_error, Result};
    use tracing::debug;

    pub struct ServerAuth {
        has_failed: bool,
        packets_to_send: VecDeque<Packet>,
        is_authenticated: Option<String>,
        options: HashSet<AuthOption>,
        banner: Option<String>,
        server_requests: VecDeque<ServerRequest>,
        session_ident: [u8; 32],
    }

    pub enum ServerRequest {
        VerifyPassword(VerifyPassword),
        /// Check whether a pubkey is usable.
        CheckPubkey(CheckPubkey),
        /// Verify the signature from a pubkey.
        VerifySignature(VerifySignature),
    }

    #[derive(Debug, Clone)]
    pub struct VerifyPassword {
        pub user: String,
        pub password: String,
    }

    #[derive(Debug, Clone)]
    pub struct CheckPubkey {
        pub user: String,
        pub session_identifier: [u8; 32],
        pub pubkey_alg_name: String,
        pub pubkey: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    pub struct VerifySignature {
        pub user: String,
        pub session_identifier: [u8; 32],
        pub pubkey_alg_name: String,
        pub pubkey: Vec<u8>,
        pub signature: Vec<u8>,
    }

    #[derive(Debug, PartialEq, Eq, Hash)]
    pub enum AuthOption {
        Password,
        PublicKey,
    }

    impl ServerAuth {
        pub fn new(
            options: HashSet<AuthOption>,
            banner: Option<String>,
            session_ident: [u8; 32],
        ) -> Self {
            Self {
                has_failed: false,
                packets_to_send: VecDeque::new(),
                options,
                is_authenticated: None,
                session_ident,
                banner,
                server_requests: VecDeque::new(),
            }
        }

        pub fn recv_packet(&mut self, packet: Packet) -> Result<()> {
            assert!(self.is_authenticated.is_none(), "Must not feed more packets to authentication after authentication is been completed, check with .is_authenticated()");

            // This is a super simplistic implementation of RFC4252 SSH authentication.
            // We ask for a public key, and always let that one pass.
            // The reason for this is that this makes it a lot easier to test locally.
            // It's not very good, but it's good enough for now.
            let mut p = packet.payload_parser();

            if p.u8()? != numbers::SSH_MSG_USERAUTH_REQUEST {
                return Err(peer_error!("did not send SSH_MSG_SERVICE_REQUEST"));
            }
            let username = p.utf8_string()?;
            let service_name = p.utf8_string()?;
            let method_name = p.utf8_string()?;

            if method_name != "none" {
                debug!(
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
                    if !self.options.contains(&AuthOption::Password) {
                        self.has_failed = true;
                        self.send_failure();
                    }

                    let change_password = p.bool()?;
                    if change_password {
                        return Err(peer_error!("client tried to change password unprompted"));
                    }
                    let password = p.utf8_string()?;

                    self.server_requests
                        .push_back(ServerRequest::VerifyPassword(VerifyPassword {
                            user: username.to_owned(),
                            password: password.to_owned(),
                        }));
                }
                "publickey" => {
                    if !self.options.contains(&AuthOption::PublicKey) {
                        self.has_failed = true;
                        self.send_failure();
                    }

                    let has_signature = p.bool()?;

                    let pubkey_alg_name = p.utf8_string()?;
                    let public_key_blob = p.string()?;

                    // Whether the client is just checking whether the public key is allowed.
                    if !has_signature {
                        self.server_requests
                            .push_back(ServerRequest::CheckPubkey(CheckPubkey {
                                user: username.to_owned(),
                                session_identifier: self.session_ident,
                                pubkey_alg_name: pubkey_alg_name.to_owned(),
                                pubkey: public_key_blob.to_vec(),
                            }));
                    } else {
                        let signature = p.string()?;
                        self.server_requests
                            .push_back(ServerRequest::VerifySignature(VerifySignature {
                                user: username.to_owned(),
                                session_identifier: self.session_ident,
                                pubkey_alg_name: pubkey_alg_name.to_owned(),
                                pubkey: public_key_blob.to_vec(),
                                signature: signature.to_vec(),
                            }));
                    }
                }
                _ if self.has_failed => {
                    return Err(peer_error!(
                        "client tried unsupported method twice: {method_name}"
                    ));
                }
                _ => {
                    // Initial:
                    if let Some(banner) = &self.banner {
                        self.queue_packet(Packet::new_msg_userauth_banner(banner.as_bytes(), b""));
                    }
                    self.send_failure();
                    // Stay in the same state
                }
            }
            Ok(())
        }

        pub fn pubkey_check_result(&mut self, is_ok: bool, alg: &str, key_blob: &[u8]) {
            if is_ok {
                self.queue_packet(Packet::new_msg_userauth_pk_ok(alg.as_bytes(), key_blob));
            } else {
                self.send_failure();
                // It's ok, don't treat this as a fatal failure.
            }
        }

        // TODO: improve types with a newtype around an authenticated user
        pub fn verification_result(&mut self, is_ok: bool, user: String) {
            if is_ok {
                self.queue_packet(Packet::new_msg_userauth_success());
                self.is_authenticated = Some(user);
            } else {
                self.send_failure();
                self.has_failed = true;
            }
        }

        pub fn packets_to_send(&mut self) -> impl Iterator<Item = Packet> + '_ {
            self.packets_to_send.drain(..)
        }

        pub fn authenticated_user(&self) -> Option<&str> {
            self.is_authenticated.as_deref()
        }

        pub fn server_requests(&mut self) -> impl Iterator<Item = ServerRequest> + '_ {
            self.server_requests.drain(..)
        }

        fn send_failure(&mut self) {
            self.queue_packet(Packet::new_msg_userauth_failure(
                NameList(&self.option_list()),
                false,
            ));
        }

        fn option_list(&self) -> String {
            self.options
                .iter()
                .map(|op| match op {
                    AuthOption::Password => "password",
                    AuthOption::PublicKey => "publickey",
                })
                .collect::<Vec<&str>>()
                .join(",")
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
