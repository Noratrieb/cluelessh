pub use ssh_connection as connection;
use ssh_connection::ChannelOperation;
pub use ssh_connection::{ChannelUpdate, ChannelUpdateKind};
pub use ssh_transport as transport;
pub use ssh_transport::{Result, SshStatus};

pub struct ServerConnection {
    transport: ssh_transport::ServerConnection,
    state: ServerConnectionState,
}

enum ServerConnectionState {
    Auth(auth::BadAuth),
    Open(ssh_connection::ServerChannelsState),
}

impl ServerConnection {
    pub fn new(transport: ssh_transport::ServerConnection) -> Self {
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
                        self.state =
                            ServerConnectionState::Open(ssh_connection::ServerChannelsState::new());
                    }
                }
                ServerConnectionState::Open(con) => {
                    con.recv_packet(packet)?;
                    for to_send in con.packets_to_send() {
                        self.transport.send_plaintext_packet(to_send);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn next_msg_to_send(&mut self) -> Option<ssh_transport::Msg> {
        self.transport.next_msg_to_send()
    }

    pub fn next_channel_update(&mut self) -> Option<ssh_connection::ChannelUpdate> {
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

    use ssh_transport::{client_error, packet::Packet, parse::NameList, Result};
    use tracing::info;

    pub struct BadAuth {
        has_failed: bool,
        packets_to_send: VecDeque<Packet>,
        is_authenticated: bool,
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

            if auth_req.u8()? != Packet::SSH_MSG_USERAUTH_REQUEST {
                return Err(client_error!("did not send SSH_MSG_SERVICE_REQUEST"));
            }
            let username = auth_req.utf8_string()?;
            let service_name = auth_req.utf8_string()?;
            let method_name = auth_req.utf8_string()?;

            info!(
                ?username,
                ?service_name,
                ?method_name,
                "User trying to authenticate"
            );

            if service_name != "ssh-connection" {
                return Err(client_error!(
                    "client tried to unsupported service: {service_name}"
                ));
            }

            match method_name {
                "password" => {
                    let change_password = auth_req.bool()?;
                    if change_password {
                        return Err(client_error!("client tried to change password unprompted"));
                    }
                    let password = auth_req.utf8_string()?;

                    info!(?password, "Got password");
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
                    return Err(client_error!(
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

        fn queue_packet(&mut self, packet: Packet) {
            self.packets_to_send.push_back(packet);
        }
    }
}
