use std::{collections::VecDeque, mem};

use tracing::{debug, info, trace};

use crate::{
    crypto::{self, AlgorithmName, AlgorithmNegotiation},
    numbers,
    packet::{Packet, PacketTransport, ProtocolIdentParser},
    parse::{NameList, Parser, Writer},
    peer_error, Msg, Result, SshRng, SshStatus,
};

pub struct ClientConnection {
    state: ClientState,
    packet_transport: PacketTransport,
    rng: Box<dyn SshRng + Send + Sync>,

    plaintext_packets: VecDeque<Packet>,
}

enum ClientState {
    ProtoExchange {
        client_ident: Vec<u8>,
        ident_parser: ProtocolIdentParser,
    },
    KexInit {
        client_ident: Vec<u8>,
    },
}

impl ClientConnection {
    pub fn new(rng: impl SshRng + Send + Sync + 'static) -> Self {
        let client_ident = b"SSH-2.0-FakeSSH\r\n".to_vec();

        let mut packet_transport = PacketTransport::new();
        packet_transport.queue_send_protocol_info(client_ident.clone());

        Self {
            state: ClientState::ProtoExchange {
                ident_parser: ProtocolIdentParser::new(),
                client_ident,
            },
            packet_transport,
            rng: Box::new(rng),

            plaintext_packets: VecDeque::new(),
        }
    }

    pub fn recv_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if let ClientState::ProtoExchange {
            ident_parser,
            client_ident,
        } = &mut self.state
        {
            ident_parser.recv_bytes(bytes);
            if ident_parser.get_peer_ident().is_some() {
                let client_ident = mem::take(client_ident);
                // This moves to the next state.
                self.send_kexinit(client_ident);
                return Ok(());
            }
            return Ok(());
        }

        self.packet_transport.recv_bytes(bytes)?;

        while let Some(packet) = self.packet_transport.recv_next_packet() {
            let packet_type = packet.payload.get(0).unwrap_or(&0xFF);
            let packet_type_string = numbers::packet_type_to_string(*packet_type);

            trace!(%packet_type, %packet_type_string, packet_len = %packet.payload.len(), "Received packet");

            // Handle some packets ignoring the state.
            match packet.payload.get(0).copied() {
                Some(numbers::SSH_MSG_DISCONNECT) => {
                    // <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>
                    let mut disconnect = Parser::new(&packet.payload[1..]);
                    let reason = disconnect.u32()?;
                    let description = disconnect.utf8_string()?;
                    let _language_tag = disconnect.utf8_string()?;

                    let reason_string =
                        numbers::disconnect_reason_to_string(reason).unwrap_or("<unknown>");

                    info!(%reason, %reason_string, %description, "Server disconnecting");

                    return Err(SshStatus::Disconnect);
                }
                _ => {}
            }

            match &mut self.state {
                ClientState::ProtoExchange { .. } => unreachable!("handled above"),
                ClientState::KexInit { client_ident } => {
                    let mut kexinit = packet.payload_parser();
                    let packet_type = kexinit.u8()?;
                    if packet_type != numbers::SSH_MSG_KEXINIT {
                        return Err(peer_error!(
                            "expected SSH_MSG_KEXINIT, found {}",
                            numbers::packet_type_to_string(packet_type)
                        ));
                    }
/* 
                    let cookie = kexinit.array::<16>()?;
                    let kex_algorithm = kexinit.name_list()?;
                    let kex_algorithms = AlgorithmNegotiation {
                        supported: vec![
                            crypto::KEX_CURVE_25519_SHA256,
                            crypto::KEX_ECDH_SHA2_NISTP256,
                        ],
                    };
                    let kex_algorithm = kex_algorithms.find(kex_algorithm.0)?;
                    debug!(name = %kex_algorithm.name(), "Using KEX algorithm");

                    let server_hostkey_algorithm = kexinit.name_list()?;
                    let server_hostkey_algorithms = AlgorithmNegotiation {
                        supported: vec![
                            crypto::hostkey_ed25519(ED25519_PRIVKEY_BYTES.to_vec()),
                            crypto::hostkey_ecdsa_sha2_p256(ECDSA_P256_PRIVKEY_BYTES.to_vec()),
                        ],
                    };
                    let server_hostkey_algorithm =
                        server_hostkey_algorithms.find(server_hostkey_algorithm.0)?;
                    debug!(name = %server_hostkey_algorithm.name(), "Using host key algorithm");

                    let encryption_algorithms_client_to_server = kexinit.name_list()?;
                    let encryption_algorithms_client_to_server = select_alg(
                        encryption_algorithms_client_to_server,
                        [
                            crypto::encrypt::CHACHA20POLY1305,
                            crypto::encrypt::AES256_GCM,
                        ],
                    );
                    let encryption_algorithms_server_to_client = kexinit.name_list()?;
                    let encryption_algorithms_server_to_client = select_alg(
                        encryption_algorithms_server_to_client,
                        [
                            crypto::encrypt::CHACHA20POLY1305,
                            crypto::encrypt::AES256_GCM,
                        ],
                    );
                    let mac_algorithms_client_to_server = kexinit.name_list()?;
                    select_alg(mac_algorithms_client_to_server, ["hmac-sha2-256"])?;
                    let mac_algorithms_server_to_client = kexinit.name_list()?;
                    select_alg(mac_algorithms_server_to_client, ["hmac-sha2-256"])?;

                    let compression_algorithms_client_to_server = kexinit.name_list()?;
                    select_alg(compression_algorithms_client_to_server, ["none"])?;
                    let compression_algorithms_server_to_client = kexinit.name_list()?;
                    select_alg(compression_algorithms_server_to_client, ["none"])?;
                    let _languages_client_to_server = kexinit.name_list()?;
                    let _languages_server_to_client = kexinit.name_list()?;
                    let first_kex_packet_follows = kexinit.bool()?;
                    if first_kex_packet_follows {
                        return Err(peer_error!("does not support guessed kex init packages"));
                    }*/
                }
            }
        }
        Ok(())
    }

    pub fn next_msg_to_send(&mut self) -> Option<Msg> {
        self.packet_transport.next_msg_to_send()
    }

    fn send_kexinit(&mut self, client_ident: Vec<u8>) {
        let mut cookie = [0; 16];
        self.rng.fill_bytes(&mut cookie);

        let mut kexinit = Writer::new();
        kexinit.u8(numbers::SSH_MSG_KEXINIT);
        kexinit.array(cookie);
        kexinit.name_list(NameList::multi("curve25519-sha256,ecdh-sha2-nistp256")); // kex_algorithms
        kexinit.name_list(NameList::multi("ssh-ed25519,ecdsa-sha2-nistp256")); // server_host_key_algorithms
        kexinit.name_list(NameList::multi(
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        )); // encryption_algorithms_client_to_server
        kexinit.name_list(NameList::multi(
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        )); // encryption_algorithms_server_to_client
        kexinit.name_list(NameList::one("hmac-sha2-256")); // mac_algorithms_client_to_server
        kexinit.name_list(NameList::one("hmac-sha2-256")); // mac_algorithms_server_to_client
        kexinit.name_list(NameList::one("none")); // compression_algorithms_client_to_server
        kexinit.name_list(NameList::one("none")); // compression_algorithms_server_to_client
        kexinit.name_list(NameList::none()); // languages_client_to_server
        kexinit.name_list(NameList::none()); // languages_server_to_client
        kexinit.bool(false); // first_kex_packet_follows
        kexinit.u32(0); // reserved
        let kexinit = kexinit.finish();

        self.packet_transport
            .queue_packet(Packet { payload: kexinit });
        self.state = ClientState::KexInit { client_ident };
    }
}
