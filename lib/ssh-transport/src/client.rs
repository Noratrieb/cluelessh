use std::{collections::VecDeque, mem};

use tracing::{debug, info, trace};

use crate::{
    crypto::{
        self, AlgorithmName, EncodedSshSignature, EncryptionAlgorithm, HostKeySigningAlgorithm,
        KeyExchangeSecret, SupportedAlgorithms,
    },
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

    pub abort_for_dos: bool,
}

enum ClientState {
    ProtoExchange {
        client_ident: Vec<u8>,
        ident_parser: ProtocolIdentParser,
    },
    KexInit {
        client_ident: Vec<u8>,
        server_ident: Vec<u8>,
        client_kexinit: Vec<u8>,
    },
    DhKeyInit {
        client_ident: Vec<u8>,
        server_ident: Vec<u8>,
        kex_secret: Option<KeyExchangeSecret>,
        server_hostkey_algorithm: HostKeySigningAlgorithm,
        encryption_client_to_server: EncryptionAlgorithm,
        encryption_server_to_client: EncryptionAlgorithm,
        client_kexinit: Vec<u8>,
        server_kexinit: Vec<u8>,
    },
    NewKeys {
        h: [u8; 32],
        k: Vec<u8>,
        encryption_client_to_server: EncryptionAlgorithm,
        encryption_server_to_client: EncryptionAlgorithm,
    },
    ServiceRequest {
        session_identifier: [u8; 32],
    },
    Open {
        session_identifier: [u8; 32],
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
            abort_for_dos: false,
        }
    }

    pub fn recv_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if let ClientState::ProtoExchange {
            ident_parser,
            client_ident,
        } = &mut self.state
        {
            ident_parser.recv_bytes(bytes);
            if let Some(server_ident) = ident_parser.get_peer_ident() {
                let client_ident = mem::take(client_ident);
                // This moves to the next state.
                self.send_kexinit(client_ident, server_ident);
                return Ok(());
            }
            return Ok(());
        }

        self.packet_transport.recv_bytes(bytes)?;

        while let Some(packet) = self.packet_transport.recv_next_packet() {
            let packet_type = packet.payload.first().unwrap_or(&0xFF);
            let packet_type_string = numbers::packet_type_to_string(*packet_type);

            trace!(%packet_type, %packet_type_string, packet_len = %packet.payload.len(), "Received packet");

            // TODO: deduplicate with server
            // Handle some packets ignoring the state.
            match packet.payload.first().copied() {
                Some(numbers::SSH_MSG_DISCONNECT) => {
                    // <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>
                    let mut p = Parser::new(&packet.payload[1..]);
                    let reason = p.u32()?;
                    let description = p.utf8_string()?;
                    let _language_tag = p.utf8_string()?;

                    let reason_string =
                        numbers::disconnect_reason_to_string(reason).unwrap_or("<unknown>");

                    info!(%reason, %reason_string, %description, "Server disconnecting");

                    return Err(SshStatus::Disconnect);
                }
                Some(numbers::SSH_MSG_IGNORE) => {
                    // <https://datatracker.ietf.org/doc/html/rfc4253#section-11.2>
                    let mut p = Parser::new(&packet.payload[1..]);
                    let _ = p.string()?;
                    continue;
                }
                Some(numbers::SSH_MSG_DEBUG) => {
                    // <https://datatracker.ietf.org/doc/html/rfc4253#section-11.3>
                    let mut p = Parser::new(&packet.payload[1..]);
                    let always_display = p.bool()?;
                    let msg = p.utf8_string()?;
                    let _language_tag = p.utf8_string()?;

                    if always_display {
                        info!(%msg, "Received debug message (SSH_MSG_DEBUG)");
                    } else {
                        debug!(%msg, "Received debug message (SSH_MSG_DEBUG)")
                    }
                    continue;
                }
                _ => {}
            }

            match &mut self.state {
                ClientState::ProtoExchange { .. } => unreachable!("handled above"),
                ClientState::KexInit {
                    client_ident,
                    server_ident,
                    client_kexinit,
                } => {
                    let mut kexinit = packet.payload_parser();
                    let packet_type = kexinit.u8()?;
                    if packet_type != numbers::SSH_MSG_KEXINIT {
                        return Err(peer_error!(
                            "expected SSH_MSG_KEXINIT, found {}",
                            numbers::packet_type_to_string(packet_type)
                        ));
                    }

                    let sup_algs = SupportedAlgorithms::secure();

                    let _cookie = kexinit.array::<16>()?;

                    let kex_algorithm = kexinit.name_list()?;
                    let kex_algorithm = sup_algs.key_exchange.find(kex_algorithm.0)?;
                    debug!(name = %kex_algorithm.name(), "Using KEX algorithm");

                    let server_hostkey_algorithm = kexinit.name_list()?;
                    let server_hostkey_algorithm =
                        sup_algs.hostkey.find(server_hostkey_algorithm.0)?;
                    debug!(name = %server_hostkey_algorithm.name(), "Using host key algorithm");

                    let encryption_algorithms_client_to_server = kexinit.name_list()?;
                    let encryption_client_to_server = sup_algs
                        .encryption_to_peer
                        .find(encryption_algorithms_client_to_server.0)?;
                    debug!(name = %encryption_client_to_server.name(), "Using encryption algorithm C->S");

                    let encryption_algorithms_server_to_client = kexinit.name_list()?;
                    let encryption_server_to_client = sup_algs
                        .encryption_from_peer
                        .find(encryption_algorithms_server_to_client.0)?;
                    debug!(name = %encryption_server_to_client.name(), "Using encryption algorithm S->C");

                    let mac_algorithms_client_to_server = kexinit.name_list()?;
                    let _mac_client_to_server = sup_algs
                        .mac_to_peer
                        .find(mac_algorithms_client_to_server.0)?;
                    let mac_algorithms_server_to_client = kexinit.name_list()?;
                    let _mac_server_to_client = sup_algs
                        .mac_from_peer
                        .find(mac_algorithms_server_to_client.0)?;

                    let compression_algorithms_client_to_server = kexinit.name_list()?;
                    let _compression_client_to_server = sup_algs
                        .compression_to_peer
                        .find(compression_algorithms_client_to_server.0)?;
                    let compression_algorithms_server_to_client = kexinit.name_list()?;
                    let _compression_server_to_client = sup_algs
                        .compression_from_peer
                        .find(compression_algorithms_server_to_client.0)?;

                    let _languages_client_to_server = kexinit.name_list()?;
                    let _languages_server_to_client = kexinit.name_list()?;
                    let first_kex_packet_follows = kexinit.bool()?;
                    if first_kex_packet_follows {
                        return Err(peer_error!("does not support guessed kex init packages"));
                    }

                    let kex_secret = (kex_algorithm.generate_secret)(&mut *self.rng);

                    self.packet_transport
                        .queue_packet(Packet::new_msg_kex_ecdh_init(&kex_secret.pubkey));

                    self.state = ClientState::DhKeyInit {
                        client_ident: mem::take(client_ident),
                        server_ident: mem::take(server_ident),
                        kex_secret: Some(kex_secret),
                        server_hostkey_algorithm,
                        encryption_client_to_server,
                        encryption_server_to_client,
                        client_kexinit: mem::take(client_kexinit),
                        server_kexinit: packet.payload,
                    };
                }
                ClientState::DhKeyInit {
                    client_ident,
                    server_ident,
                    kex_secret,
                    server_hostkey_algorithm,
                    encryption_client_to_server,
                    encryption_server_to_client,
                    client_kexinit,
                    server_kexinit,
                } => {
                    let mut dh = packet.payload_parser();

                    let packet_type = dh.u8()?;
                    if packet_type != numbers::SSH_MSG_KEX_ECDH_REPLY {
                        return Err(peer_error!(
                            "expected SSH_MSG_KEX_ECDH_REPLY, found {}",
                            numbers::packet_type_to_string(packet_type)
                        ));
                    }

                    if self.abort_for_dos {
                        return Err(peer_error!("early abort"));
                    }

                    let server_hostkey = dh.string()?;
                    let server_ephermal_key = dh.string()?;
                    let signature = dh.string()?;

                    let kex_secret = mem::take(kex_secret).unwrap();
                    let shared_secret = (kex_secret.exchange)(server_ephermal_key)?;

                    // The exchange hash serves as the session identifier.
                    let hash = crypto::key_exchange_hash(
                        client_ident,
                        server_ident,
                        client_kexinit,
                        server_kexinit,
                        server_hostkey,
                        &kex_secret.pubkey,
                        server_ephermal_key,
                        &shared_secret,
                    );

                    (server_hostkey_algorithm.verify)(
                        server_hostkey,
                        &hash,
                        &EncodedSshSignature(signature.to_vec()),
                    )?;

                    // eprintln!("client_public_key: {:x?}", kex_secret.pubkey);
                    // eprintln!("server_public_key: {:x?}", server_ephermal_key);
                    // eprintln!("shared_secret:     {:x?}", shared_secret);
                    // eprintln!("hash:              {:x?}", hash);

                    self.packet_transport.queue_packet(Packet {
                        payload: vec![numbers::SSH_MSG_NEWKEYS],
                    });
                    self.state = ClientState::NewKeys {
                        h: hash,
                        k: shared_secret,
                        encryption_client_to_server: *encryption_client_to_server,
                        encryption_server_to_client: *encryption_server_to_client,
                    };
                }
                ClientState::NewKeys {
                    h,
                    k,
                    encryption_client_to_server,
                    encryption_server_to_client,
                } => {
                    if packet.payload != [numbers::SSH_MSG_NEWKEYS] {
                        return Err(peer_error!("did not send SSH_MSG_NEWKEYS"));
                    }

                    self.packet_transport.set_key(
                        *h,
                        k,
                        *encryption_client_to_server,
                        *encryption_server_to_client,
                        false,
                    );

                    debug!("Requesting ssh-userauth service");
                    self.packet_transport
                        .queue_packet(Packet::new_msg_service_request(b"ssh-userauth"));

                    self.state = ClientState::ServiceRequest {
                        session_identifier: *h,
                    };
                }
                ClientState::ServiceRequest { session_identifier } => {
                    let mut accept = packet.payload_parser();
                    let packet_type = accept.u8()?;
                    if packet_type != numbers::SSH_MSG_SERVICE_ACCEPT {
                        return Err(peer_error!("did not accept service"));
                    }
                    let service = accept.utf8_string()?;
                    if service != "ssh-userauth" {
                        return Err(peer_error!("server accepted the wrong service: {service}"));
                    }

                    debug!("Connection has been opened successfully");
                    self.state = ClientState::Open {
                        session_identifier: *session_identifier,
                    };
                }
                ClientState::Open { .. } => {
                    self.plaintext_packets.push_back(packet);
                }
            }
        }
        Ok(())
    }

    pub fn next_msg_to_send(&mut self) -> Option<Msg> {
        self.packet_transport.next_msg_to_send()
    }

    pub fn next_plaintext_packet(&mut self) -> Option<Packet> {
        self.plaintext_packets.pop_front()
    }

    pub fn send_plaintext_packet(&mut self, packet: Packet) {
        self.packet_transport.queue_packet(packet);
    }

    pub fn is_open(&self) -> Option<[u8; 32]> {
        match self.state {
            ClientState::Open { session_identifier } => Some(session_identifier),
            _ => None,
        }
    }

    fn send_kexinit(&mut self, client_ident: Vec<u8>, server_ident: Vec<u8>) {
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

        self.packet_transport.queue_packet(Packet {
            payload: kexinit.clone(),
        });
        self.state = ClientState::KexInit {
            client_ident,
            server_ident,
            client_kexinit: kexinit,
        };
    }
}
