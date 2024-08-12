mod keys;
pub mod packet;
pub mod parse;

use core::str;
use std::{collections::VecDeque, mem::take};

use ed25519_dalek::ed25519::signature::Signer;
use packet::{
    DhKeyExchangeInitPacket, DhKeyExchangeInitReplyPacket, KeyExchangeInitPacket, Packet,
    PacketTransport, SshPublicKey, SshSignature,
};
use parse::{MpInt, NameList, Parser, Writer};
use rand::RngCore;
use sha2::Digest;
use tracing::{debug, info, trace};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub use packet::Msg;

#[derive(Debug)]
pub enum SshStatus {
    /// The client has sent a disconnect request, close the connection.
    /// This is not an error.
    Disconnect,
    /// The client did something wrong.
    /// The connection should be closed and a notice may be logged,
    /// but this does not require operator intervention.
    ClientError(String),
    /// Something went wrong on the server.
    /// The connection should be closed and an error should be logged.
    // TODO: does this ever happen?
    ServerError(eyre::Report),
}

pub type Result<T, E = SshStatus> = std::result::Result<T, E>;

impl From<eyre::Report> for SshStatus {
    fn from(value: eyre::Report) -> Self {
        Self::ServerError(value)
    }
}

// This is definitely who we are.
pub const SERVER_IDENTIFICATION: &[u8] = b"SSH-2.0-OpenSSH_9.7\r\n";

pub struct ServerConnection {
    state: ServerState,
    packet_transport: PacketTransport,
    rng: Box<dyn SshRng + Send + Sync>,

    plaintext_packets: VecDeque<Packet>,
}

enum ServerState {
    ProtoExchange {
        received: Vec<u8>,
    },
    KeyExchangeInit {
        client_identification: Vec<u8>,
    },
    DhKeyInit {
        client_identification: Vec<u8>,
        client_kexinit: Vec<u8>,
        server_kexinit: Vec<u8>,
    },
    NewKeys {
        h: [u8; 32],
        k: [u8; 32],
    },
    ServiceRequest,
    Open,
}

pub trait SshRng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
struct SshRngRandAdapter<'a>(&'a mut dyn SshRng);
impl rand::CryptoRng for SshRngRandAdapter<'_> {}
impl rand::RngCore for SshRngRandAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub struct ThreadRngRand;
impl SshRng for ThreadRngRand {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::thread_rng().fill_bytes(dest);
    }
}

impl ServerConnection {
    pub fn new(rng: impl SshRng + Send + Sync + 'static) -> Self {
        Self {
            state: ServerState::ProtoExchange {
                received: Vec::new(),
            },
            packet_transport: PacketTransport::new(),
            rng: Box::new(rng),

            plaintext_packets: VecDeque::new(),
        }
    }
}

impl ServerConnection {
    pub fn recv_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if let ServerState::ProtoExchange { received } = &mut self.state {
            received.extend_from_slice(bytes);
            if received.windows(2).any(|win| win == b"\r\n") {
                // TODO: care that its SSH 2.0 instead of anythin anything else
                // The client will not send any more information than this until we respond, so discord the rest of the bytes.
                let client_identification = received.to_owned();
                self.packet_transport.queue_send_protocol_info();
                self.state = ServerState::KeyExchangeInit {
                    client_identification,
                };
            }
            // This means that we must be called at least twice, which is fine I think.
            return Ok(());
        }

        self.packet_transport.recv_bytes(bytes)?;

        while let Some(packet) = self.packet_transport.recv_next_packet() {
            trace!(packet_type = ?packet.payload.get(0), packet_len = ?packet.payload.len(), "Received packet");

            // Handle some packets ignoring the state.
            match packet.payload.get(0).copied() {
                Some(Packet::SSH_MSG_DISCONNECT) => {
                    // <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>
                    let mut disconnect = Parser::new(&packet.payload[1..]);
                    let reason = disconnect.u32()?;
                    let description = disconnect.utf8_string()?;
                    let _language_tag = disconnect.utf8_string()?;

                    info!(?reason, ?description, "Client disconnecting");

                    return Ok(());
                }
                _ => {}
            }

            match &mut self.state {
                ServerState::ProtoExchange { .. } => unreachable!("handled above"),
                ServerState::KeyExchangeInit {
                    client_identification,
                } => {
                    let kex = KeyExchangeInitPacket::parse(&packet.payload)?;

                    let require_algorithm = |expected: &'static str,
                                             list: NameList<'_>|
                     -> Result<&'static str> {
                        if list.iter().any(|alg| alg == expected) {
                            Ok(expected)
                        } else {
                            Err(client_error!(
                                    "client does not supported algorithm {expected}. supported: {list:?}",
                                ))
                        }
                    };

                    let key_algorithm = require_algorithm("curve25519-sha256", kex.kex_algorithms)?;
                    let server_host_key_algorithm =
                        require_algorithm("ssh-ed25519", kex.server_host_key_algorithms)?;
                    let encryption_algorithm_client_to_server = require_algorithm(
                        "chacha20-poly1305@openssh.com",
                        kex.encryption_algorithms_client_to_server,
                    )?;
                    let encryption_algorithm_server_to_client = require_algorithm(
                        "chacha20-poly1305@openssh.com",
                        kex.encryption_algorithms_server_to_client,
                    )?;
                    let mac_algorithm_client_to_server =
                        require_algorithm("hmac-sha2-256", kex.mac_algorithms_client_to_server)?;
                    let mac_algorithm_server_to_client =
                        require_algorithm("hmac-sha2-256", kex.mac_algorithms_server_to_client)?;
                    let compression_algorithm_client_to_server =
                        require_algorithm("none", kex.compression_algorithms_client_to_server)?;
                    let compression_algorithm_server_to_client =
                        require_algorithm("none", kex.compression_algorithms_server_to_client)?;

                    let _ = kex.languages_client_to_server;
                    let _ = kex.languages_server_to_client;

                    if kex.first_kex_packet_follows {
                        return Err(client_error!(
                            "the client wants to send a guessed packet, that's annoying :("
                        ));
                    }

                    let server_kexinit = KeyExchangeInitPacket {
                        cookie: [0; 16],
                        kex_algorithms: NameList::one(key_algorithm),
                        server_host_key_algorithms: NameList::one(server_host_key_algorithm),
                        encryption_algorithms_client_to_server: NameList::one(
                            encryption_algorithm_client_to_server,
                        ),
                        encryption_algorithms_server_to_client: NameList::one(
                            encryption_algorithm_server_to_client,
                        ),
                        mac_algorithms_client_to_server: NameList::one(
                            mac_algorithm_client_to_server,
                        ),
                        mac_algorithms_server_to_client: NameList::one(
                            mac_algorithm_server_to_client,
                        ),
                        compression_algorithms_client_to_server: NameList::one(
                            compression_algorithm_client_to_server,
                        ),
                        compression_algorithms_server_to_client: NameList::one(
                            compression_algorithm_server_to_client,
                        ),
                        languages_client_to_server: NameList::none(),
                        languages_server_to_client: NameList::none(),
                        first_kex_packet_follows: false,
                    };

                    let client_identification = take(client_identification);
                    let server_kexinit_payload = server_kexinit.to_bytes();
                    self.packet_transport.queue_packet(Packet {
                        payload: server_kexinit_payload.clone(),
                    });
                    self.state = ServerState::DhKeyInit {
                        client_identification,
                        client_kexinit: packet.payload,
                        server_kexinit: server_kexinit_payload,
                    };
                }
                ServerState::DhKeyInit {
                    client_identification,
                    client_kexinit,
                    server_kexinit,
                } => {
                    // TODO: move to keys.rs
                    let dh = DhKeyExchangeInitPacket::parse(&packet.payload)?;

                    let secret =
                        EphemeralSecret::random_from_rng(SshRngRandAdapter(&mut *self.rng));
                    let server_public_key = PublicKey::from(&secret); // Q_S

                    let client_public_key = dh.e; // Q_C

                    let shared_secret =
                        secret.diffie_hellman(&client_public_key.as_x25519_public_key()?); // K

                    let pub_hostkey = SshPublicKey {
                        format: b"ssh-ed25519",
                        data: PUB_HOSTKEY_BYTES,
                    };

                    let mut hash = sha2::Sha256::new();
                    let add_hash = |hash: &mut sha2::Sha256, bytes: &[u8]| {
                        hash.update(bytes);
                    };
                    let hash_string = |hash: &mut sha2::Sha256, bytes: &[u8]| {
                        add_hash(hash, &u32::to_be_bytes(bytes.len() as u32));
                        add_hash(hash, bytes);
                    };
                    let hash_mpint = |hash: &mut sha2::Sha256, bytes: &[u8]| {
                        keys::encode_mpint_for_hash(bytes, |data| add_hash(hash, data));
                    };

                    hash_string(
                        &mut hash,
                        &client_identification[..(client_identification.len() - 2)],
                    ); // V_C
                    hash_string(
                        &mut hash,
                        &SERVER_IDENTIFICATION[..(SERVER_IDENTIFICATION.len() - 2)],
                    ); // V_S
                    hash_string(&mut hash, client_kexinit); // I_C
                    hash_string(&mut hash, server_kexinit); // I_S
                    add_hash(&mut hash, &pub_hostkey.to_bytes()); // K_S
                                                                  // For normal DH as in RFC4253, e and f are mpints.
                                                                  // But for ECDH as defined in RFC5656, Q_C and Q_S are strings.
                                                                  // <https://datatracker.ietf.org/doc/html/rfc5656#section-4>
                    hash_string(&mut hash, client_public_key.0); // Q_C
                    hash_string(&mut hash, server_public_key.as_bytes()); // Q_S
                    hash_mpint(&mut hash, shared_secret.as_bytes()); // K

                    let hash = hash.finalize();

                    let host_priv_key = ed25519_dalek::SigningKey::from_bytes(PRIVKEY_BYTES);
                    assert_eq!(PUB_HOSTKEY_BYTES, host_priv_key.verifying_key().as_bytes());

                    let signature = host_priv_key.sign(&hash);

                    // eprintln!("client_public_key: {:x?}", client_public_key.0);
                    // eprintln!("server_public_key: {:x?}", server_public_key.as_bytes());
                    // eprintln!("shared_secret:     {:x?}", shared_secret.as_bytes());
                    // eprintln!("hash:              {:x?}", hash);

                    let packet = DhKeyExchangeInitReplyPacket {
                        pubkey: pub_hostkey,
                        f: MpInt(server_public_key.as_bytes()),
                        signature: SshSignature {
                            format: b"ssh-ed25519",
                            data: &signature.to_bytes(),
                        },
                    };
                    self.packet_transport.queue_packet(Packet {
                        payload: packet.to_bytes(),
                    });
                    self.state = ServerState::NewKeys {
                        h: hash.into(),
                        k: shared_secret.to_bytes(),
                    };
                }
                ServerState::NewKeys { h, k } => {
                    if packet.payload != [Packet::SSH_MSG_NEWKEYS] {
                        return Err(client_error!("did not send SSH_MSG_NEWKEYS"));
                    }

                    let (h, k) = (*h, *k);

                    self.packet_transport.queue_packet(Packet {
                        payload: vec![Packet::SSH_MSG_NEWKEYS],
                    });
                    self.state = ServerState::ServiceRequest {};
                    self.packet_transport.set_key(h, k);
                }
                ServerState::ServiceRequest => {
                    // TODO: this should probably move out of here? unsure.
                    if packet.payload.first() != Some(&Packet::SSH_MSG_SERVICE_REQUEST) {
                        return Err(client_error!("did not send SSH_MSG_SERVICE_REQUEST"));
                    }
                    let mut p = Parser::new(&packet.payload[1..]);
                    let service = p.utf8_string()?;
                    debug!(?service, "Client requesting service");

                    if service != "ssh-userauth" {
                        return Err(client_error!("only supports ssh-userauth"));
                    }

                    self.packet_transport.queue_packet(Packet {
                        payload: {
                            let mut writer = Writer::new();
                            writer.u8(Packet::SSH_MSG_SERVICE_ACCEPT);
                            writer.string(service.as_bytes());
                            writer.finish()
                        },
                    });
                    self.state = ServerState::Open;
                }
                ServerState::Open => {
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
}

// hardcoded test keys. lol.
const _PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOk5zfpvwNc3MztTTpE90zLI1Ref4AwwRVdSFyJLGbj2 testkey";
/// Manually extracted, even worse, <https://superuser.com/questions/1477472/openssh-public-key-file-format>, help
const PUB_HOSTKEY_BYTES: &[u8; 32] = &[
    0xe9, 0x39, 0xcd, 0xfa, 0x6f, 0xc0, 0xd7, 0x37, 0x33, 0x3b, 0x53, 0x4e, 0x91, 0x3d, 0xd3, 0x32,
    0xc8, 0xd5, 0x17, 0x9f, 0xe0, 0x0c, 0x30, 0x45, 0x57, 0x52, 0x17, 0x22, 0x4b, 0x19, 0xb8, 0xf6,
];
const _PRIVKEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDpOc36b8DXNzM7U06RPdMyyNUXn+AMMEVXUhciSxm49gAAAJDpgLSk6YC0
pAAAAAtzc2gtZWQyNTUxOQAAACDpOc36b8DXNzM7U06RPdMyyNUXn+AMMEVXUhciSxm49g
AAAECSeskxuEtJrr9L7ZkbpogXC5pKRNVHx1ueMX2h1XUnmek5zfpvwNc3MztTTpE90zLI
1Ref4AwwRVdSFyJLGbj2AAAAB3Rlc3RrZXkBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
";
/// Manually extracted from the key using <https://peterlyons.com/problog/2017/12/openssh-ed25519-private-key-file-format/>, probably wrong
const PRIVKEY_BYTES: &[u8; 32] = &[
    0x92, 0x7a, 0xc9, 0x31, 0xb8, 0x4b, 0x49, 0xae, 0xbf, 0x4b, 0xed, 0x99, 0x1b, 0xa6, 0x88, 0x17,
    0x0b, 0x9a, 0x4a, 0x44, 0xd5, 0x47, 0xc7, 0x5b, 0x9e, 0x31, 0x7d, 0xa1, 0xd5, 0x75, 0x27, 0x99,
];

#[macro_export]
macro_rules! client_error {
    ($($tt:tt)*) => {
        $crate::SshStatus::ClientError(::std::format!($($tt)*))
    };
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{packet::MsgKind, ServerConnection, SshRng};

    struct NoRng;
    impl SshRng for NoRng {
        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!()
        }
    }

    struct HardcodedRng(Vec<u8>);
    impl SshRng for HardcodedRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&self.0[..dest.len()]);
            self.0.splice(0..dest.len(), []);
        }
    }

    #[test]
    fn protocol_exchange() {
        let mut con = ServerConnection::new(NoRng);
        con.recv_bytes(b"SSH-2.0-OpenSSH_9.7\r\n").unwrap();
        let msg = con.next_msg_to_send().unwrap();
        assert_eq!(msg.0, MsgKind::ServerProtocolInfo);
    }

    #[test]
    fn protocol_exchange_slow_client() {
        let mut con = ServerConnection::new(NoRng);
        con.recv_bytes(b"SSH-2.0-").unwrap();
        con.recv_bytes(b"OpenSSH_9.7\r\n").unwrap();
        let msg = con.next_msg_to_send().unwrap();
        assert_eq!(msg.0, MsgKind::ServerProtocolInfo);
    }

    #[test]
    fn handshake() {
        #[rustfmt::skip]
        let rng = vec![
            0x14, 0xa2, 0x04, 0xa5, 0x4b, 0x2f, 0x5f, 0xa7, 0xff, 0x53, 0x13, 0x67, 0x57, 0x67, 0xbc, 0x55,
            0x3f, 0xc0, 0x6c, 0x0d, 0x07, 0x8f, 0xe2, 0x75, 0x95, 0x18, 0x4b, 0xd2, 0xcb, 0xd0, 0x64, 0x06,
        ];

        struct Part {
            client: &'static [u8],
            server: &'static [u8],
        }

        // Extracted from a real OpenSSH client using this server (with hardcoded creds) using Wireshark.
        let conversation = [
            Part {
                client: &hex!("5353482d322e302d4f70656e5353485f392e370d0a"),
                server: &hex!("5353482d322e302d4f70656e5353485f392e370d0a"),
            },
            // KEX Init
            Part {
                client: &hex!(
                    "000005fc0714b76523360210e3119b17bb2ea2301b0800000131736e747275703736317832353531392d736861353132406f70656e7373682e636f6d2c637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6578742d696e666f2d632c6b65782d7374726963742d632d763030406f70656e7373682e636f6d000001cf7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c736b2d7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c736b2d65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c736b2d7373682d65643235353139406f70656e7373682e636f6d2c736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d2c7273612d736861322d3531322c7273612d736861322d3235360000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000000000000000000000000000000000000000"
                ),
                server: &hex!(
                    "000000bc05140000000000000000000000000000000000000011637572766532353531392d7368613235360000000b7373682d656432353531390000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000000d686d61632d736861322d3235360000000d686d61632d736861322d323536000000046e6f6e65000000046e6f6e65000000000000000000000000000000000000"
                ),
            },
            // ECDH KEX Init
            Part {
                client: &hex!(
                    "0000002c061e000000203c37b81a887449b168cd9128d8b8bf034f17ac6374f814fca2f4583ec60b9b05000000000000"
                ),
                server: &hex!(
                    "000000bc081f000000330000000b7373682d6564323535313900000020e939cdfa6fc0d737333b534e913dd332c8d5179fe00c3045575217224b19b8f6000000203b92eb7008cc13056bc9f198049f75d5832f3650969dfcccd80841431b350160000000530000000b7373682d6564323535313900000040c9ae31b043d2a964265ffa7672e99a136053cc29fa17a0e432a62c742bb187aee16527e299b601593ebf5cb255d39f2edbafc32236c17adbfcf6f01527827b060000000000000000"
                ),
            },
            // New Keys
            Part {
                client: &hex!("0000000c0a1500000000000000000000"),
                server: &hex!("0000000c0a1500000000000000000000"),
            },
            // Service Request (encrypted)
            Part {
                client: &hex!("c514026ef814ab7e1d5854df6af106eda203e10935ab887151e16d85024713c5e1b51435072e599eab5662e0"),
                server: &hex!("76eecb34af5ba93308499b41fc3c9bfc7dad89208fb26b0ae04baaed4515a788c45f81930eabc45f0f42c142"),
            },
        ];

        let mut con = ServerConnection::new(HardcodedRng(rng));
        for part in conversation {
            con.recv_bytes(&part.client).unwrap();
            eprintln!("client: {:x?}", part.client);
            let bytes = con.next_msg_to_send().unwrap().to_bytes();
            if part.server != bytes {
                panic!(
                    "expected != found\nexpected: {:x?}\nfound:    {:x?}",
                    part.server, bytes
                );
            }
        }
    }
}
