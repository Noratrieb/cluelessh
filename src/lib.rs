mod parse;

#[derive(Debug)]
pub enum SshError {
    /// The client did something wrong.
    /// The connection should be closed and a notice may be logged,
    /// but this does not require operator intervention.
    ClientError(String),
    /// Something went wrong on the server.
    /// The connection should be closed and an error should be logged.
    ServerError(eyre::Report),
}

pub type Result<T, E = SshError> = std::result::Result<T, E>;

impl From<eyre::Report> for SshError {
    fn from(value: eyre::Report) -> Self {
        Self::ServerError(value)
    }
}

macro_rules! client_error {
    ($($tt:tt)*) => {
        $crate::SshError::ClientError(::std::format!($($tt)*))
    };
}
use core::str;
use std::{io::Write, mem::take};

use client_error;
use ed25519_dalek::ed25519::signature::Signer;
use eyre::Context;
use parse::{MpInt, NameList, Parser, Writer};
use sha2::Digest;
use x25519_dalek::{EphemeralSecret, PublicKey};

// This is definitely who we are.
pub const SERVER_IDENTIFICATION: &[u8] = b"SSH-2.0-OpenSSH_9.7\r\n";

#[derive(Default)]
pub struct ServerConnection {
    state: ServerState,
    send_queue: Vec<Msg>,
}

enum ServerState {
    ProtoExchange {
        received: Vec<u8>,
    },
    KeyExchangeInit {
        client_packet: PacketParser,
        client_identification: Vec<u8>,
    },
    DhKeyInit {
        client_packet: PacketParser,
        client_identification: Vec<u8>,
        client_kexinit: Vec<u8>,
        server_kexinit: Vec<u8>,
    },
    NewKeys {
        client_packet: PacketParser,
    },
    ServiceRequest {},
}

impl Default for ServerState {
    fn default() -> Self {
        Self::ProtoExchange {
            received: Vec::new(),
        }
    }
}

impl ServerConnection {
    pub fn recv_bytes(&mut self, mut bytes: &[u8]) -> Result<()> {
        while let Some(consumed) = self.recv_bytes_step(bytes)? {
            bytes = &bytes[consumed..];
            if bytes.is_empty() {
                break;
            }
        }
        Ok(())
    }
    fn recv_bytes_step(&mut self, bytes: &[u8]) -> Result<Option<usize>> {
        let result = match &mut self.state {
            ServerState::ProtoExchange { received } => {
                // TODO: get rid of this allocation :(
                received.extend_from_slice(bytes);
                if received.windows(2).find(|win| win == b"\r\n").is_some() {
                    // TODO: care that its SSH 2.0 instead of anythin anything else
                    // The client will not send any more information than this until we respond, so discord the rest of the bytes.
                    let client_identification = received.to_owned();
                    self.queue_msg(MsgKind::ServerProtocolInfo);
                    self.state = ServerState::KeyExchangeInit {
                        client_packet: PacketParser::new(),
                        client_identification,
                    };
                }
                None
            }
            ServerState::KeyExchangeInit {
                client_packet: packet,
                client_identification,
            } => match packet.recv_bytes(bytes, ())? {
                Some((consumed, data)) => {
                    let kex = KeyExchangeInitPacket::parse(&data.payload)?;

                    let require_algorithm =
                        |expected: &'static str, list: NameList<'_>| -> Result<&'static str> {
                            if list.iter().any(|alg| alg == expected) {
                                Ok(expected)
                            } else {
                                Err(client_error!(
                                    "client does not supported algorithm {expected}"
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
                    self.queue_msg(MsgKind::Packet(Packet {
                        payload: server_kexinit_payload.clone(),
                    }));
                    self.state = ServerState::DhKeyInit {
                        client_packet: PacketParser::new(),
                        client_identification,
                        client_kexinit: data.payload,
                        server_kexinit: server_kexinit_payload,
                    };

                    Some(consumed)
                }
                None => None,
            },
            ServerState::DhKeyInit {
                client_packet: packet,
                client_identification,
                client_kexinit,
                server_kexinit,
            } => match packet.recv_bytes(bytes, ())? {
                Some((consumed, data)) => {
                    let dh = DhKeyExchangeInitPacket::parse(&data.payload)?;

                    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
                    let server_public_key = PublicKey::from(&secret); // f

                    let client_public_key = dh.e; // e

                    let shared_secret =
                        secret.diffie_hellman(&client_public_key.to_x25519_public_key()?); // k

                    let pub_hostkey = SshPublicKey {
                        format: b"ssh-ed25519",
                        data: PUB_HOSTKEY_BYTES,
                    };

                    let dump = std::fs::File::create("debug.bin").wrap_err("opening debug.bin")?;
                    let mut hash = sha2::Sha256::new();
                    let add_hash = |hash: &mut sha2::Sha256, bytes: &[u8]| {
                        hash.update(bytes);
                        (&dump).write_all(bytes).unwrap();
                    };
                    let hash_string = |hash: &mut sha2::Sha256, bytes: &[u8]| {
                        add_hash(hash, &u32::to_be_bytes(bytes.len() as u32));
                        add_hash(hash, bytes);
                    };
                    let hash_mpint = |hash: &mut sha2::Sha256, mut bytes: &[u8]| {
                        while bytes[0] == 0 {
                            bytes = &bytes[1..];
                        }
                        // If the first high bit is set, pad it with a zero.
                        let pad_zero = (bytes[0] & 0b10000000) > 1;
                        add_hash(
                            hash,
                            &u32::to_be_bytes((bytes.len() + (pad_zero as usize)) as u32),
                        );
                        if pad_zero {
                            add_hash(hash, &[0]);
                        }
                        add_hash(hash, bytes);
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

                    // While the RFC says that e and f are mpints, we need to *NOT* treat them as mpints here.
                    // Neither RFC4253 nor RFC8709 mention this.
                    hash_string(&mut hash, &client_public_key.0); // e
                    hash_string(&mut hash, server_public_key.as_bytes()); // f
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
                    self.queue_msg(MsgKind::Packet(Packet {
                        payload: packet.to_bytes(),
                    }));
                    self.state = ServerState::NewKeys {
                        client_packet: PacketParser::new(),
                    };

                    Some(consumed)
                }
                None => None,
            },
            ServerState::NewKeys { client_packet } => match client_packet.recv_bytes(bytes, ())? {
                Some((consumed, data)) => {
                    if data.payload != &[Packet::SSH_MSG_NEWKEYS] {
                        return Err(client_error!("did not send SSH_MSG_NEWKEYS"));
                    }

                    self.queue_msg(MsgKind::Packet(Packet {
                        payload: vec![Packet::SSH_MSG_NEWKEYS],
                    }));
                    self.state = ServerState::ServiceRequest {};

                    Some(consumed)
                }
                None => None,
            },
            ServerState::ServiceRequest {} => None,
        };
        Ok(result)
    }

    pub fn next_message_to_send(&mut self) -> Option<Msg> {
        self.send_queue.pop()
    }

    fn queue_msg(&mut self, msg: MsgKind) {
        self.send_queue.push(Msg(msg));
    }
}

#[derive(Debug)]
pub struct Msg(MsgKind);

#[derive(Debug, PartialEq)]
enum MsgKind {
    ServerProtocolInfo,
    Packet(Packet),
}

impl Msg {
    // TODO: MAKE THIS ZERO ALLOC AAAAAA
    pub fn to_bytes_inefficient(self) -> Vec<u8> {
        match self.0 {
            MsgKind::ServerProtocolInfo => SERVER_IDENTIFICATION.to_vec(),
            MsgKind::Packet(v) => v.to_bytes(),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Packet {
    payload: Vec<u8>,
}
impl Packet {
    const SSH_MSG_KEXINIT: u8 = 20;
    const SSH_MSG_NEWKEYS: u8 = 21;
    const SSH_MSG_KEXDH_INIT: u8 = 30;
    const SSH_MSG_KEXDH_REPLY: u8 = 31;

    fn from_raw(bytes: &[u8]) -> Result<Self> {
        let Some(padding_length) = bytes.get(0) else {
            return Err(client_error!("empty packet"));
        };
        // TODO: mac?
        let Some(payload_len) = (bytes.len() - 1).checked_sub(*padding_length as usize) else {
            return Err(client_error!("packet padding longer than packet"));
        };
        let payload = &bytes[1..][..payload_len];

        if (bytes.len() + 4) % 8 != 0 {
            return Err(client_error!("full packet length must be multiple of 8"));
        }

        Ok(Self {
            payload: payload.to_vec(),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut new = Vec::new();

        let min_full_length = self.payload.len() + 4 + 1;

        // The padding must give a factor of 8.
        let min_padding_len = (min_full_length.next_multiple_of(8) - min_full_length) as u8;
        // > There MUST be at least four bytes of padding.
        // So let's satisfy this by just adding 8. We can always properly randomize it later if desired.
        let padding_len = min_padding_len + 8;

        let packet_len = self.payload.len() + (padding_len as usize) + 1;
        new.extend_from_slice(&u32::to_be_bytes(packet_len as u32));
        new.extend_from_slice(&[padding_len]);
        new.extend_from_slice(&self.payload);
        new.extend(std::iter::repeat(0).take(padding_len as usize));
        // mac...

        assert!((4 + 1 + self.payload.len() + (padding_len as usize)) % 8 == 0);
        assert!(new.len() % 8 == 0);

        new
    }
}

#[derive(Debug)]
struct KeyExchangeInitPacket<'a> {
    cookie: [u8; 16],
    kex_algorithms: NameList<'a>,
    server_host_key_algorithms: NameList<'a>,
    encryption_algorithms_client_to_server: NameList<'a>,
    encryption_algorithms_server_to_client: NameList<'a>,
    mac_algorithms_client_to_server: NameList<'a>,
    mac_algorithms_server_to_client: NameList<'a>,
    compression_algorithms_client_to_server: NameList<'a>,
    compression_algorithms_server_to_client: NameList<'a>,
    languages_client_to_server: NameList<'a>,
    languages_server_to_client: NameList<'a>,
    first_kex_packet_follows: bool,
}

impl<'a> KeyExchangeInitPacket<'a> {
    fn parse(payload: &'a [u8]) -> Result<KeyExchangeInitPacket<'_>> {
        let mut c = Parser::new(payload);

        let kind = c.u8()?;
        if kind != Packet::SSH_MSG_KEXINIT {
            return Err(client_error!(
                "expected SSH_MSG_KEXINIT packet, found {kind}"
            ));
        }
        let cookie = c.read_array::<16>()?;
        let kex_algorithms = c.name_list()?;
        let server_host_key_algorithms = c.name_list()?;
        let encryption_algorithms_client_to_server = c.name_list()?;
        let encryption_algorithms_server_to_client = c.name_list()?;
        let mac_algorithms_client_to_server = c.name_list()?;
        let mac_algorithms_server_to_client = c.name_list()?;
        let compression_algorithms_client_to_server = c.name_list()?;
        let compression_algorithms_server_to_client = c.name_list()?;

        let languages_client_to_server = c.name_list()?;
        let languages_server_to_client = c.name_list()?;

        let first_kex_packet_follows = c.bool()?;

        let _ = c.u32()?; // Reserved.

        Ok(Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Writer::new();

        data.u8(Packet::SSH_MSG_KEXINIT);
        data.write(&self.cookie);
        data.name_list(self.kex_algorithms);
        data.name_list(self.server_host_key_algorithms);
        data.name_list(self.encryption_algorithms_client_to_server);
        data.name_list(self.encryption_algorithms_server_to_client);
        data.name_list(self.mac_algorithms_client_to_server);
        data.name_list(self.mac_algorithms_server_to_client);
        data.name_list(self.compression_algorithms_client_to_server);
        data.name_list(self.compression_algorithms_server_to_client);
        data.name_list(self.languages_client_to_server);
        data.name_list(self.languages_server_to_client);
        data.u8(self.first_kex_packet_follows as u8);
        data.u32(0); // Reserved.

        data.finish()
    }
}

#[derive(Debug)]
struct DhKeyExchangeInitPacket<'a> {
    e: MpInt<'a>,
}
impl<'a> DhKeyExchangeInitPacket<'a> {
    fn parse(payload: &'a [u8]) -> Result<DhKeyExchangeInitPacket<'_>> {
        let mut c = Parser::new(payload);

        let kind = c.u8()?;
        if kind != Packet::SSH_MSG_KEXDH_INIT {
            return Err(client_error!(
                "expected SSH_MSG_KEXDH_INIT packet, found {kind}"
            ));
        }
        let e = c.mpint()?;
        Ok(Self { e })
    }
}

#[derive(Debug)]
struct SshPublicKey<'a> {
    format: &'a [u8],
    data: &'a [u8],
}
impl SshPublicKey<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Writer::new();
        data.u32((4 + self.format.len() + 4 + self.data.len()) as u32);
        // ed25519-specific!
        // <https://datatracker.ietf.org/doc/html/rfc8709#section-4>
        data.string(&self.format);
        data.string(&self.data);
        data.finish()
    }
}
#[derive(Debug)]
struct SshSignature<'a> {
    format: &'a [u8],
    data: &'a [u8],
}

#[derive(Debug)]
struct DhKeyExchangeInitReplyPacket<'a> {
    pubkey: SshPublicKey<'a>,
    f: MpInt<'a>,
    signature: SshSignature<'a>,
}
impl<'a> DhKeyExchangeInitReplyPacket<'a> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Writer::new();

        data.u8(Packet::SSH_MSG_KEXDH_REPLY);
        data.write(&self.pubkey.to_bytes());
        data.mpint(self.f);

        data.u32((4 + self.signature.format.len() + 4 + self.signature.data.len()) as u32);
        // <https://datatracker.ietf.org/doc/html/rfc8709#section-6>
        data.string(&self.signature.format);
        data.string(&self.signature.data);
        data.finish()
    }
}

struct PacketParser {
    // The length of the packet.
    packet_length: Option<usize>,
    // Before we've read the length fully, this stores the length.
    // Afterwards, this stores the packet data *after* the length.
    data: Vec<u8>,
}
impl PacketParser {
    fn new() -> Self {
        Self {
            packet_length: None,
            data: Vec::new(),
        }
    }
    fn recv_bytes(&mut self, bytes: &[u8], mac: ()) -> Result<Option<(usize, Packet)>> {
        let Some((consumed, data)) = self.recv_bytes_inner(bytes, mac)? else {
            return Ok(None);
        };
        Ok(Some((consumed, Packet::from_raw(&data)?)))
    }
    fn recv_bytes_inner(&mut self, mut bytes: &[u8], _mac: ()) -> Result<Option<(usize, Vec<u8>)>> {
        let mut consumed = 0;
        let packet_length = match self.packet_length {
            Some(packet_length) => packet_length,
            None => {
                let remaining_len = std::cmp::min(bytes.len(), 4 - self.data.len());
                // Try to read the bytes of the length.
                self.data.extend_from_slice(&bytes[..remaining_len]);
                if self.data.len() < 4 {
                    // Not enough data yet :(.
                    return Ok(None);
                }

                let packet_length = u32::from_be_bytes(self.data.as_slice().try_into().unwrap());
                let packet_length = packet_length.try_into().unwrap();
                self.data.clear();

                self.packet_length = Some(packet_length);

                // We have the data.
                bytes = &bytes[remaining_len..];
                consumed += remaining_len;

                packet_length
            }
        };

        let remaining_len = std::cmp::min(bytes.len(), packet_length - self.data.len());
        self.data.extend_from_slice(&bytes[..remaining_len]);
        consumed += remaining_len;

        if self.data.len() == packet_length {
            // We have the full data.
            Ok(Some((consumed, std::mem::take(&mut self.data))))
        } else {
            Ok(None)
        }
    }
    #[cfg(test)]
    fn test_recv_bytes(&mut self, bytes: &[u8], mac: ()) -> Option<(usize, Vec<u8>)> {
        self.recv_bytes_inner(bytes, mac).unwrap()
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

#[cfg(test)]
mod tests {
    use crate::{MsgKind, PacketParser, ServerConnection};

    trait OptionExt {
        fn unwrap_none(self);
    }
    impl<T> OptionExt for Option<T> {
        #[track_caller]
        fn unwrap_none(self) {
            assert!(self.is_none());
        }
    }

    #[test]
    fn protocol_exchange() {
        let mut con = ServerConnection::default();
        con.recv_bytes(b"SSH-2.0-OpenSSH_9.7\r\n").unwrap();
        let msg = con.next_message_to_send().unwrap();
        assert_eq!(msg.0, MsgKind::ServerProtocolInfo);
    }

    #[test]
    fn protocol_exchange_slow_client() {
        let mut con = ServerConnection::default();
        con.recv_bytes(b"SSH-2.0-").unwrap();
        con.recv_bytes(b"OpenSSH_9.7\r\n").unwrap();
        let msg = con.next_message_to_send().unwrap();
        assert_eq!(msg.0, MsgKind::ServerProtocolInfo);
    }

    #[test]
    fn packet_parser() {
        let mut p = PacketParser::new();
        p.test_recv_bytes(&2_u32.to_be_bytes(), ()).unwrap_none();
        p.test_recv_bytes(&[1], ()).unwrap_none();
        let (consumed, data) = p.test_recv_bytes(&[2], ()).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(data, &[1, 2]);
    }

    #[test]
    fn packet_parser_split_len() {
        let mut p = PacketParser::new();
        let len = &2_u32.to_be_bytes();
        p.test_recv_bytes(&len[0..2], ()).unwrap_none();
        p.test_recv_bytes(&len[2..4], ()).unwrap_none();

        p.test_recv_bytes(&[1], ()).unwrap_none();
        let (consumed, data) = p.test_recv_bytes(&[2], ()).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(data, &[1, 2]);
    }

    #[test]
    fn packet_parser_all() {
        let mut p = PacketParser::new();
        let (consumed, data) = p.test_recv_bytes(&[0, 0, 0, 2, 1, 2], ()).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(data, &[1, 2]);
    }
}
