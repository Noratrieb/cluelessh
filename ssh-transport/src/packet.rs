mod ctors;

use std::collections::VecDeque;

use crate::client_error;
use crate::crypto::{EncryptionAlgorithm, Keys, Plaintext, Session};
use crate::parse::{NameList, Parser, Writer};
use crate::Result;

/// Frames the byte stream into packets.
pub(crate) struct PacketTransport {
    keys: Box<dyn Keys>,
    recv_next_packet: PacketParser,

    recv_packets: VecDeque<Packet>,
    recv_next_seq_nr: u64,

    send_packets: VecDeque<Msg>,
    send_next_seq_nr: u64,
}

#[derive(Debug)]
pub struct Msg(pub(crate) MsgKind);

#[derive(Debug, PartialEq)]
pub(crate) enum MsgKind {
    ServerProtocolInfo,
    PlaintextPacket(Packet),
    EncryptedPacket(EncryptedPacket),
}

impl Msg {
    pub fn to_bytes(self) -> Vec<u8> {
        match self.0 {
            MsgKind::ServerProtocolInfo => crate::SERVER_IDENTIFICATION.to_vec(),
            MsgKind::PlaintextPacket(v) => v.to_bytes(true, Packet::DEFAULT_BLOCK_SIZE),
            MsgKind::EncryptedPacket(v) => v.into_bytes(),
        }
    }
}

impl PacketTransport {
    pub(crate) fn new() -> Self {
        PacketTransport {
            keys: Box::new(Plaintext),
            recv_next_packet: PacketParser::new(),

            recv_packets: VecDeque::new(),
            recv_next_seq_nr: 0,

            send_packets: VecDeque::new(),
            send_next_seq_nr: 0,
        }
    }
    pub(crate) fn recv_bytes(&mut self, mut bytes: &[u8]) -> Result<()> {
        while let Some(consumed) = self.recv_bytes_step(bytes)? {
            bytes = &bytes[consumed..];
            if bytes.is_empty() {
                break;
            }
        }
        Ok(())
    }

    fn recv_bytes_step(&mut self, bytes: &[u8]) -> Result<Option<usize>> {
        // TODO: This might not work if we buffer two packets where one changes keys in between?

        let result =
            self.recv_next_packet
                .recv_bytes(bytes, &mut *self.keys, self.recv_next_seq_nr)?;
        if let Some((consumed, result)) = result {
            self.recv_packets.push_back(result);
            self.recv_next_seq_nr = self.recv_next_seq_nr.wrapping_add(1);
            self.recv_next_packet = PacketParser::new();
            return Ok(Some(consumed));
        }

        Ok(None)
    }

    pub(crate) fn queue_packet(&mut self, packet: Packet) {
        let seq_nr = self.send_next_seq_nr;
        self.send_next_seq_nr = self.send_next_seq_nr.wrapping_add(1);
        let msg = self.keys.encrypt_packet_to_msg(packet, seq_nr);
        self.queue_send_msg(msg);
    }

    pub(crate) fn queue_send_protocol_info(&mut self) {
        self.queue_send_msg(Msg(MsgKind::ServerProtocolInfo));
    }

    pub(crate) fn recv_next_packet(&mut self) -> Option<Packet> {
        self.recv_packets.pop_front()
    }

    // Private: Make sure all sending goes through variant-specific functions here.
    fn queue_send_msg(&mut self, msg: Msg) {
        self.send_packets.push_back(msg);
    }
    pub(crate) fn next_msg_to_send(&mut self) -> Option<Msg> {
        self.send_packets.pop_front()
    }

    pub(crate) fn set_key(
        &mut self,
        h: [u8; 32],
        k: &[u8],
        encryption_client_to_server: EncryptionAlgorithm,
        encryption_server_to_client: EncryptionAlgorithm,
    ) {
        if let Err(()) = self.keys.rekey(
            h,
            k,
            encryption_client_to_server,
            encryption_server_to_client,
        ) {
            self.keys = Box::new(Session::new(
                h,
                k,
                encryption_client_to_server,
                encryption_server_to_client,
            ));
        }
    }
}

/*
packet teminology used throughout this crate:

length | padding_length | payload | random padding | MAC

-------------------------------------------------------- "full"
         ----------------------------------------------- "rest"
                          -------                        "payload"
         -----------------------------------------       "content"
--------------------------------------------------       "authenticated"

^^^^^^ encrypted using K1
                                                     ^^^^ plaintext
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ encrypted using K2
*/

/// A plaintext SSH packet payload.
#[derive(Debug, PartialEq)]
pub struct Packet {
    pub payload: Vec<u8>,
}
impl Packet {
    // -----
    // Transport layer protocol:

    // 1 to 19 Transport layer generic (e.g., disconnect, ignore, debug, etc.)
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;

    // 20 to 29 Algorithm negotiation
    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;

    // 30 to 49 Key exchange method specific (numbers can be reused for different authentication methods)
    pub const SSH_MSG_KEXDH_INIT: u8 = 30;
    pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30; // Same number
    pub const SSH_MSG_KEXDH_REPLY: u8 = 31;
    pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

    // -----
    // User authentication protocol:

    // 50 to 59   User authentication generic
    pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
    pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
    pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;

    //  60 to 79   User authentication method specific (numbers can be reused for different authentication methods)

    // -----
    // Connection protocol:

    // 80 to 89   Connection protocol generic
    pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
    pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
    pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

    // 90 to 127  Channel related messages
    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
    pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
    pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
    pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
    pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
    pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

    pub const DEFAULT_BLOCK_SIZE: u8 = 8;

    pub(crate) fn from_full(bytes: &[u8]) -> Result<Self> {
        let Some(padding_length) = bytes.first() else {
            return Err(client_error!("empty packet"));
        };

        let Some(payload_len) = (bytes.len() - 1).checked_sub(*padding_length as usize) else {
            return Err(client_error!("packet padding longer than packet"));
        };
        let payload = &bytes[1..][..payload_len];

        // TODO: handle the annoying decryption special case differnt where its +0 instead of +4
        //if (bytes.len() + 4) % 8 != 0 {
        //    return Err(client_error!("full packet length must be multiple of 8: {}", bytes.len()));
        //}

        Ok(Self {
            payload: payload.to_vec(),
        })
    }

    pub(crate) fn to_bytes(&self, respect_len_for_padding: bool, block_size: u8) -> Vec<u8> {
        assert!(block_size.is_power_of_two());

        let let_bytes = if respect_len_for_padding { 4 } else { 0 };

        // <https://datatracker.ietf.org/doc/html/rfc4253#section-6>
        let min_full_length = self.payload.len() + let_bytes + 1;

        // The padding must give a factor of block_size.
        let min_padding_len =
            (min_full_length.next_multiple_of(block_size as usize) - min_full_length) as u8;
        // > There MUST be at least four bytes of padding.
        let padding_len = if min_padding_len < 4 {
            min_padding_len + block_size
        } else {
            min_padding_len
        };

        let packet_len = self.payload.len() + (padding_len as usize) + 1;

        let mut new = Vec::new();
        new.extend_from_slice(&u32::to_be_bytes(packet_len as u32));
        new.extend_from_slice(&[padding_len]);
        new.extend_from_slice(&self.payload);
        new.extend(std::iter::repeat(0).take(padding_len as usize));

        assert!((let_bytes + 1 + self.payload.len() + (padding_len as usize)) % 8 == 0);

        new
    }

    pub fn payload_parser(&self) -> Parser<'_> {
        Parser::new(&self.payload)
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct EncryptedPacket {
    data: Vec<u8>,
}
impl EncryptedPacket {
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.data
    }
    pub(crate) fn from_encrypted_full_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }
}

#[derive(Debug)]
pub(crate) struct KeyExchangeInitPacket<'a> {
    pub(crate) cookie: [u8; 16],
    pub(crate) kex_algorithms: NameList<'a>,
    pub(crate) server_host_key_algorithms: NameList<'a>,
    pub(crate) encryption_algorithms_client_to_server: NameList<'a>,
    pub(crate) encryption_algorithms_server_to_client: NameList<'a>,
    pub(crate) mac_algorithms_client_to_server: NameList<'a>,
    pub(crate) mac_algorithms_server_to_client: NameList<'a>,
    pub(crate) compression_algorithms_client_to_server: NameList<'a>,
    pub(crate) compression_algorithms_server_to_client: NameList<'a>,
    pub(crate) languages_client_to_server: NameList<'a>,
    pub(crate) languages_server_to_client: NameList<'a>,
    pub(crate) first_kex_packet_follows: bool,
}

impl<'a> KeyExchangeInitPacket<'a> {
    pub(crate) fn parse(payload: &'a [u8]) -> Result<KeyExchangeInitPacket<'_>> {
        let mut c = Parser::new(payload);

        let kind = c.u8()?;
        if kind != Packet::SSH_MSG_KEXINIT {
            return Err(client_error!(
                "expected SSH_MSG_KEXINIT packet, found {kind}"
            ));
        }
        let cookie = c.array::<16>()?;
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

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
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
pub(crate) struct KeyExchangeEcDhInitPacket<'a> {
    pub(crate) qc: &'a [u8],
}
impl<'a> KeyExchangeEcDhInitPacket<'a> {
    pub(crate) fn parse(payload: &'a [u8]) -> Result<KeyExchangeEcDhInitPacket<'_>> {
        let mut c = Parser::new(payload);

        let kind = c.u8()?;
        if kind != Packet::SSH_MSG_KEX_ECDH_INIT {
            return Err(client_error!(
                "expected SSH_MSG_KEXDH_INIT packet, found {kind}"
            ));
        }
        let qc = c.string()?;
        Ok(Self { qc })
    }
}

#[derive(Debug)]
pub(crate) struct SshPublicKey<'a> {
    pub(crate) format: &'a [u8],
    pub(crate) data: &'a [u8],
}
impl SshPublicKey<'_> {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut data = Writer::new();
        data.u32((4 + self.format.len() + 4 + self.data.len()) as u32);
        // ed25519-specific!
        // <https://datatracker.ietf.org/doc/html/rfc8709#section-4>
        data.string(self.format);
        data.string(self.data);
        data.finish()
    }
}
#[derive(Debug)]
pub(crate) struct SshSignature<'a> {
    pub(crate) format: &'a [u8],
    pub(crate) data: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct DhKeyExchangeInitReplyPacket<'a> {
    /// K_S
    pub(crate) public_host_key: SshPublicKey<'a>,
    /// Q_S
    pub(crate) ephemeral_public_key: &'a [u8],
    pub(crate) signature: SshSignature<'a>,
}
impl<'a> DhKeyExchangeInitReplyPacket<'a> {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut data = Writer::new();

        data.u8(Packet::SSH_MSG_KEX_ECDH_REPLY);
        data.write(&self.public_host_key.to_bytes());
        data.string(self.ephemeral_public_key);

        data.u32((4 + self.signature.format.len() + 4 + self.signature.data.len()) as u32);
        // <https://datatracker.ietf.org/doc/html/rfc8709#section-6>
        data.string(self.signature.format);
        data.string(self.signature.data);
        data.finish()
    }
}

pub(crate) struct RawPacket {
    pub mac_len: usize,
    pub raw: Vec<u8>,
}
impl RawPacket {
    pub(crate) fn rest(&self) -> &[u8] {
        &self.raw[4..]
    }
    pub(crate) fn full_packet(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn content_mut(&mut self) -> &mut [u8] {
        let mac_start = self.raw.len() - self.mac_len;
        &mut self.raw[4..mac_start]
    }
}

struct PacketParser {
    // The length of the packet.
    packet_length: Option<usize>,
    // The raw data *encrypted*, including the length.
    raw_data: Vec<u8>,
}
impl PacketParser {
    fn new() -> Self {
        Self {
            packet_length: None,
            raw_data: Vec::new(),
        }
    }
    fn recv_bytes(
        &mut self,
        bytes: &[u8],
        decrytor: &mut dyn Keys,
        next_seq_nr: u64,
    ) -> Result<Option<(usize, Packet)>> {
        let Some((consumed, data)) = self.recv_bytes_inner(bytes, decrytor, next_seq_nr)? else {
            return Ok(None);
        };
        let packet = decrytor.decrypt_packet(data, next_seq_nr)?;
        Ok(Some((consumed, packet)))
    }
    fn recv_bytes_inner(
        &mut self,
        mut bytes: &[u8],
        keys: &mut dyn Keys,
        next_seq_nr: u64,
    ) -> Result<Option<(usize, RawPacket)>> {
        let mut consumed = 0;
        let packet_length = match self.packet_length {
            Some(packet_length) => {
                assert!(self.raw_data.len() >= 4);
                packet_length
            }
            None => {
                let remaining_len = std::cmp::min(bytes.len(), 4 - self.raw_data.len());
                // Try to read the bytes of the length.
                self.raw_data.extend_from_slice(&bytes[..remaining_len]);
                if self.raw_data.len() < 4 {
                    // Not enough data yet :(.
                    return Ok(None);
                }

                let mut len_to_decrypt = [0_u8; 4];
                len_to_decrypt.copy_from_slice(self.raw_data.as_slice());

                keys.decrypt_len(&mut len_to_decrypt, next_seq_nr);
                let packet_length = u32::from_be_bytes(len_to_decrypt);
                let packet_length: usize = packet_length.try_into().unwrap();

                let packet_length = packet_length + keys.additional_mac_len();

                self.packet_length = Some(packet_length);

                // We have the data.
                bytes = &bytes[remaining_len..];
                consumed += remaining_len;

                packet_length
            }
        };

        // <https://datatracker.ietf.org/doc/html/rfc4253#section-6.1>
        // All implementations MUST be able to process packets with an
        // uncompressed payload length of 32768 bytes or less and a total packet
        // size of 35000 bytes or less (including 'packet_length',
        // 'padding_length', 'payload', 'random padding', and 'mac').
        // Implementations SHOULD support longer packets, where they might be needed.
        if packet_length > 500_000 {
            return Err(client_error!(
                "packet too large (>500_000): {packet_length}"
            ));
        }

        let remaining_len = std::cmp::min(bytes.len(), packet_length - (self.raw_data.len() - 4));
        self.raw_data.extend_from_slice(&bytes[..remaining_len]);
        consumed += remaining_len;

        if (self.raw_data.len() - 4) == packet_length {
            // We have the full data.
            Ok(Some((
                consumed,
                RawPacket {
                    raw: std::mem::take(&mut self.raw_data),
                    mac_len: keys.additional_mac_len(),
                },
            )))
        } else {
            Ok(None)
        }
    }
    #[cfg(test)]
    fn test_recv_bytes(&mut self, bytes: &[u8]) -> Option<(usize, RawPacket)> {
        self.recv_bytes_inner(bytes, &mut Plaintext, 0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::PacketParser;

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
    fn packet_parser() {
        let mut p = PacketParser::new();
        p.test_recv_bytes(&2_u32.to_be_bytes()).unwrap_none();
        p.test_recv_bytes(&[1]).unwrap_none();
        let (consumed, data) = p.test_recv_bytes(&[2]).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(data.rest(), &[1, 2]);
    }

    #[test]
    fn packet_parser_split_len() {
        let mut p = PacketParser::new();
        let len = &2_u32.to_be_bytes();
        p.test_recv_bytes(&len[0..2]).unwrap_none();
        p.test_recv_bytes(&len[2..4]).unwrap_none();

        p.test_recv_bytes(&[1]).unwrap_none();
        let (consumed, data) = p.test_recv_bytes(&[2]).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(data.rest(), &[1, 2]);
    }

    #[test]
    fn packet_parser_all() {
        let mut p = PacketParser::new();
        let (consumed, data) = p.test_recv_bytes(&[0, 0, 0, 2, 1, 2]).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(data.rest(), &[1, 2]);
    }
}
