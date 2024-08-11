use std::collections::VecDeque;

use crate::client_error;
use crate::keys::{Keys, Plaintext, Session};
use crate::parse::{MpInt, NameList, Parser, Writer};
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
            MsgKind::PlaintextPacket(v) => v.to_bytes(true),
            MsgKind::EncryptedPacket(v) => v.to_bytes(),
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

    pub(crate) fn set_key(&mut self, h: [u8; 32], k: [u8; 32]) {
        if let Err(()) = self.keys.rekey(h, k) {
            self.keys = Box::new(Session::new(h, k));
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

#[derive(Debug, PartialEq)]
pub(crate) struct Packet {
    pub(crate) payload: Vec<u8>,
}
impl Packet {
    pub(crate) const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub(crate) const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub(crate) const SSH_MSG_KEXINIT: u8 = 20;
    pub(crate) const SSH_MSG_NEWKEYS: u8 = 21;
    pub(crate) const SSH_MSG_KEXDH_INIT: u8 = 30;
    pub(crate) const SSH_MSG_KEXDH_REPLY: u8 = 31;

    pub(crate) fn from_raw(bytes: &[u8]) -> Result<Self> {
        let Some(padding_length) = bytes.get(0) else {
            return Err(client_error!("empty packet"));
        };
        // TODO: mac?
        let Some(payload_len) = (bytes.len() - 1).checked_sub(*padding_length as usize) else {
            return Err(client_error!("packet padding longer than packet"));
        };
        let payload = &bytes[1..][..payload_len];

        // TODO: this fails with OpenSSH client... why?
        //if (bytes.len() + 4) % 8 != 0 {
        //    return Err(client_error!("full packet length must be multiple of 8: {}", bytes.len()));
        //}

        Ok(Self {
            payload: payload.to_vec(),
        })
    }

    pub(crate) fn to_bytes(&self, respect_len_for_padding: bool) -> Vec<u8> {
        let let_bytes = if respect_len_for_padding { 4 } else { 0 };

        // <https://datatracker.ietf.org/doc/html/rfc4253#section-6>
        let min_full_length = self.payload.len() + let_bytes + 1;

        // The padding must give a factor of 8.
        let min_padding_len = (min_full_length.next_multiple_of(8) - min_full_length) as u8;
        // > There MUST be at least four bytes of padding.
        let padding_len = if min_padding_len < 4 {
            min_padding_len + 8
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
}

#[derive(Debug, PartialEq)]
pub(crate) struct EncryptedPacket {
    data: Vec<u8>,
}
impl EncryptedPacket {
    pub(crate) fn to_bytes(self) -> Vec<u8> {
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
pub(crate) struct DhKeyExchangeInitPacket<'a> {
    pub(crate) e: MpInt<'a>,
}
impl<'a> DhKeyExchangeInitPacket<'a> {
    pub(crate) fn parse(payload: &'a [u8]) -> Result<DhKeyExchangeInitPacket<'_>> {
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
        data.string(&self.format);
        data.string(&self.data);
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
    pub(crate) pubkey: SshPublicKey<'a>,
    pub(crate) f: MpInt<'a>,
    pub(crate) signature: SshSignature<'a>,
}
impl<'a> DhKeyExchangeInitReplyPacket<'a> {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
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

pub(crate) struct RawPacket {
    pub len: usize,
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
                    len: packet_length,
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
