use std::collections::VecDeque;

use cluelessh_format::{numbers, Reader};
use cluelessh_transport::packet::PacketParser;
use eyre::{ensure, eyre, Result};

#[derive(Debug)]
pub struct Packet {
    payload: Vec<u8>,
}

impl Packet {
    pub fn packet_type(&self) -> u8 {
        self.payload[4]
    }

    pub fn payload_reader(&self) -> Reader {
        Reader::new(&&self.payload[5..])
    }

    pub fn all_payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn from_body(body: &[u8]) -> Self {
        let len = body.len() as u32;
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::to_be_bytes(len));
        payload.extend_from_slice(&body);
        Self { payload }
    }
}

pub struct PacketTransport {
    parser: PacketParser,
    packets: VecDeque<Packet>,
}

impl PacketTransport {
    pub fn new() -> Self {
        Self {
            parser: PacketParser::new(),
            packets: VecDeque::new(),
        }
    }

    pub fn packets(&mut self) -> impl IntoIterator<Item = Packet> {
        std::mem::take(&mut self.packets)
    }

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
        let result = self
            .parser
            .recv_plaintext_bytes(bytes)
            .map_err(|_| eyre!("invalid packet"))?;

        if let Some((consumed, result)) = result {
            ensure!(result.len() > (4 + 1), "Empty packet");
            let packet = Packet { payload: result };
            if packet.packet_type() != numbers::SSH_FXP_INIT
                && packet.packet_type() != numbers::SSH_FXP_VERSION
            {
                ensure!(
                    packet.all_payload().len() > (4 + 1 + 4),
                    "Missing request ID"
                );
            }
            self.packets.push_back(packet);
            self.parser = PacketParser::new();
            return Ok(Some(consumed));
        }

        Ok(None)
    }
}
