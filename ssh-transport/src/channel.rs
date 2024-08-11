use std::collections::VecDeque;
use tracing::{debug, warn};

use crate::client_error;
use crate::packet::Packet;
use crate::parse::{Parser, Writer};
use crate::Result;

pub(crate) struct ServerChannelsState {
    packets_to_send: VecDeque<Packet>,
    channels: Vec<SessionChannel>,

    channel_updates: VecDeque<ChannelUpdate>,
}

struct SessionChannel {
    /// Whether our side has closed this channel.
    we_closed: bool,
    peer_channel: u32,
    has_pty: bool,
    has_shell: bool,
    sent_bytes: Vec<u8>,
}

pub struct ChannelUpdate {
    pub channel: u32,
    pub kind: ChannelUpdateKind,
}

pub enum ChannelUpdateKind {
    ChannelData(Vec<u8>),
}

impl ServerChannelsState {
    pub(crate) fn new() -> Self {
        ServerChannelsState {
            packets_to_send: VecDeque::new(),
            channels: Vec::new(),
            channel_updates: VecDeque::new(),
        }
    }

    pub(crate) fn on_packet(&mut self, packet_type: u8, mut payload: Parser<'_>) -> Result<()> {
        match packet_type {
            Packet::SSH_MSG_CHANNEL_OPEN => {
                // <https://datatracker.ietf.org/doc/html/rfc4254#section-5.1>
                let channel_type = payload.utf8_string()?;
                let sender_channel = payload.u32()?;
                let initial_window_size = payload.u32()?;
                let max_packet_size = payload.u32()?;

                debug!(?channel_type, ?sender_channel, "Opening channel");

                match channel_type {
                    "session" => {
                        let our_number = self.channels.len() as u32;

                        self.packets_to_send
                            .push_back(Packet::new_msg_channel_open_confirmation(
                                our_number,
                                sender_channel,
                                initial_window_size,
                                max_packet_size,
                            ));

                        self.channels.push(SessionChannel {
                            we_closed: false,
                            peer_channel: sender_channel,
                            has_pty: false,
                            has_shell: false,
                            sent_bytes: Vec::new(),
                        });

                        debug!(?channel_type, ?our_number, "Successfully opened channel");
                    }
                    _ => {
                        self.packets_to_send
                            .push_back(Packet::new_msg_channel_open_failure(
                                sender_channel,
                                3, // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
                                b"unknown channel type",
                                b"",
                            ));
                    }
                }
            }
            Packet::SSH_MSG_CHANNEL_DATA => {
                let our_channel = payload.u32()?;
                let data = payload.string()?;

                let channel = self.channel(our_channel)?;
                channel.recv_bytes(data);

                let peer = channel.peer_channel;
                // echo :3
                self.packets_to_send
                    .push_back(Packet::new_msg_channel_data(peer, data));

                if data.contains(&0x03 /*EOF, Ctrl-C*/) {
                    debug!(?our_channel, "Received EOF, closing channel");
                    // <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>
                    self.packets_to_send
                        .push_back(Packet::new_msg_channel_close(peer));

                    let channel = self.channel(our_channel)?;
                    channel.we_closed = true;
                }
            }
            Packet::SSH_MSG_CHANNEL_CLOSE => {
                // <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>
                let our_channel = payload.u32()?;
                let channel = self.channel(our_channel)?;
                if !channel.we_closed {
                    let close = Packet::new_msg_channel_close(channel.peer_channel);
                    self.packets_to_send.push_back(close);
                }

                self.channels.remove(our_channel as usize);

                debug!("Channel has been closed");
            }
            Packet::SSH_MSG_CHANNEL_REQUEST => {
                let our_channel = payload.u32()?;
                let request_type = payload.utf8_string()?;
                let want_reply = payload.bool()?;

                debug!(?our_channel, ?request_type, "Got channel request");

                let channel = self.channel(our_channel)?;
                let peer_channel = channel.peer_channel;

                match request_type {
                    "pty-req" => {
                        let term = payload.utf8_string()?;
                        let width_chars = payload.u32()?;
                        let height_rows = payload.u32()?;
                        let _width_px = payload.u32()?;
                        let _height_px = payload.u32()?;
                        let _term_modes = payload.string()?;

                        debug!(
                            ?our_channel,
                            ?term,
                            ?width_chars,
                            ?height_rows,
                            "Trying to open a terminal"
                        );

                        // Faithfully allocate the PTY.
                        channel.has_pty = true;

                        if want_reply {
                            self.send_channel_success(peer_channel);
                        }
                    }
                    "shell" => {
                        if !channel.has_pty {
                            self.send_channel_failure(peer_channel);
                        }

                        // Sure! (reborrow)
                        let channel = self.channel(our_channel)?;
                        channel.has_shell = true;

                        debug!(?our_channel, "Opening shell");

                        if want_reply {
                            self.send_channel_success(peer_channel);
                        }
                    }
                    "signal" => {
                        debug!(?our_channel, "Received signal");
                        // Ignore signals, something we can do.
                    }
                    _ => {
                        warn!(?request_type, ?our_channel, "Unknown channel request");
                        self.send_channel_failure(peer_channel);
                    }
                }
            }
            _ => {
                todo!("{packet_type}");
            }
        }

        Ok(())
    }

    pub(crate) fn packets_to_send(&mut self) -> impl Iterator<Item = Packet> + '_ {
        self.packets_to_send.drain(..)
    }

    pub(crate) fn channel_updates(&mut self) -> impl Iterator<Item = ChannelUpdate> + '_ {
        self.channel_updates.drain(..)
    }

    fn send_channel_success(&mut self, recipient_channel: u32) {
        self.packets_to_send
            .push_back(Packet::new_msg_channel_success(recipient_channel));
    }

    fn send_channel_failure(&mut self, recipient_channel: u32) {
        self.packets_to_send
            .push_back(Packet::new_msg_channel_failure(recipient_channel));
    }

    fn channel(&mut self, number: u32) -> Result<&mut SessionChannel> {
        self.channels
            .get_mut(number as usize)
            .ok_or_else(|| client_error!("unknown channel: {number}"))
    }
}

impl SessionChannel {
    fn recv_bytes(&mut self, bytes: &[u8]) {
        self.sent_bytes.extend_from_slice(bytes);
    }
}
