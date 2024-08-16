use std::cmp;
use std::collections::{HashMap, VecDeque};
use tracing::{debug, info, trace, warn};

use ssh_transport::packet::Packet;
use ssh_transport::Result;
use ssh_transport::{numbers, peer_error};

/// A channel number (on our side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelNumber(pub u32);

impl std::fmt::Display for ChannelNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

pub struct ChannelsState {
    packets_to_send: VecDeque<Packet>,
    channel_updates: VecDeque<ChannelUpdate>,

    channels: HashMap<ChannelNumber, Channel>,
    next_channel_id: ChannelNumber,

    is_server: bool,
}

struct Channel {
    /// Whether our side has closed this channel.
    we_closed: bool,
    /// The channel number for the other side.
    peer_channel: u32,
    /// The current max window size of our peer, controls how many bytes we can still send.
    peer_window_size: u32,
    /// The max packet size of the peer.
    // We need to split our packets if the user requests more.
    peer_max_packet_size: u32,

    /// For validation only.
    our_window_size: u32,
    /// For validation only.
    our_max_packet_size: u32,
    /// By how much we want to increase the window when it gets small.
    our_window_size_increase_step: u32,

    /// Queued data that we want to send, but have not been able to because of the window limits.
    /// Whenever we get more window space, we will send this data.
    queued_data: Vec<u8>,
}

/// An update from a channel.
/// The receiver-equivalent of [`ChannelOperation`].
#[derive(Debug)]
pub struct ChannelUpdate {
    pub number: ChannelNumber,
    pub kind: ChannelUpdateKind,
}
#[derive(Debug)]
pub enum ChannelUpdateKind {
    Open(ChannelOpen),
    Request(ChannelRequest),
    Data { data: Vec<u8> },
    ExtendedData { code: u32, data: Vec<u8> },
    Eof,
    Closed,
}
#[derive(Debug)]
pub enum ChannelOpen {
    Session,
}
#[derive(Debug)]
pub enum ChannelRequest {
    PtyReq {
        want_reply: bool,

        term: String,
        width_chars: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
        term_modes: Vec<u8>,
    },
    Shell {
        want_reply: bool,
    },
    Exec {
        want_reply: bool,

        command: Vec<u8>,
    },
    Env {
        want_reply: bool,

        name: String,
        value: Vec<u8>,
    },
    ExitStatus {
        status: u32,
    },
}

impl ChannelNumber {
    #[must_use]
    pub fn construct_op(self, kind: ChannelOperationKind) -> ChannelOperation {
        ChannelOperation { number: self, kind }
    }
}

/// An operation to do on a channel.
/// The sender-equivalent of [`ChannelUpdate`].
pub struct ChannelOperation {
    pub number: ChannelNumber,
    pub kind: ChannelOperationKind,
}

pub enum ChannelOperationKind {
    Success,
    Failure,
    Data(Vec<u8>),
    Request(ChannelRequest),
    Eof,
    Close,
}

impl ChannelsState {
    pub fn new(is_server: bool) -> Self {
        ChannelsState {
            packets_to_send: VecDeque::new(),
            channels: HashMap::new(),
            channel_updates: VecDeque::new(),
            next_channel_id: ChannelNumber(0),

            is_server,
        }
    }

    pub fn recv_packet(&mut self, packet: Packet) -> Result<()> {
        // TODO: window

        let mut packet = packet.payload_parser();
        let packet_type = packet.u8()?;
        match packet_type {
            numbers::SSH_MSG_GLOBAL_REQUEST => {
                let request_name = packet.utf8_string()?;
                let want_reply = packet.bool()?;
                debug!(%request_name, %want_reply, "Received global request");

                self.packets_to_send
                    .push_back(Packet::new_msg_request_failure());
            }
            numbers::SSH_MSG_CHANNEL_OPEN => {
                // <https://datatracker.ietf.org/doc/html/rfc4254#section-5.1>
                let channel_type = packet.utf8_string()?;
                let sender_channel = packet.u32()?;
                let initial_window_size = packet.u32()?;
                let max_packet_size = packet.u32()?;

                debug!(%channel_type, %sender_channel, "Opening channel");

                let update_message = match channel_type {
                    "session" => ChannelOpen::Session,
                    _ => {
                        self.packets_to_send
                            .push_back(Packet::new_msg_channel_open_failure(
                                sender_channel,
                                numbers::SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                                b"unknown channel type",
                                b"",
                            ));
                        return Ok(());
                    }
                };

                let our_number = self.next_channel_id;
                self.next_channel_id =
                    ChannelNumber(self.next_channel_id.0.checked_add(1).ok_or_else(|| {
                        peer_error!("created too many channels, overflowed the counter")
                    })?);

                self.packets_to_send
                    .push_back(Packet::new_msg_channel_open_confirmation(
                        sender_channel,
                        our_number.0,
                        initial_window_size,
                        max_packet_size,
                    ));

                self.channels.insert(
                    our_number,
                    Channel {
                        we_closed: false,
                        peer_channel: sender_channel,
                        peer_max_packet_size: max_packet_size,
                        peer_window_size: initial_window_size,
                        our_max_packet_size: max_packet_size,
                        our_window_size: initial_window_size,
                        our_window_size_increase_step: initial_window_size,

                        queued_data: Vec::new(),
                    },
                );

                self.channel_updates.push_back(ChannelUpdate {
                    number: our_number,
                    kind: ChannelUpdateKind::Open(update_message),
                });

                debug!(%channel_type, %our_number, "Successfully opened channel");
            }
            numbers::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                let our_channel = packet.u32()?;
                let our_channel = self.validate_channel(our_channel)?;
                let bytes_to_add = packet.u32()?;

                let channel = self.channel(our_channel)?;
                channel.peer_window_size = channel
                    .peer_window_size
                    .checked_add(bytes_to_add)
                    .ok_or_else(|| peer_error!("window size larger than 2^32"))?;

                if !channel.queued_data.is_empty() {
                    let limit =
                        cmp::min(channel.queued_data.len(), channel.peer_window_size as usize);
                    let data_to_send = channel.queued_data.splice(..limit, []).collect::<Vec<_>>();
                    self.send_data(our_channel, &data_to_send);
                }
            }
            numbers::SSH_MSG_CHANNEL_DATA => {
                let our_channel = packet.u32()?;
                let our_channel = self.validate_channel(our_channel)?;
                let data = packet.string()?;

                let channel = self.channel(our_channel)?;
                channel.our_window_size = channel
                    .our_window_size
                    .checked_sub(data.len() as u32)
                    .ok_or_else(|| {
                        peer_error!(
                            "sent more data than the window allows: {} while the window is {}",
                            data.len(),
                            channel.our_window_size
                        )
                    })?;
                if channel.our_max_packet_size < (data.len() as u32) {
                    return Err(peer_error!(
                        "data bigger than allowed packet size: {} while the max packet size is {}",
                        data.len(),
                        channel.our_max_packet_size
                    ));
                }

                trace!(channel = %our_channel, window = %channel.our_window_size, "Remaining window on our side");

                // We probably want to make this user-controllable in the future.
                if channel.our_window_size < 1000 {
                    let peer = channel.peer_channel;
                    let bytes_to_add = channel.our_window_size_increase_step;
                    channel.our_window_size += bytes_to_add;
                    self.packets_to_send
                        .push_back(Packet::new_msg_channel_window_adjust(peer, bytes_to_add))
                }

                self.channel_updates.push_back(ChannelUpdate {
                    number: our_channel,
                    kind: ChannelUpdateKind::Data {
                        data: data.to_owned(),
                    },
                });
            }
            numbers::SSH_MSG_CHANNEL_EOF => {
                // <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>
                let our_channel = packet.u32()?;
                let our_channel = self.validate_channel(our_channel)?;

                self.channel_updates.push_back(ChannelUpdate {
                    number: our_channel,
                    kind: ChannelUpdateKind::Eof,
                });
            }
            numbers::SSH_MSG_CHANNEL_CLOSE => {
                // <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>
                let our_channel = packet.u32()?;
                let our_channel = self.validate_channel(our_channel)?;
                let channel = self.channel(our_channel)?;
                if !channel.we_closed {
                    info!("closeing here");
                    let close = Packet::new_msg_channel_close(channel.peer_channel);
                    self.packets_to_send.push_back(close);
                }

                self.channels.remove(&our_channel);

                self.channel_updates.push_back(ChannelUpdate {
                    number: our_channel,
                    kind: ChannelUpdateKind::Closed,
                });

                debug!("Channel has been closed");
            }
            numbers::SSH_MSG_CHANNEL_REQUEST => {
                let our_channel = packet.u32()?;
                let our_channel = self.validate_channel(our_channel)?;
                let request_type = packet.utf8_string()?;
                let want_reply = packet.bool()?;

                debug!(channel = %our_channel, %request_type, "Got channel request");

                let channel = self.channel(our_channel)?;
                let peer_channel = channel.peer_channel;

                let channel_request = match request_type {
                    "pty-req" => {
                        let term = packet.utf8_string()?;
                        let width_chars = packet.u32()?;
                        let height_rows = packet.u32()?;
                        let width_px = packet.u32()?;
                        let height_px = packet.u32()?;
                        let term_modes = packet.string()?;

                        debug!(
                            channel = %our_channel,
                            %term,
                            %width_chars,
                            %height_rows,
                            "Trying to open a terminal"
                        );

                        ChannelRequest::PtyReq {
                            want_reply,
                            term: term.to_owned(),
                            width_chars,
                            height_rows,
                            width_px,
                            height_px,
                            term_modes: term_modes.to_owned(),
                        }
                    }
                    "shell" => {
                        info!(channel = %our_channel, "Opening shell");
                        ChannelRequest::Shell { want_reply }
                    }
                    "exec" => {
                        let command = packet.string()?;
                        info!(channel = %our_channel, command = %String::from_utf8_lossy(command), "Executing command");
                        ChannelRequest::Exec {
                            want_reply,
                            command: command.to_owned(),
                        }
                    }
                    "env" => {
                        let name = packet.utf8_string()?;
                        let value = packet.string()?;

                        info!(channel = %our_channel, %name, value = %String::from_utf8_lossy(value), "Setting environment variable");

                        ChannelRequest::Env {
                            want_reply,
                            name: name.to_owned(),
                            value: value.to_owned(),
                        }
                    }
                    "signal" => {
                        debug!(channel = %our_channel, "Received signal");
                        // Ignore signals, something we can do.
                        return Ok(());
                    }
                    _ => {
                        warn!(%request_type, channel = %our_channel, "Unknown channel request");
                        self.send_channel_failure(peer_channel);
                        return Ok(());
                    }
                };

                self.channel_updates.push_back(ChannelUpdate {
                    number: our_channel,
                    kind: ChannelUpdateKind::Request(channel_request),
                })
            }
            _ => {
                todo!(
                    "unsupported packet: {} ({packet_type})",
                    numbers::packet_type_to_string(packet_type)
                );
            }
        }

        Ok(())
    }

    pub fn packets_to_send(&mut self) -> impl Iterator<Item = Packet> + '_ {
        self.packets_to_send.drain(..)
    }

    pub fn next_channel_update(&mut self) -> Option<ChannelUpdate> {
        self.channel_updates.pop_front()
    }

    /// Executes an operation on the channel.
    ///
    /// # Panics
    /// This will panic when the channel has already been closed.
    pub fn do_operation(&mut self, op: ChannelOperation) {
        op.trace();

        let Ok(channel) = self.channel(op.number) else {
            debug!(number = %op.number, "Dropping operation as channel does not exist, probably because it has been closed");
            return;
        };
        let peer = channel.peer_channel;

        if channel.we_closed {
            debug!(number = %op.number, "Dropping operation as channel has been closed already");
            return;
        }

        match op.kind {
            ChannelOperationKind::Success => self.send_channel_success(peer),
            ChannelOperationKind::Failure => self.send_channel_failure(peer),
            ChannelOperationKind::Data(data) => {
                self.send_data(op.number, &data);
            }
            ChannelOperationKind::Request(req) => {
                let packet = match req {
                    ChannelRequest::PtyReq { .. } => todo!("pty-req"),
                    ChannelRequest::Shell { .. } => todo!("shell"),
                    ChannelRequest::Exec { .. } => todo!("exec"),
                    ChannelRequest::Env { .. } => todo!("env"),
                    ChannelRequest::ExitStatus { status } => {
                        Packet::new_msg_channel_request_exit_status(
                            peer,
                            b"exit-status",
                            false,
                            status,
                        )
                    }
                };
                self.packets_to_send.push_back(packet);
            }
            ChannelOperationKind::Eof => {
                self.packets_to_send
                    .push_back(Packet::new_msg_channel_eof(peer));
            }
            ChannelOperationKind::Close => {
                // <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>
                self.packets_to_send
                    .push_back(Packet::new_msg_channel_close(peer));

                let channel = self.channel(op.number).unwrap();
                channel.we_closed = true;
            }
        }
    }

    fn send_data(&mut self, channel_number: ChannelNumber, data: &[u8]) {
        let channel = self.channel(channel_number).unwrap();

        let mut chunks = data.chunks(channel.peer_max_packet_size as usize);

        while let Some(data) = chunks.next() {
            let channel = self.channel(channel_number).unwrap();
            let remaining_window_space_after =
                channel.peer_window_size.checked_sub(data.len() as u32);
            match remaining_window_space_after {
                None => {
                    let rest = channel.peer_window_size;
                    let (to_send, to_keep) = data.split_at(rest as usize);

                    if !to_send.is_empty() {
                        // Send everything we can, which empties the window.
                        channel.peer_window_size -= rest;
                        assert_eq!(channel.peer_window_size, 0);
                        self.send_data_packet(channel_number, to_send);
                    }

                    // It's over, we have exhausted all window space.
                    // Queue the rest of the bytes.
                    let channel = self.channel(channel_number).unwrap();
                    channel.queued_data.extend_from_slice(to_keep);
                    for data in chunks {
                        channel.queued_data.extend_from_slice(data);
                    }
                    debug!(channel = %channel_number, queue_len = %channel.queued_data.len(), "Exhausted window space, queueing the rest of the data");
                    return;
                }
                Some(space) => channel.peer_window_size = space,
            }
            trace!(channel = %channel_number, window = %channel.peer_window_size, "Remaining window on their side");

            self.send_data_packet(channel_number, data);
        }
    }

    /// Send a single data packet.
    /// The caller needs to ensure the windowing and packet size requirements are upheld.
    fn send_data_packet(&mut self, channel_number: ChannelNumber, data: &[u8]) {
        assert!(!data.is_empty(), "Trying to send empty data packet");

        trace!(%channel_number, amount = %data.len(), "Sending channel data");
        let channel = self.channel(channel_number).unwrap();
        let peer = channel.peer_channel;
        assert!(channel.peer_max_packet_size >= data.len() as u32);
        self.packets_to_send
            .push_back(Packet::new_msg_channel_data(peer, data));
    }

    fn send_channel_success(&mut self, recipient_channel: u32) {
        self.packets_to_send
            .push_back(Packet::new_msg_channel_success(recipient_channel));
    }

    fn send_channel_failure(&mut self, recipient_channel: u32) {
        self.packets_to_send
            .push_back(Packet::new_msg_channel_failure(recipient_channel));
    }

    fn validate_channel(&self, number: u32) -> Result<ChannelNumber> {
        if !self.channels.contains_key(&ChannelNumber(number)) {
            return Err(peer_error!("unknown channel: {number}"));
        }
        Ok(ChannelNumber(number))
    }

    fn channel(&mut self, number: ChannelNumber) -> Result<&mut Channel> {
        self.channels
            .get_mut(&number)
            .ok_or_else(|| peer_error!("unknown channel: {number:?}"))
    }
}

impl ChannelOperation {
    /// Logs the attempted operation.
    fn trace(&self) {
        let kind = match &self.kind {
            ChannelOperationKind::Success => "success",
            ChannelOperationKind::Failure => "failure",
            ChannelOperationKind::Data(_) => "data",
            ChannelOperationKind::Request(req) => match req {
                ChannelRequest::PtyReq { .. } => "pty-req",
                ChannelRequest::Shell { .. } => "shell",
                ChannelRequest::Exec { .. } => "exec",
                ChannelRequest::Env { .. } => "env",
                ChannelRequest::ExitStatus { .. } => "exit-status",
            },
            ChannelOperationKind::Eof => "eof",
            ChannelOperationKind::Close => "close",
        };
        trace!(number = %self.number, %kind, "Attempt channel operation")
    }
}

#[cfg(test)]
mod tests {
    use ssh_transport::{numbers, packet::Packet};

    use crate::{ChannelNumber, ChannelOperation, ChannelOperationKind, ChannelsState};

    /// If a test fails, add this to the test to get logs.
    #[allow(dead_code)]
    fn init_test_log() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }

    #[track_caller]
    fn assert_response_types(state: &mut ChannelsState, types: &[u8]) {
        let response = state
            .packets_to_send()
            .map(|p| numbers::packet_type_to_string(p.packet_type()))
            .collect::<Vec<_>>();

        let expected = types
            .iter()
            .map(|p| numbers::packet_type_to_string(*p))
            .collect::<Vec<_>>();
        assert_eq!(expected, response);
    }

    fn open_session_channel(state: &mut ChannelsState) {
        state
            .recv_packet(Packet::new_msg_channel_open_session(
                b"session", 0, 2048, 1024,
            ))
            .unwrap();
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_OPEN_CONFIRMATION]);
    }

    #[test]
    fn interactive_pty() {
        let state = &mut ChannelsState::new(true);
        open_session_channel(state);

        state
            .recv_packet(Packet::new_msg_channel_request_pty_req(
                0, b"pty-req", true, b"xterm", 80, 24, 0, 0, b"",
            ))
            .unwrap();
        state.do_operation(ChannelNumber(0).construct_op(ChannelOperationKind::Success));
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_SUCCESS]);

        state
            .recv_packet(Packet::new_msg_channel_request_shell(0, b"shell", true))
            .unwrap();
        state.do_operation(ChannelNumber(0).construct_op(ChannelOperationKind::Success));
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_SUCCESS]);

        state
            .recv_packet(Packet::new_msg_channel_data(0, b"hello, world"))
            .unwrap();
        assert_response_types(state, &[]);

        state.recv_packet(Packet::new_msg_channel_eof(0)).unwrap();
        assert_response_types(state, &[]);

        state.recv_packet(Packet::new_msg_channel_close(0)).unwrap();
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_CLOSE]);
    }

    #[test]
    fn only_single_close_for_double_close_operation() {
        let state = &mut ChannelsState::new(true);
        open_session_channel(state);
        state.do_operation(ChannelOperation {
            number: ChannelNumber(0),
            kind: ChannelOperationKind::Close,
        });
        state.do_operation(ChannelOperation {
            number: ChannelNumber(0),
            kind: ChannelOperationKind::Close,
        });
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_CLOSE]);
    }

    #[test]
    fn ignore_operation_after_close() {
        let mut state = &mut ChannelsState::new(true);
        open_session_channel(state);
        state.recv_packet(Packet::new_msg_channel_close(0)).unwrap();
        assert_response_types(&mut state, &[numbers::SSH_MSG_CHANNEL_CLOSE]);
        state.do_operation(ChannelOperation {
            number: ChannelNumber(0),
            kind: ChannelOperationKind::Data(vec![0]),
        });
        assert_response_types(state, &[]);
    }

    #[test]
    fn respect_peer_windowing() {
        let state = &mut ChannelsState::new(true);
        state
            .recv_packet(Packet::new_msg_channel_open_session(b"session", 0, 10, 50))
            .unwrap();
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_OPEN_CONFIRMATION]);

        // Send 100 bytes.
        state.do_operation(
            ChannelNumber(0)
                .construct_op(ChannelOperationKind::Data((0_u8..200).collect::<Vec<_>>())),
        );

        // 0..10
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_DATA]);

        state
            .recv_packet(Packet::new_msg_channel_window_adjust(0, 90))
            .unwrap();
        // 10..60, 60..100
        assert_response_types(
            state,
            &[numbers::SSH_MSG_CHANNEL_DATA, numbers::SSH_MSG_CHANNEL_DATA],
        );

        state
            .recv_packet(Packet::new_msg_channel_window_adjust(0, 100))
            .unwrap();
        // 100..150, 150..20
        assert_response_types(
            state,
            &[numbers::SSH_MSG_CHANNEL_DATA, numbers::SSH_MSG_CHANNEL_DATA],
        );

        state
            .recv_packet(Packet::new_msg_channel_window_adjust(0, 100))
            .unwrap();
        assert_response_types(state, &[]);
    }

    #[test]
    fn send_windowing_adjustments() {
        let state = &mut ChannelsState::new(true);
        state
            .recv_packet(Packet::new_msg_channel_open_session(
                b"session", 0, 2000, 2000,
            ))
            .unwrap();
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_OPEN_CONFIRMATION]);

        state
            .recv_packet(Packet::new_msg_channel_data(0, &vec![0; 2000]))
            .unwrap();
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_WINDOW_ADJUST]);

        // We currently hardcode <1000 for when to send window size adjustments.
        state
            .recv_packet(Packet::new_msg_channel_data(0, &vec![0; 1000]))
            .unwrap();
        assert_response_types(state, &[]);
        state
            .recv_packet(Packet::new_msg_channel_data(0, &vec![0; 1]))
            .unwrap();
        assert_response_types(state, &[numbers::SSH_MSG_CHANNEL_WINDOW_ADJUST]);
    }
}
