use tracing::debug;

use crate::packet::Packet;
use crate::parse::Parser;
use crate::Result;
use crate::client_error;

pub(crate) struct ServerChannelsState {}

impl ServerChannelsState {
    pub(crate) fn new() -> Self {
        ServerChannelsState {}
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
                        todo!("open session")
                    }
                    _ => todo!("response with SSH_MSG_CHANNEL_OPEN_FAILURE"),
                }
            }
            _ => {
                todo!("{packet_type}");
            }
        }

        Ok(())
    }
}
