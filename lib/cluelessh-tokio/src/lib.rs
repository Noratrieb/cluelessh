pub mod client;
pub mod server;

use cluelessh_connection::{ChannelKind, ChannelNumber, ChannelOperation, ChannelOperationKind};
use cluelessh_protocol::ChannelUpdateKind;
use eyre::{OptionExt, Result};

pub struct Channel {
    number: ChannelNumber,
    updates_recv: tokio::sync::mpsc::Receiver<ChannelUpdateKind>,
    ops_send: tokio::sync::mpsc::Sender<ChannelOperation>,
    kind: ChannelKind,
}

impl Channel {
    pub async fn send(&mut self, op: ChannelOperationKind) -> Result<()> {
        self.ops_send
            .send(self.number.construct_op(op))
            .await
            .map_err(Into::into)
    }

    pub async fn next_update(&mut self) -> Result<ChannelUpdateKind> {
        self.updates_recv
            .recv()
            .await
            .ok_or_eyre("channel has been closed")
    }

    pub fn kind(&self) -> &ChannelKind {
        &self.kind
    }
}
