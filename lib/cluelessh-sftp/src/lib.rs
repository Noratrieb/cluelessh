mod transport;

use std::{
    collections::HashMap,
    io,
    os::fd::OwnedFd,
    path::Path,
    pin::Pin,
    sync::atomic::{AtomicU32, Ordering},
};

use cluelessh_format::{numbers, Writer};
use eyre::{bail, ensure, OptionExt, Result};
use rustix::fs::{Mode, OFlags};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tracing::trace;
use transport::{Packet, PacketTransport};

pub struct SftpServer {
    input: Pin<Box<dyn AsyncRead + Send + Sync>>,
    output: Pin<Box<dyn AsyncWrite + Send + Sync>>,

    state: SftpState,

    transport: PacketTransport,

    files: HashMap<Handle, OwnedFd>,
    next_handle: AtomicU32,

    _events_send: mpsc::Sender<Event>,
    events_recv: mpsc::Receiver<Event>,
}

type Handle = u32;

enum SftpState {
    Init,
    Open,
}

const BUF_SIZE: usize = 1024;

struct Event {
    _data: Vec<u8>,
}

impl SftpServer {
    pub fn new(
        input: impl AsyncRead + Send + Sync + 'static,
        output: impl AsyncWrite + Send + Sync + 'static,
    ) -> Self {
        let (events_send, events_recv) = mpsc::channel(10);
        Self {
            input: Box::pin(input),
            output: Box::pin(output),

            state: SftpState::Init,

            files: HashMap::new(),
            next_handle: AtomicU32::new(0),

            transport: PacketTransport::new(),
            _events_send: events_send,
            events_recv,
        }
    }

    pub async fn serve(&mut self) -> Result<()> {
        let mut buf = [0; BUF_SIZE];

        loop {
            tokio::select! {
                read = self.input.read(&mut buf) => {
                    self.recv_byte(&buf[..read?]).await?;
                }
                _event = self.events_recv.recv() => {
                    todo!()
                }
            }
        }
    }

    async fn recv_byte(&mut self, bytes: &[u8]) -> Result<()> {
        self.transport.recv_bytes(bytes)?;

        let packets = self.transport.packets();

        for packet in packets {
            let packet_type = packet.packet_type();
            let packet_type_string = numbers::sftp_message_type_to_string(packet_type);
            trace!(%packet_type, %packet_type_string, packet_len = %packet.all_payload().len(), "Received packet");

            if let SftpState::Init = self.state {
                ensure!(
                    packet.packet_type() == numbers::SSH_FXP_INIT,
                    "Client did not send SSH_FXP_INIT"
                );
                let mut p = packet.payload_reader();
                let version = p.u32()?;
                ensure!(
                    version == 6 || version == 3,
                    "Unexpected version: {version}"
                );
                // TODO: negotiate 6 nicely using the version-select extension
                let mut w = Writer::new();
                w.u8(numbers::SSH_FXP_VERSION);
                w.u32(3); // version
                          // newline extension
                w.string("newline");
                w.string("\n");
                self.send_packet(w.finish()).await?;
                self.state = SftpState::Open;
                continue;
            }

            let mut p = packet.payload_reader();

            match packet_type {
                numbers::SSH_FXP_CLOSE => {
                    let req_id = p.u32()?;
                    let _ = p.u32()?;
                    let handle = p.u32()?;
                    let Some(handle) = self.files.remove(&handle) else {
                        bail!("invalid handle");
                    };
                    drop(handle);
                    self.send_packet(status(req_id, numbers::SSH_FX_OK, ""))
                        .await?;
                }
                numbers::SSH_FXP_OPENDIR => {
                    let req_id = p.u32()?;
                    let path = p.utf8_string()?;

                    // TODO: dont block lol
                    let result =
                        rustix::fs::open(path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty());
                    match result {
                        Ok(fd) => {
                            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
                            self.files.insert(handle, fd);
                            let mut w = Writer::new();
                            w.u8(numbers::SSH_FXP_HANDLE);
                            w.u32(req_id);
                            w.u32(4); // handle length
                            w.u32(handle);
                            self.send_packet(w.finish()).await?;
                        }
                        Err(err) => self.send_io_error(req_id, err.into()).await?,
                    }
                }
                numbers::SSH_FXP_READDIR => {
                    let req_id = p.u32()?;
                    let _ = p.u32()?;
                    let handle = p.u32()?;
                    let Some(handle) = self.files.get(&handle) else {
                        bail!("invalid handle");
                    };
                    let mut entries: Vec<(String, String, Attrs)> = Vec::new();
                    let mut buf = Vec::with_capacity(8192);
                    let mut iter = rustix::fs::RawDir::new(handle, buf.spare_capacity_mut());
                    while let Some(entry) = iter.next() {
                        let entry = entry?; // TODO: handle error
                        let name = entry.file_name().to_str()?.to_owned();
                        entries.push((name.clone(), name, Attrs::default()));
                    }

                    let mut w = Writer::new();
                    w.u8(numbers::SSH_FXP_NAME);
                    w.u32(req_id);
                    w.u32(entries.len() as u32);
                    for entry in entries {
                        w.string(entry.0);
                        w.string(entry.1);
                        entry.2.encode(&mut w);
                    }

                    self.send_packet(w.finish()).await?;
                }
                numbers::SSH_FXP_REALPATH => {
                    let req_id = p.u32()?;
                    let original_path = p.utf8_string()?;

                    let p = Path::new(original_path).canonicalize();

                    match p {
                        Ok(p) => {
                            let mut w = Writer::new();
                            w.u8(numbers::SSH_FXP_NAME);
                            w.u32(req_id);
                            w.u32(1); // count

                            let filename = p
                                .as_os_str()
                                .to_str()
                                .ok_or_eyre("filename is invalid UTF-8")?
                                .as_bytes();
                            w.string(filename); // filename
                            w.string(filename); // longname, TODO: this should be ls -l output lol
                            Attrs::default().encode(&mut w); // attrs, dummy
                            self.send_packet(w.finish()).await?;
                        }
                        Err(err) => self.send_io_error(req_id, err).await?,
                    }
                }
                _ => {
                    bail!("unknown packet: {packet_type_string} ({packet_type})")
                }
            }
        }

        Ok(())
    }

    async fn send_io_error(&mut self, req_id: u32, err: io::Error) -> Result<()> {
        self.send_packet(status(req_id, io_error_to_code(&err), &err.to_string()))
            .await
    }

    async fn send_packet(&mut self, body: impl AsRef<[u8]>) -> Result<()> {
        let packet = Packet::from_body(body.as_ref());
        let packet_type = packet.packet_type();
        let packet_type_string = numbers::sftp_message_type_to_string(packet_type);
        trace!(%packet_type, %packet_type_string, packet_len = %packet.all_payload().len(), "Sending packet");

        // TODO: do this async...
        self.output.write_all(packet.all_payload()).await?;
        Ok(())
    }
}

fn io_error_to_code(err: &io::Error) -> u32 {
    match err.kind() {
        io::ErrorKind::NotFound => numbers::SSH_FX_NO_SUCH_FILE,
        io::ErrorKind::PermissionDenied => numbers::SSH_FX_PERMISSION_DENIED,
        _ => numbers::SSH_FX_FAILURE,
    }
}

#[derive(Default)]
struct Attrs {
    size: Option<u64>,
    uid_gid: Option<(u32, u32)>,
    permissions: Option<u32>,
    atime_mtime: Option<(u32, u32)>,
}

impl Attrs {
    fn encode(&self, w: &mut Writer) {
        use numbers::*;

        let flag = |bool, flag| if bool { flag } else { 0 };
        let flags = flag(self.size.is_some(), SSH_FILEXFER_ATTR_SIZE)
            | flag(self.uid_gid.is_some(), SSH_FILEXFER_ATTR_UIDGID)
            | flag(self.permissions.is_some(), SSH_FILEXFER_ATTR_PERMISSIONS)
            | flag(self.atime_mtime.is_some(), SSH_FILEXFER_ATTR_ACMODTIME);

        w.u32(flags);
        if let Some(size) = self.size {
            w.u64(size);
        };
        if let Some((uid, gid)) = self.uid_gid {
            w.u32(uid);
            w.u32(gid);
        };
        if let Some(perm) = self.permissions {
            w.u32(perm);
        }
        if let Some((atime, mtime)) = self.atime_mtime {
            w.u32(atime);
            w.u32(mtime);
        }
    }
}

fn status(req_id: u32, code: u32, message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(numbers::SSH_FXP_STATUS);
    w.u32(req_id);
    w.u32(code);
    w.string(message);
    w.string("");
    w.finish()
}
