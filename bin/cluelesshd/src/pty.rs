//! PTY-related operations for setting up the session.

use std::{
    io::{Read, Write},
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    path::PathBuf,
};

use eyre::{Context, Result};
use rustix::{
    fs::{Mode, OFlags},
    pty::OpenptFlags,
    termios::Winsize,
};
use tokio::{process::Command, sync::mpsc, task::JoinHandle};

pub struct Pty {
    term: String,

    #[expect(dead_code)]
    writer_handle: JoinHandle<()>,
    #[expect(dead_code)]
    reader_handle: JoinHandle<()>,
    pub ctrl_write_send: mpsc::Sender<Vec<u8>>,
    pub ctrl_read_recv: mpsc::Receiver<Vec<u8>>,
    user_pty: OwnedFd,
}

impl Pty {
    pub async fn new(term: String, winsize: Winsize, modes: Vec<u8>) -> Result<Self> {
        tokio::task::spawn_blocking(move || Self::new_blocking(term, winsize, modes)).await?
    }
    pub fn new_blocking(term: String, winsize: Winsize, modes: Vec<u8>) -> Result<Self> {
        // Create new PTY:
        let controller = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)
            .wrap_err("opening controller pty")?;
        rustix::pty::unlockpt(&controller).wrap_err("unlocking pty")?;

        let user_pty_name = rustix::pty::ptsname(&controller, Vec::new())?;
        let user_pty_name =
            std::str::from_utf8(user_pty_name.as_bytes()).wrap_err("pty name is invalid UTF-8")?;
        let user_pty_name = PathBuf::from(user_pty_name);

        let user_pty =
            rustix::fs::open(user_pty_name, OFlags::RDWR | OFlags::NOCTTY, Mode::empty())?;

        // Configure terminal:
        rustix::termios::tcsetwinsize(&user_pty, winsize)?;
        let termios = rustix::termios::tcgetattr(&user_pty)?;
        // TODO: set modes
        // <https://datatracker.ietf.org/doc/html/rfc4254#section-8>
        let _ = termios;
        let _ = modes;
        rustix::termios::tcsetattr(&user_pty, rustix::termios::OptionalActions::Flush, &termios)?;

        // Set up communication threads:
        let mut controller_read = std::fs::File::from(controller);
        let mut controller_write = controller_read.try_clone()?;

        let (ctrl_write_send, mut ctrl_write_recv) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
        let (ctrl_read_send, ctrl_read_recv) = tokio::sync::mpsc::channel::<Vec<u8>>(10);

        let writer_handle = tokio::task::spawn_blocking(move || {
            while let Some(write) = ctrl_write_recv.blocking_recv() {
                let _ = controller_write.write_all(&write);
            }
        });

        let reader_handle = tokio::task::spawn_blocking(move || {
            let mut buf = [0; 1024];
            loop {
                let Ok(read) = controller_read.read(&mut buf) else {
                    return;
                };
                let Ok(_) = ctrl_read_send.blocking_send(buf[..read].to_vec()) else {
                    return;
                };
            }
        });

        Ok(Self {
            term,
            writer_handle,
            reader_handle,
            ctrl_write_send,
            ctrl_read_recv,
            user_pty,
        })
    }

    pub fn start_session_for_command(&self, cmd: &mut Command) -> Result<()> {
        let user_pty = self.user_pty.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                let user_pty = BorrowedFd::borrow_raw(user_pty);
                rustix::pty::grantpt(user_pty)?;
                let pid = rustix::process::setsid()?;
                rustix::process::ioctl_tiocsctty(user_pty)?; // Set as the current controlling tty
                rustix::termios::tcsetpgrp(user_pty, pid)?; // Set current process as tty controller

                // Setup stdio with PTY.
                rustix::stdio::dup2_stdin(user_pty)?;
                rustix::stdio::dup2_stdout(user_pty)?;
                rustix::stdio::dup2_stderr(user_pty)?;

                Ok(())
            });
            cmd.env("TERM", &self.term);
        }

        Ok(())
    }
}
