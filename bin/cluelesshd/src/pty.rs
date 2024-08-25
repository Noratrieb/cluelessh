//! PTY-related operations for setting up the session.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use eyre::{Context, Result};
use rustix::{
    fs::{Mode, OFlags},
    pty::OpenptFlags,
    termios::Winsize,
};
use tokio::process::Command;

pub struct Pty {
    term: String,

    controller: OwnedFd,

    user_pty: OwnedFd,
    user_pty_name: String,
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
        let user_pty_name = std::str::from_utf8(user_pty_name.as_bytes())
            .wrap_err("pty name is invalid UTF-8")?
            .to_owned();

        let user_pty =
            rustix::fs::open(&user_pty_name, OFlags::RDWR | OFlags::NOCTTY, Mode::empty())?;

        // Configure terminal:
        rustix::termios::tcsetwinsize(&user_pty, winsize)?;
        let termios = rustix::termios::tcgetattr(&user_pty)?;
        // TODO: set modes
        // <https://datatracker.ietf.org/doc/html/rfc4254#section-8>
        let _ = termios;
        let _ = modes;
        rustix::termios::tcsetattr(&user_pty, rustix::termios::OptionalActions::Flush, &termios)?;

        Ok(Self {
            term,
            controller,
            user_pty,
            user_pty_name,
        })
    }

    pub fn controller(&self) -> BorrowedFd<'_> {
        self.controller.as_fd()
    }

    pub fn start_session_for_command(&self, cmd: &mut Command) -> Result<()> {
        let user_pty = self.user_pty.try_clone()?;
        unsafe {
            cmd.pre_exec(move || {
                rustix::pty::grantpt(&user_pty)?;
                let pid = rustix::process::setsid()?;
                rustix::process::ioctl_tiocsctty(&user_pty)?; // Set as the current controlling tty
                rustix::termios::tcsetpgrp(&user_pty, pid)?; // Set current process as tty controller

                // Setup stdio with PTY.
                rustix::stdio::dup2_stdin(&user_pty)?;
                rustix::stdio::dup2_stdout(&user_pty)?;
                rustix::stdio::dup2_stderr(&user_pty)?;

                Ok(())
            });
            cmd.env("TERM", &self.term);
            cmd.env("SSH_TTY", &self.user_pty_name);
        }

        Ok(())
    }
}
