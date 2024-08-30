use std::{
    fs::File,
    io,
    os::fd::OwnedFd,
    pin::Pin,
    task::{ready, Poll},
};

use eyre::{Context, Result};
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite};
use tracing::debug;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let env_filter =
        EnvFilter::try_from_env("SFTP_LOG").unwrap_or_else(|_| EnvFilter::new("debug"));

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .init();

    let stdin = rustix::stdio::stdin().try_clone_to_owned()?;
    let stdout = rustix::stdio::stdout().try_clone_to_owned()?;

    // Ensure that writing to stdout fails
    if let Ok(full) = File::open("/dev/full") {
        let _ = rustix::stdio::dup2_stdout(&full);
    }

    let input = AsyncFdWrapper::from_fd(stdin)?;
    let output = AsyncFdWrapper::from_fd(stdout)?;

    debug!("Starting SFTP server");

    let mut server = cluelessh_sftp::SftpServer::new(input, output);
    server.serve().await
}

// TODO: Share with cluelesshd
struct AsyncFdWrapper {
    fd: AsyncFd<OwnedFd>,
}

impl AsyncFdWrapper {
    fn from_fd(fd: OwnedFd) -> Result<Self> {
        rustix::io::ioctl_fionbio(&fd, true).wrap_err("putting fd into nonblocking mode")?;
        Ok(Self {
            fd: AsyncFd::new(fd).wrap_err("failed to register async event")?,
        })
    }
}

impl AsyncRead for AsyncFdWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                rustix::io::read(inner.get_ref(), unfilled).map_err(io::Error::from)
            }) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncFdWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;

            match guard
                .try_io(|inner| rustix::io::write(inner.get_ref(), buf).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}
