mod crypto;
pub mod numbers;
pub mod packet;
pub mod parse;
pub mod server;

pub use packet::Msg;

#[derive(Debug)]
pub enum SshStatus {
    /// The client has sent a disconnect request, close the connection.
    /// This is not an error.
    Disconnect,
    /// The client did something wrong.
    /// The connection should be closed and a notice may be logged,
    /// but this does not require operator intervention.
    ClientError(String),
    /// Something went wrong on the server.
    /// The connection should be closed and an error should be logged.
    // TODO: does this ever happen?
    ServerError(eyre::Report),
}

pub type Result<T, E = SshStatus> = std::result::Result<T, E>;

impl From<eyre::Report> for SshStatus {
    fn from(value: eyre::Report) -> Self {
        Self::ServerError(value)
    }
}

pub trait SshRng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
struct SshRngRandAdapter<'a>(&'a mut dyn SshRng);
impl rand_core::CryptoRng for SshRngRandAdapter<'_> {}
impl rand_core::RngCore for SshRngRandAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[macro_export]
macro_rules! client_error {
    ($($tt:tt)*) => {
        $crate::SshStatus::ClientError(::std::format!($($tt)*))
    };
}
