use eyre::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let env_filter =
        EnvFilter::try_from_env("SFTP_LOG").unwrap_or_else(|_| EnvFilter::new("debug"));

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .init();

    info!("mroooow!");

    Ok(())
}
