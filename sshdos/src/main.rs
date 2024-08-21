use std::{
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;

use eyre::Context;
use rand::RngCore;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, error, info};

use ssh_protocol::{
    transport::{self},
    SshStatus,
};
use tracing_subscriber::EnvFilter;

struct ThreadRngRand;
impl ssh_protocol::transport::SshRng for ThreadRngRand {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::thread_rng().fill_bytes(dest);
    }
}

#[derive(clap::Parser, Debug, Clone)]
struct Args {
    #[arg(short = 'p', long, default_value_t = 22)]
    port: u16,
    #[arg(short = 't', long, default_value_t = 16)]
    threads: usize,
    #[arg(short = 'd', long, default_value_t = 1.0)]
    delay: f32,
    #[arg(short = 'c', long)]
    chill: bool,
    destination: String,
    command: Vec<String>,
}

enum Operation {
    PasswordEntered(std::io::Result<String>),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    for i in 0..args.threads {
        info!("Starting worker {i}");

        let args = args.clone();
        let counter = counter.clone();
        let handle = tokio::spawn(async move {
            loop {
                let result = execute_attempt(&args).await;
                counter.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs_f32(args.delay)).await;
                info!(
                    "Executed attempt {} on worker {i} with output {result:?}",
                    counter.load(Ordering::Relaxed)
                );
            }
        });
        handles.push(handle);
    }

    futures::future::join_all(handles).await;

    Ok(())
}

async fn execute_attempt(args: &Args) -> eyre::Result<()> {
    let conn = TcpStream::connect(&format!("{}:{}", args.destination, args.port)).await?;

    let result = execute_attempt_inner(args, conn).await;

    if args.chill {
        info!("Chilling, taking up space");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    result
}

async fn execute_attempt_inner(args: &Args, mut conn: TcpStream) -> eyre::Result<()> {
    let username = "dos";

    let mut transport = transport::client::ClientConnection::new(ThreadRngRand);
    transport.abort_for_dos = true;

    let mut state = ssh_protocol::ClientConnection::new(
        transport,
        ssh_protocol::auth::ClientAuth::new(username.as_bytes().to_vec()),
    );

    let (send_op, mut recv_op) = tokio::sync::mpsc::channel::<Operation>(10);

    let mut buf = [0; 1024];

    loop {
        while let Some(msg) = state.next_msg_to_send() {
            conn.write_all(&msg.to_bytes())
                .await
                .wrap_err("writing response")?;
        }

        if let Some(auth) = state.auth() {
            for req in auth.user_requests() {
                match req {
                    ssh_protocol::auth::ClientUserRequest::Password => {
                        let username = username.to_owned();
                        let destination = args.destination.clone();
                        let send_op = send_op.clone();
                        std::thread::spawn(move || {
                            let password = rpassword::prompt_password(format!(
                                "{}@{}'s password: ",
                                username, destination
                            ));
                            let _ = send_op.blocking_send(Operation::PasswordEntered(password));
                        });
                    }
                    ssh_protocol::auth::ClientUserRequest::Banner(banner) => {
                        let banner = String::from_utf8_lossy(&banner);
                        std::io::stdout().write(&banner.as_bytes())?;
                    }
                }
            }
        }

        tokio::select! {
            read = conn.read(&mut buf) => {
                let read = read.wrap_err("reading from connection")?;
                if read == 0 {
                    info!("Did not read any bytes from TCP stream, EOF");
                    return Ok(());
                }
                if let Err(err) = state.recv_bytes(&buf[..read]) {
                    match err {
                        SshStatus::PeerError(err) => {
                            if err == "early abort" {
                                // Expected.
                                return Ok(());
                            }
                            error!(?err, "disconnecting client after invalid operation");
                            return Ok(());
                        }
                        SshStatus::Disconnect => {
                            error!("Received disconnect from server");
                            return Ok(());
                        }
                    }
                }
            }
            op = recv_op.recv() => {
                match op {
                    Some(Operation::PasswordEntered(password)) => {
                        if let Some(auth) = state.auth() {
                            auth.send_password(&password?);
                        } else {
                            debug!("Ignoring entered password as the state has moved on");
                        }
                    }
                    None => {}
                }
                state.progress();
            }
        }
    }
}
