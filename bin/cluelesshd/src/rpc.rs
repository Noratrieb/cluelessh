//! [`postcard`]-based RPC between the different processes.

use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;

use cluelessh_keys::public::PublicKey;
use cluelessh_keys::signature::Signature;
use cluelessh_protocol::auth::CheckPubkey;
use cluelessh_protocol::auth::VerifySignature;
use cluelessh_tokio::server::ServerAuth;
use cluelessh_tokio::server::SignWithHostKey;
use eyre::eyre;
use eyre::Context;
use eyre::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::UnixDatagram;

#[derive(Serialize, Deserialize)]
enum Request {
    Sign {
        hash: [u8; 32],
        public_key: PublicKey,
    },
    VerifySignature {
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    CheckPubkey {
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
struct SignResponse {
    signature: Result<Signature, String>,
}

#[derive(Serialize, Deserialize)]
struct VerifySignatureResponse {
    is_ok: Result<bool, String>,
}

#[derive(Serialize, Deserialize)]
struct CheckPubkeyResponse {
    is_ok: Result<bool, String>,
}

pub struct Client {
    socket: UnixDatagram,
}

pub struct Server {
    server: UnixDatagram,
    client: UnixDatagram,
    auth_operations: ServerAuth,
}

impl Server {
    pub fn new(auth_operations: ServerAuth) -> Result<Self> {
        let (server, client) = UnixDatagram::pair().wrap_err("creating socketpair")?;

        Ok(Self {
            server,
            client,
            auth_operations,
        })
    }

    pub fn client_fd(&self) -> BorrowedFd<'_> {
        self.client.as_fd()
    }

    pub async fn process(&self) -> Result<()> {
        let mut req = [0; 1024];

        loop {
            let read = self
                .server
                .recv(&mut req)
                .await
                .wrap_err("receiving response")?;

            let req = postcard::from_bytes::<Request>(&req[..read]).wrap_err("invalid request")?;

            match req {
                Request::Sign { hash, public_key } => {
                    let signature = (self.auth_operations.sign_with_hostkey)(SignWithHostKey {
                        hash,
                        public_key,
                    })
                    .await
                    .map_err(|err| err.to_string());

                    self.respond(SignResponse { signature }).await?;
                }
                Request::VerifySignature {
                    user,
                    session_identifier,
                    pubkey_alg_name,
                    pubkey,
                    signature,
                } => {
                    let Some(verify_signature) = &self.auth_operations.verify_signature else {
                        self.respond(VerifySignatureResponse {
                            is_ok: Err("public key login not supported".into()),
                        })
                        .await?;
                        continue;
                    };
                    let is_ok = verify_signature(VerifySignature {
                        user,
                        session_identifier,
                        pubkey_alg_name,
                        pubkey,
                        signature,
                    })
                    .await
                    .map_err(|err| err.to_string());

                    self.respond(VerifySignatureResponse { is_ok }).await?;
                }
                Request::CheckPubkey {
                    user,
                    session_identifier,
                    pubkey_alg_name,
                    pubkey,
                } => {
                    let Some(check_pubkey) = &self.auth_operations.check_pubkey else {
                        self.respond(VerifySignatureResponse {
                            is_ok: Err("public key login not supported".into()),
                        })
                        .await?;
                        continue;
                    };
                    let is_ok = check_pubkey(CheckPubkey {
                        user,
                        session_identifier,
                        pubkey_alg_name,
                        pubkey,
                    })
                    .await
                    .map_err(|err| err.to_string());

                    self.respond(CheckPubkeyResponse { is_ok }).await?;
                }
            }
        }
    }

    async fn respond(&self, resp: impl Serialize) -> Result<()> {
        self.server
            .send(&postcard::to_allocvec(&resp)?)
            .await
            .wrap_err("sending response")?;
        Ok(())
    }
}

impl Client {
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        let socket = UnixDatagram::from_std(std::os::unix::net::UnixDatagram::from(fd))?;
        Ok(Self { socket })
    }

    pub async fn sign(&self, hash: [u8; 32], public_key: PublicKey) -> Result<Signature> {
        let resp = self
            .request_response::<SignResponse>(&Request::Sign { hash, public_key })
            .await?;

        resp.signature.map_err(|err| eyre!(err))
    }

    pub async fn check_pubkey(
        &self,
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
    ) -> Result<bool> {
        let resp = self
            .request_response::<CheckPubkeyResponse>(&Request::CheckPubkey {
                user,
                session_identifier,
                pubkey_alg_name,
                pubkey,
            })
            .await?;

        resp.is_ok.map_err(|err| eyre!(err))
    }

    pub async fn verify_signature(
        &self,
        user: String,
        session_identifier: [u8; 32],
        pubkey_alg_name: String,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool> {
        let resp = self
            .request_response::<VerifySignatureResponse>(&Request::VerifySignature {
                user,
                session_identifier,
                pubkey_alg_name,
                pubkey,
                signature,
            })
            .await?;

        resp.is_ok.map_err(|err| eyre!(err))
    }

    async fn request_response<Resp: DeserializeOwned>(&self, req: &Request) -> Result<Resp> {
        self.socket
            .send(&postcard::to_allocvec(&req)?)
            .await
            .wrap_err("sending request")?;

        let mut resp = [0; 1024];
        let read = self
            .socket
            .recv(&mut resp)
            .await
            .wrap_err("receiving response")?;

        let resp =
            postcard::from_bytes::<Resp>(&resp[..read]).wrap_err("invalid signature response")?;

        Ok(resp)
    }
}
