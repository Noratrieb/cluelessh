//! User authentication.

use std::io;

use cluelessh_keys::{
    authorized_keys::{self, AuthorizedKeys},
    public::{PublicKey, PublicKeyWithComment},
};
use cluelessh_protocol::auth::{CheckPubkey, VerifySignature};
use eyre::eyre;
use tracing::debug;
use users::{os::unix::UserExt, User};

/// A known-authorized public key for a user.
pub struct UserPublicKey {
    key: PublicKeyWithComment,
    user: User,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("unknown user")]
    UnknownUser,
    #[error("~/.ssh/authorized_keys not found")]
    NoAuthorizedKeys(#[source] io::Error),
    #[error("invalid ~/.ssh/authorized_keys")]
    InvalidAuthorizedKeys(#[from] authorized_keys::Error),
    #[error("public key not authorized")]
    UnauthorizedPublicKey,
}

impl UserPublicKey {
    pub async fn for_user_and_key(
        user: String,
        provided_key: &PublicKey,
    ) -> Result<Self, AuthError> {
        let user = tokio::task::spawn_blocking(move || {
            users::get_user_by_name(&user).ok_or(AuthError::UnknownUser)
        })
        .await
        .unwrap()?;

        let sshd_dir = user.home_dir().join(".ssh").join("authorized_keys");

        let file = tokio::fs::read_to_string(sshd_dir)
            .await
            .map_err(AuthError::NoAuthorizedKeys)?;

        let authorized_keys = AuthorizedKeys::parse(&file)?;

        if let Some(key) = authorized_keys.contains(provided_key) {
            Ok(Self {
                key: key.clone(),
                user,
            })
        } else {
            Err(AuthError::UnauthorizedPublicKey)
        }
    }

    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        self.key.key.verify_signature(data, signature)
    }
}

pub async fn verify_signature(auth: VerifySignature) -> eyre::Result<Option<User>> {
    let Ok(public_key) = PublicKey::from_wire_encoding(&auth.pubkey) else {
        return Ok(None);
    };
    if auth.pubkey_alg_name != public_key.algorithm_name() {
        return Ok(None);
    }

    let result = UserPublicKey::for_user_and_key(auth.user.clone(), &public_key).await;

    debug!(user = %auth.user, err = ?result.as_ref().err(), "Attempting publickey signature");

    match result {
        Ok(user_key) => {
            // Verify signature...

            let sign_data = cluelessh_keys::signature::signature_data(
                auth.session_identifier,
                &auth.user,
                &public_key,
            );

            if user_key.verify_signature(&sign_data, &auth.signature) {
                Ok(Some(user_key.user))
            } else {
                Ok(None)
            }
        }
        Err(
            AuthError::UnknownUser
            | AuthError::UnauthorizedPublicKey
            | AuthError::NoAuthorizedKeys(_),
        ) => Ok(None),
        Err(AuthError::InvalidAuthorizedKeys(err)) => Err(eyre!(err)),
    }
}

pub async fn check_pubkey(auth: CheckPubkey) -> eyre::Result<bool> {
    let Ok(public_key) = PublicKey::from_wire_encoding(&auth.pubkey) else {
        return Ok(false);
    };
    if auth.pubkey_alg_name != public_key.algorithm_name() {
        return Ok(false);
    }
    let result = UserPublicKey::for_user_and_key(auth.user.clone(), &public_key).await;

    debug!(user = %auth.user, err = ?result.as_ref().err(), "Attempting publickey check");

    match result {
        Ok(_) => Ok(true),
        Err(
            AuthError::UnknownUser
            | AuthError::UnauthorizedPublicKey
            | AuthError::NoAuthorizedKeys(_),
        ) => Ok(false),
        Err(AuthError::InvalidAuthorizedKeys(err)) => Err(eyre!(err)),
    }
}
