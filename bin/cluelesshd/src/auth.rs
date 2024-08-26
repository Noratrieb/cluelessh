//! User authentication.

use std::io;

use cluelessh_keys::{
    authorized_keys::{self, AuthorizedKeys}, public::PublicKey, PublicKeyWithComment
};
use users::os::unix::UserExt;

/// A known-authorized public key for a user.
pub struct UserPublicKey(PublicKeyWithComment);

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
    /// Blocking!
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
            .map_err(|err| AuthError::NoAuthorizedKeys(err))?;

        let authorized_keys = AuthorizedKeys::parse(&file)?;

        if let Some(key) = authorized_keys.contains(&provided_key) {
            Ok(Self(key.clone()))
        } else {
            Err(AuthError::UnauthorizedPublicKey)
        }
    }

    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        self.0.key.verify_signature(data, signature)
    }
}
