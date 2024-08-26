pub mod authorized_keys;
mod crypto;
pub mod private;
pub mod public;
pub mod signature;

// TODO: good typed error messages so the user knows what's going on

pub use crate::crypto::{KeyGenerationParams, KeyType};
