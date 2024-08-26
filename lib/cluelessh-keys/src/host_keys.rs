use std::collections::HashSet;

use thiserror::Error;

use crate::private::PlaintextPrivateKey;

/// A set of host keys, ensuring there are no duplicated algorithms.
#[derive(Debug, Default)]
pub struct HostKeySet {
    algs: HashSet<&'static str>,
    keys: Vec<PlaintextPrivateKey>,
}

impl HostKeySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_keys(self) -> Vec<PlaintextPrivateKey> {
        self.keys
    }

    pub fn insert(&mut self, key: PlaintextPrivateKey) -> Result<(), DuplicateHostKeyAlgorithm> {
        let alg = key.private_key.algorithm_name();

        let newly_inserted = self.algs.insert(alg);
        if !newly_inserted {
            return Err(DuplicateHostKeyAlgorithm { alg });
        }

        self.keys.push(key);

        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("another host key with algorithm {alg} has already been loaded")]
pub struct DuplicateHostKeyAlgorithm {
    alg: &'static str,
}

// TODO: write tests
