use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use crate::Args;

// TODO: validate config and user nicer structs to consume it

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_info")]
    pub log_level: String,
    pub net: NetConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub subsystem: HashMap<String, SubsystemConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetConfig {
    #[serde(default = "addr_default")]
    pub ip: IpAddr,
    #[serde(default = "port_default")]
    pub port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub host_keys: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub password_login: bool,
    pub banner: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// A hardcoded uid for an unprivileged user.
    /// Mostly useful for testing.
    pub unprivileged_uid: Option<u32>,
    /// A hardcoded gid for an unprivileged user.
    /// Mostly useful for testing.
    pub unprivileged_gid: Option<u32>,
    /// The username of an unprivileged user.
    pub unprivileged_user: Option<String>,

    /// Apply experimental seccomp filters.
    #[serde(default = "default_false")]
    pub experimental_seccomp: bool,
}

/// Add arbitrary subsystems.
/// # Subsystem Protocol
/// Every subsystem process gets spawned in the home directory of the user, as the user.
/// Several FDs are guaranteed to be open.
/// - stdin (0): data from the client channel
/// - stdout (1): data to the client channel
/// - stderr (2): data to the client channel extended stderr (used for debugging)
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubsystemConfig {
    pub path: PathBuf,
}

impl Config {
    pub fn load(args: &Args) -> Result<Self> {
        let path = std::env::var("CLUELESSHD_CONFIG")
            .map(PathBuf::from)
            .or(args.config.clone().ok_or(std::env::VarError::NotPresent))
            .unwrap_or_else(|_| PathBuf::from("cluelesshd.toml"));

        let content = std::fs::read_to_string(&path).wrap_err_with(|| {
            format!("failed to open config file '{}', refusing to start. you can change the config file path with the --config arg or the CLUELESSHD_CONFIG environment variable", path.display())
        })?;

        let mut config: Config = toml::from_str(&content)
            .wrap_err_with(|| format!("invalid config file '{}'", path.display()))?;

        for sub in config.subsystem.values_mut() {
            sub.path = sub.path.canonicalize().wrap_err_with(|| {
                format!(
                    "error canonicalizing subsystem path: {}",
                    sub.path.display()
                )
            })?;
        }

        Ok(config)
    }
}

fn default_info() -> String {
    "info".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn addr_default() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

fn port_default() -> u16 {
    22
}
