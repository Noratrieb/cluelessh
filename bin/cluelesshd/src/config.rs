use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use crate::Args;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_info")]
    pub log_level: String,
    pub net: NetConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
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
}

impl Config {
    pub fn find(args: &Args) -> Result<Self> {
        let path = std::env::var("CLUELESSHD_CONFIG")
            .map(PathBuf::from)
            .or(args.config.clone().ok_or(std::env::VarError::NotPresent))
            .unwrap_or_else(|_| PathBuf::from("cluelesshd.toml"));

        let content = std::fs::read_to_string(&path).wrap_err_with(|| {
            format!("failed to open config file '{}', refusing to start. you can change the config file path with the --config arg or the CLUELESSHD_CONFIG environment variable", path.display())
        })?;

        toml::from_str(&content)
            .wrap_err_with(|| format!("invalid config file '{}'", path.display()))
    }
}

fn default_info() -> String {
    "info".to_owned()
}

fn default_true() -> bool {
    true
}

fn addr_default() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

fn port_default() -> u16 {
    22
}
