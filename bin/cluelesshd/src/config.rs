use eyre::{Context, Result};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_info")]
    pub log_level: String,
    pub net: NetConfig,
    pub auth: AuthConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetConfig {
    #[serde(default = "addr_default")]
    pub ip: IpAddr,
    #[serde(default = "port_default")]
    pub port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub host_keys: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub password_login: bool,
    pub banner: Option<String>,
}

impl Config {
    pub fn find() -> Result<Self> {
        let path =
            std::env::var("CLUELESSHD_CONFIG").unwrap_or_else(|_| "cluelesshd.toml".to_owned());

        let content = std::fs::read_to_string(&path).wrap_err_with(|| {
            format!("failed to open config file '{path}', refusing to start. you can change the config file path with the CLUELESSHD_CONFIG environment variable")
        })?;

        toml::from_str(&content).wrap_err_with(|| format!("invalid config file '{path}'"))
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
