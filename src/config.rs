use std::path::PathBuf;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub blocklist_sources: Option<Vec<String>>, // URLs or file paths
    pub listen_addr: String,
    pub upstream_addr: String,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub enable_udp: Option<bool>,
    pub enable_dot: Option<bool>,
    pub enable_doh: Option<bool>,
    // Add more settings as needed
}

impl Config {
    pub fn load() -> Self {
        let config_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/"))
            .join(".config/zendns/config.toml");
        let content = fs::read_to_string(&config_path).expect("Failed to read config.toml");
        toml::from_str(&content).expect("Failed to parse config.toml")
    }
}
