use std::collections::HashSet;
use std::path::PathBuf;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;
use tokio::signal::unix::{signal, SignalKind};

/// Thread-safe blocklist of domains
#[derive(Clone)]
pub struct Blocklist {
    pub domains: Arc<Mutex<HashSet<String>>>,
}

impl Blocklist {
    /// Loads domains from a list of blocklist URLs or files
    pub async fn load(sources: &[String]) -> Self {
        let mut domains = HashSet::new();
        for src in sources {
            if src.starts_with("http://") || src.starts_with("https://") {
                if let Ok(resp) = reqwest::get(src).await {
                    if let Ok(text) = resp.text().await {
                        for line in text.lines() {
                            let domain = line.trim();
                            if !domain.is_empty() && !domain.starts_with('#') {
                                domains.insert(domain.to_string());
                            }
                        }
                    }
                }
            } else {
                if let Ok(file) = File::open(src) {
                    let reader = BufReader::new(file);
                    for line in reader.lines() {
                        if let Ok(domain) = line {
                            let domain = domain.trim();
                            if !domain.is_empty() && !domain.starts_with('#') {
                                domains.insert(domain.to_string());
                            }
                        }
                    }
                }
            }
        }
        Blocklist { domains: Arc::new(Mutex::new(domains)) }
    }

    /// Checks if a domain is blocked
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.domains.lock().unwrap().contains(domain)
    }

    /// Periodically updates blocklist from URLs in a blocklist file
    pub async fn periodic_update(
        blocklist_path: PathBuf,
        interval_secs: u64,
        blocklist: Arc<Mutex<HashSet<String>>>,
    ) {
        use reqwest;
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
        loop {
            // Read blocklist.toml for URLs
            let urls = if let Ok(content) = std::fs::read_to_string(&blocklist_path) {
                content
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };
            let mut new_domains = HashSet::new();
            for url in urls {
                match reqwest::get(&url).await {
                    Ok(resp) => {
                        if let Ok(text) = resp.text().await {
                            for line in text.lines() {
                                let domain = line.trim();
                                if !domain.is_empty() && !domain.starts_with('#') {
                                    new_domains.insert(domain.to_string());
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("[blocklist] Failed to fetch {}: {}", url, e),
                }
            }
            // Atomically replace the in-memory blocklist
            {
                let mut guard = blocklist.lock().unwrap();
                *guard = new_domains;
                println!("[blocklist] Updated in-memory blocklist");
            }
            tokio::select! {
                _ = time::sleep(Duration::from_secs(interval_secs)) => {},
                _ = sighup.recv() => {
                    println!("[blocklist] Received SIGHUP, reloading blocklist immediately");
                }
            }
        }
    }
}
