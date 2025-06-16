use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;

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
            } else if let Ok(file) = File::open(src) {
                let reader = BufReader::new(file);
                for domain in reader.lines().map_while(Result::ok) {
                    let domain = domain.trim();
                    if !domain.is_empty() && !domain.starts_with('#') {
                        domains.insert(domain.to_string());
                    }
                }
            }
        }
        Blocklist {
            domains: Arc::new(Mutex::new(domains)),
        }
    }

    /// Checks if a domain is blocked
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.domains.lock().unwrap().contains(domain)
    }

    /// Periodically updates blocklist from the original sources
    pub async fn periodic_update(&self, sources: Vec<String>) {
        let interval_secs = 3600; // Update every hour

        loop {
            println!(
                "[blocklist] Periodic update check - refreshing from {} sources",
                sources.len()
            );

            let mut new_domains = HashSet::new();
            for src in &sources {
                if src.starts_with("http://") || src.starts_with("https://") {
                    match reqwest::get(src).await {
                        Ok(resp) => {
                            if let Ok(text) = resp.text().await {
                                for line in text.lines() {
                                    let domain = line.trim();
                                    if !domain.is_empty() && !domain.starts_with('#') {
                                        new_domains.insert(domain.to_string());
                                    }
                                }
                                println!("[blocklist] Updated from URL: {}", src);
                            }
                        }
                        Err(e) => eprintln!("[blocklist] Failed to fetch {}: {}", src, e),
                    }
                } else if let Ok(file) = File::open(src) {
                    let reader = BufReader::new(file);
                    for domain in reader.lines().map_while(Result::ok) {
                        let domain = domain.trim();
                        if !domain.is_empty() && !domain.starts_with('#') {
                            new_domains.insert(domain.to_string());
                        }
                    }
                    println!("[blocklist] Updated from file: {}", src);
                }
            }

            // Atomically replace the in-memory blocklist
            {
                let mut guard = self.domains.lock().unwrap();
                *guard = new_domains;
                println!("[blocklist] Updated in-memory blocklist with fresh data");
            }

            time::sleep(Duration::from_secs(interval_secs)).await;
        }
    }
}
