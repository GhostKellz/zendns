use dashmap::DashMap;
use std::sync::Arc;
use std::fs;
use std::path::PathBuf;
use std::collections::HashSet;
use std::time::Instant;
use reqwest;
use crate::blocklist::Blocklist;
use crate::config::Config;

pub mod udp;
pub mod dot;
pub mod doh;

// DnsCache is just the DashMap, not Arc
pub type DnsCache = DashMap<String, (Vec<u8>, Instant)>;

pub fn start(config: &Config, blocklist: &Blocklist) {
    let cache: Arc<DnsCache> = Arc::new(DashMap::new());
    let blocklist_arc: Arc<Blocklist> = Arc::new(blocklist.clone());
    println!("Starting DNS resolver...");

    let enable_udp = config.enable_udp.unwrap_or(true); // default true
    let enable_dot = config.enable_dot.unwrap_or(false);
    let enable_doh = config.enable_doh.unwrap_or(false);

    if enable_udp {
        tokio::spawn(udp::run_udp_server(blocklist_arc.clone(), cache.clone()));
    }
    if enable_dot {
        tokio::spawn(dot::run_dot_server(blocklist_arc.clone(), cache.clone()));
    }
    if enable_doh {
        tokio::spawn(doh::run_doh_server(blocklist_arc.clone(), cache.clone()));
    }
}

// DNSSEC validator stub
pub struct DnssecValidator {
    trust_anchors: HashSet<String>, // Store trust anchor keys as strings for now
    root_hints_path: PathBuf,
}

impl DnssecValidator {
    pub fn new() -> Self {
        // Load trust anchors from ~/.config/zendns/root.key
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        let root_key_path = home.join(".config/zendns/root.key");
        let root_hints_path = home.join(".config/zendns/root.hints");
        let trust_anchors = Self::load_trust_anchors(&root_key_path);
        DnssecValidator { trust_anchors, root_hints_path }
    }

    fn load_trust_anchors(path: &PathBuf) -> HashSet<String> {
        let mut anchors = HashSet::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    anchors.insert(line.to_string());
                }
            }
        }
        anchors
    }

    pub async fn update_root_hints(&self) {
        // Download root hints file (e.g., https://www.internic.net/domain/named.root)
        let url = "https://www.internic.net/domain/named.root";
        match reqwest::get(url).await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    if let Err(e) = fs::write(&self.root_hints_path, &text) {
                        eprintln!("Failed to write root hints: {}", e);
                    } else {
                        println!("Updated root hints at {:?}", &self.root_hints_path);
                    }
                }
            }
            Err(e) => eprintln!("Failed to download root hints: {}", e),
        }
    }

    pub fn validate(&self, response: &[u8]) -> bool {
        use trust_dns_proto::op::Message;
        use trust_dns_proto::rr::{RecordType, RData};
   //     use trust_dns_proto::serialize::binary::BinDecodable;
        let message = match Message::from_vec(response) {
            Ok(m) => m,
            Err(_) => return false,
        };
        // Check for RRSIG in DNSSEC
        let has_rrsig = message.answers().iter().any(|rr| {
            match rr.data() {
                Some(RData::DNSSEC(dnssec)) => matches!(dnssec, trust_dns_proto::rr::dnssec::rdata::DNSSECRData::RRSIG(_)),
                _ => false,
            }
        });
        let has_dnskey = message.answers().iter().any(|rr| rr.record_type() == RecordType::DNSKEY);
        if !has_rrsig || !has_dnskey {
            return false;
        }
        true
    }

    pub async fn validate_async(&self, domain: &str, record_type: trust_dns_resolver::proto::rr::RecordType) -> bool {
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
        // Create a resolver with DNSSEC enabled
        let mut opts = ResolverOpts::default();
        opts.validate = true; // Enable DNSSEC validation
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        // Perform a lookup with DNSSEC
        match resolver.lookup(domain, record_type).await {
            Ok(_lookup) => true,
            Err(_) => false,
        }   
    }
}
