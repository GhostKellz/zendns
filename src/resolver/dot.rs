use tokio_rustls::TlsAcceptor;
use tokio::net::TcpListener;
use crate::blocklist::Blocklist;
use crate::resolver::DnsCache;
use crate::resolver::DnssecValidator;
use crate::config::Config;
use trust_dns_proto::op::Message;
use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::BufReader;

pub async fn run_dot_server(blocklist: Arc<Blocklist>, cache: Arc<DnsCache>, dnssec: Arc<DnssecValidator>, config: &Config) {
    let default_dot_addr = "0.0.0.0:853".to_string();
    let dot_addr = config.dot_listen_addr.as_ref().unwrap_or(&default_dot_addr);
    println!("DoT server running on {}", dot_addr);
    
    // Load TLS certificates from config
    let certs = load_certs(config.tls_cert.as_ref().expect("TLS cert required for DoT"));
    let key = load_private_key(config.tls_key.as_ref().expect("TLS key required for DoT"));
    
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to configure TLS");
    
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(dot_addr).await.expect("Failed to bind DoT listener");
    
    loop {
        let (stream, _addr) = listener.accept().await.expect("Failed to accept connection");
        let acceptor = acceptor.clone();
        let blocklist = blocklist.clone();
        let cache = cache.clone();
        let dnssec = dnssec.clone();
        let upstream_addr = config.upstream_addr.clone();
        
        tokio::spawn(async move {
            if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                let mut buf = [0u8; 512];
                if let Ok(size) = tls_stream.read(&mut buf).await {
                    let query_bytes = &buf[..size];
                    if let Ok(message) = Message::from_vec(query_bytes) {
                        let domain = message.queries().get(0).map(|q| q.name().to_ascii()).unwrap_or_default();
                        
                        // 1. Check cache with TTL
                        if let Some((response, expiry)) = cache.get(&domain).map(|v| v.value().clone()) {
                            if Instant::now() < expiry {
                                tls_stream.write_all(&response).await.ok();
                                return;
                            } else {
                                cache.remove(&domain);
                            }
                        }
                        
                        // 2. Check blocklist
                        if blocklist.is_blocked(&domain) {
                            let response = b"Blocked".to_vec();
                            tls_stream.write_all(&response).await.ok();
                            return;
                        }
                        
                        // 3. Forward to upstream DNS server
                        use tokio::net::UdpSocket as TokioUdpSocket;
                        let upstream_socket = TokioUdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind upstream socket");
                        upstream_socket.send_to(query_bytes, &upstream_addr).await.ok();
                        let mut upstream_buf = [0u8; 512];
                        if let Ok((up_size, _)) = upstream_socket.recv_from(&mut upstream_buf).await {
                            let response = upstream_buf[..up_size].to_vec();
                            
                            // 4. DNSSEC validation using async validator
                            if let Some(query) = message.queries().get(0) {
                                if !dnssec.validate_async(&domain, query.query_type()).await {
                                    // DNSSEC validation failed
                                    return;
                                }
                            }
                            
                            // 5. Cache response with TTL (e.g., 60s)
                            let expiry = Instant::now() + Duration::from_secs(60);
                            cache.insert(domain.clone(), (response.clone(), expiry));
                            tls_stream.write_all(&response).await.ok();
                        }
                    }
                }
            }
        });
    }
}

fn load_certs(path: &std::path::Path) -> Vec<Certificate> {
    let certfile = File::open(path).expect("Cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| Certificate(v.clone()))
        .collect()
}

fn load_private_key(path: &std::path::Path) -> PrivateKey {
    let keyfile = File::open(path).expect("Cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader).unwrap();
    assert!(!keys.is_empty(), "No private keys found");
    PrivateKey(keys[0].clone())
}
