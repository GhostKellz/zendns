use tokio_rustls::TlsAcceptor;
use tokio::net::TcpListener;
use crate::blocklist::Blocklist;
use crate::resolver::DnsCache;
use trust_dns_proto::op::Message;
use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::{Duration, Instant};

pub async fn run_dot_server(blocklist: Arc<Blocklist>, cache: Arc<DnsCache>) {
    println!("DoT server running (async)");
    // Load TLS certificate and key (replace with your own paths)
    let certs = load_certs("cert.pem");
    let key = load_private_key("key.pem");
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("bad certs/key");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("0.0.0.0:853").await.expect("Failed to bind TCP socket");
    loop {
        let (stream, _addr) = listener.accept().await.expect("accept failed");
        let acceptor = acceptor.clone();
        let blocklist = blocklist.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                let mut buf = [0u8; 512];
                if let Ok(size) = tls_stream.read(&mut buf).await {
                    let query_bytes = &buf[..size];
                    // Parse DNS query
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
                        // 3. Forward to upstream DNS server (UDP for now)
                        use tokio::net::UdpSocket as TokioUdpSocket;
                        let upstream_addr = "8.8.8.8:53";
                        let upstream_socket = TokioUdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind upstream socket");
                        upstream_socket.send_to(query_bytes, upstream_addr).await.ok();
                        let mut upstream_buf = [0u8; 512];
                        if let Ok((up_size, _)) = upstream_socket.recv_from(&mut upstream_buf).await {
                            let response = upstream_buf[..up_size].to_vec();
                            // 4. Cache response with TTL (e.g., 60s)
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

fn load_certs(_path: &str) -> Vec<Certificate> {
    // TODO: Load certificates from file
    vec![]
}

fn load_private_key(_path: &str) -> PrivateKey {
    // TODO: Load private key from file
    PrivateKey(vec![])
}
