use crate::blocklist::Blocklist;
use crate::resolver::DnsCache;
use crate::resolver::DnssecValidator;
use crate::config::Config;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};
use trust_dns_proto::op::Message;

pub async fn run_doh_server(blocklist: Arc<Blocklist>, cache: Arc<DnsCache>, dnssec: Arc<DnssecValidator>, config: &Config) {
    let default_doh_addr = "0.0.0.0:8443".to_string();
    let doh_addr = config.doh_listen_addr.as_ref().unwrap_or(&default_doh_addr);
    println!("DoH server running on {}", doh_addr);
    let upstream_addr = config.upstream_addr.clone();
    
    let make_svc = make_service_fn(move |_conn| {
        let blocklist = blocklist.clone();
        let cache = cache.clone();
        let dnssec = dnssec.clone();
        let upstream_addr = upstream_addr.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let blocklist = blocklist.clone();
                let cache = cache.clone();
                let dnssec = dnssec.clone();
                let upstream_addr = upstream_addr.clone();
                async move {
                    let whole_body = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                    let query_bytes = &whole_body;
                    if let Ok(message) = Message::from_vec(query_bytes) {
                        let domain = message.queries().get(0).map(|q| q.name().to_ascii()).unwrap_or_default();
                        // 1. Check cache with TTL
                        if let Some((response, expiry)) = cache.get(&domain).map(|v| v.value().clone()) {
                            if Instant::now() < expiry {
                                return Ok::<_, Infallible>(Response::new(Body::from(response)));
                            } else {
                                cache.remove(&domain);
                            }
                        }
                        // 2. Check blocklist
                        if blocklist.is_blocked(&domain) {
                            let response = b"Blocked".to_vec();
                            return Ok::<_, Infallible>(Response::new(Body::from(response)));
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
                                    return Ok::<_, Infallible>(Response::new(Body::from("DNSSEC validation failed")));
                                }
                            }
                            // 5. Cache response with TTL (e.g., 60s)
                            let expiry = Instant::now() + Duration::from_secs(60);
                            cache.insert(domain.clone(), (response.clone(), expiry));
                            return Ok::<_, Infallible>(Response::new(Body::from(response)));
                        }
                    }
                    // If parsing fails or no response, return empty
                    Ok::<_, Infallible>(Response::new(Body::from("")))
                }
            }))
        }
    });
    
    let addr = doh_addr.parse().expect("Invalid DoH listen address");
    
    // DoH typically runs over HTTPS, so we should use TLS if certificates are provided
    if config.tls_cert.is_some() && config.tls_key.is_some() {
        // For now, we'll use HTTP. In production, you'd want HTTPS with proper TLS setup
        println!("Note: DoH server running over HTTP. For production, configure HTTPS with TLS.");
    }
    
    let server = Server::bind(&addr).serve(make_svc);
    if let Err(e) = server.await {
        eprintln!("DoH server error: {}", e);
    }
}
