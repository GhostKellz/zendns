use tokio::net::UdpSocket;
use crate::blocklist::Blocklist;
use crate::resolver::DnsCache;
use crate::resolver::DnssecValidator;
use crate::config::Config;
use trust_dns_proto::op::Message;
use std::time::{Duration, Instant};
use std::sync::Arc;

pub async fn run_udp_server(blocklist: Arc<Blocklist>, cache: Arc<DnsCache>, dnssec: Arc<DnssecValidator>, config: &Config) {
    println!("UDP DNS server running on {}", config.listen_addr);
    let socket = UdpSocket::bind(&config.listen_addr).await.expect("Failed to bind UDP socket");
    let mut buf = [0u8; 512];
    loop {
        if let Ok((size, src)) = socket.recv_from(&mut buf).await {
            let query_bytes = &buf[..size];
            if let Ok(message) = Message::from_vec(query_bytes) {
                let domain = message.queries().get(0).map(|q| q.name().to_ascii()).unwrap_or_default();
                // 1. Check cache with TTL
                if let Some((response, expiry)) = cache.get(&domain).map(|v| v.value().clone()) {
                    if Instant::now() < expiry {
                        socket.send_to(&response, &src).await.ok();
                        continue;
                    } else {
                        cache.remove(&domain);
                    }
                }
                // 2. Check blocklist
                if blocklist.is_blocked(&domain) {
                    use trust_dns_proto::op::{Message, ResponseCode};
                    let mut response = Message::new();
                    response.set_id(message.id());
                    response.set_message_type(trust_dns_proto::op::MessageType::Response);
                    response.set_op_code(message.op_code());
                    response.set_response_code(ResponseCode::Refused);
                    response.add_queries(message.queries().to_vec());
                    let response_bytes = response.to_vec().unwrap_or_else(|_| b"".to_vec());
                    socket.send_to(&response_bytes, &src).await.ok();
                    continue;
                }
                // 3. Forward to upstream DNS server
                let upstream_socket = UdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind upstream socket");
                upstream_socket.send_to(query_bytes, &config.upstream_addr).await.ok();
                let mut upstream_buf = [0u8; 512];
                if let Ok((up_size, _)) = upstream_socket.recv_from(&mut upstream_buf).await {
                    let response = upstream_buf[..up_size].to_vec();
                    // 4. DNSSEC validation using async validator
                    if let Some(query) = message.queries().get(0) {
                        if !dnssec.validate_async(&domain, query.query_type()).await {
                            // DNSSEC validation failed
                            continue;
                        }
                    }
                    // 5. Cache response with TTL (e.g., 60s)
                    let expiry = Instant::now() + Duration::from_secs(60);
                    cache.insert(domain.clone(), (response.clone(), expiry));
                    socket.send_to(&response, &src).await.ok();
                }
            }
        }
    }
}
