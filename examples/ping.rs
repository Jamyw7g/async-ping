use std::time::Duration;

use async_ping::packet::IcmpPacket;
use async_ping::ping::Pinger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = std::env::args().skip(1).next().unwrap();
    let pinger = Pinger::new(format!("{}:0", domain))?;

    for seq in 0..16 {
        let (p, d) = match pinger.ping(seq, None).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("{}", e);
                continue;
            }
        };
        match p {
            IcmpPacket::V4(p) => {
                println!(
                    "{} bytes from {}: icmp_seq={} ttl={} time={} ms",
                    p.size,
                    p.source,
                    p.sequence,
                    p.ttl,
                    d.as_millis()
                );
            }
            IcmpPacket::V6(p) => {
                let hlim = if let Some(hlim) = p.hop_limit {
                    hlim as i32
                } else {
                    -1
                };
                println!(
                    "{} bytes from {}: icmp_seq={} hlim={} time={} ms",
                    p.size,
                    p.source,
                    p.sequence,
                    hlim,
                    d.as_millis()
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}
