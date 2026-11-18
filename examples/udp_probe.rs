// Device smoke test: use a private reality JSON config, never print credentials.
use reality::{parse_key, parse_short_id, parse_uuid, Config, UdpTunnel};
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if std::env::args().nth(1).as_deref() == Some("--stun") {
        return stun();
    }
    let path = std::env::args().nth(1).ok_or("config path required")?;
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let get = |key: &str| -> &str { value[key].as_str().unwrap_or("") };
    let cfg = Config {
        server_name: get("sni").to_string(),
        public_key: parse_key(get("pbk"))?,
        short_id: parse_short_id(get("sid"))?,
    };
    let tunnel = UdpTunnel::dial(get("server"), &cfg, parse_uuid(get("uuid"))?, "1.1.1.1", 53)?;
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x03www\x06google\x03com\x00\x00\x01\x00\x01");
    for _ in 0..3 {
        tunnel.send(&query)?;
        let reply = tunnel.recv()?;
        if reply.len() < 12
            || reply[..2] != query[..2]
            || reply[3] & 15 != 0
            || reply[6..8] == [0, 0]
        {
            return Err("invalid DNS UDP reply".into());
        }
        println!(
            "VLESS UDP DNS reply: {} bytes, {} answers",
            reply.len(),
            u16::from_be_bytes([reply[6], reply[7]])
        );
    }
    tunnel.shutdown();
    Ok(())
}

fn stun() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::net::{ToSocketAddrs, UdpSocket};
    use std::time::Duration;
    let destination = "stun.l.google.com:19302"
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .ok_or("no STUN IPv4")?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    let mut query = [0u8; 20];
    query[1] = 1;
    query[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    getrandom::getrandom(&mut query[8..]).map_err(|e| e.to_string())?;
    for _ in 0..3 {
        socket.send_to(&query, destination)?;
        let mut response = [0u8; 2048];
        let (len, source) = socket.recv_from(&mut response)?;
        if len < 20
            || source != destination
            || response[..2] != [1, 1]
            || response[4..20] != query[4..20]
        {
            return Err("invalid STUN reply".into());
        }
        let mut offset = 20;
        let mut mapped = None;
        while offset + 4 <= len {
            let kind = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let size = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            offset += 4;
            if offset + size > len {
                return Err("truncated STUN attribute".into());
            }
            if kind == 0x20 && size == 8 && response[offset + 1] == 1 {
                mapped = Some(std::net::Ipv4Addr::new(
                    response[offset + 4] ^ 0x21,
                    response[offset + 5] ^ 0x12,
                    response[offset + 6] ^ 0xa4,
                    response[offset + 7] ^ 0x42,
                ));
            }
            offset += (size + 3) & !3;
        }
        println!(
            "Transparent UDP STUN reply: {len} bytes, mapped IP {}",
            mapped.ok_or("missing STUN address")?
        );
    }
    Ok(())
}
