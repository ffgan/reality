//! VLESS + REALITY + xtls-rprx-vision client.
//!
//! The handshake matches Xray 26.11.9: the ClientHello carries an
//! X25519MLKEM768 share, and the session id is an AES-256-GCM seal of the
//! version, time, and short id. After Vision switches both directions to raw
//! inner bytes, the proxy splices the two sockets through io_uring.

mod proxy;
mod tls;
mod transparent;
mod tunnel;
mod udp;

use std::error::Error;
use std::fmt;

pub use proxy::{serve_listener, Endpoint};
pub use transparent::serve_transparent;
pub use tunnel::{ReadOut, Tunnel};
pub use udp::UdpTunnel;

pub const XRAY_VERSION: [u8; 3] = [26, 11, 9];

#[derive(Debug)]
pub struct ProtoError(pub String);

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ProtoError {}

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub(crate) fn err(msg: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(ProtoError(msg.into()))
}

#[derive(Clone)]
pub struct Config {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
}

pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex = s.replace('-', "");
    let raw = decode_hex(&hex)?;
    if raw.len() != 16 {
        return Err(err("uuid must be 16 bytes"));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&raw);
    Ok(id)
}

pub fn parse_key(s: &str) -> Result<[u8; 32]> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    for engine in [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD] {
        if let Ok(raw) = engine.decode(s) {
            if raw.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw);
                return Ok(key);
            }
        }
    }
    Err(err("public key must be 32 bytes of base64"))
}

pub fn parse_short_id(s: &str) -> Result<[u8; 8]> {
    let mut out = [0u8; 8];
    if s.is_empty() {
        return Ok(out);
    }
    let raw = decode_hex(s)?;
    if raw.len() > 8 {
        return Err(err("short id must be hex and at most 8 bytes"));
    }
    out[..raw.len()].copy_from_slice(&raw);
    Ok(out)
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(err("odd hex length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;

    #[test]
    fn parses_uuid_key_and_short_id() {
        let dashed = parse_uuid("00000000-0000-0000-0000-000000000042").unwrap();
        let plain = parse_uuid("00000000000000000000000000000042").unwrap();
        assert_eq!(dashed, plain);
        assert_eq!(plain[15], 0x42);
        assert!(parse_uuid("zz").is_err());
        assert!(parse_uuid("aa").is_err());

        let raw = [0x11u8; 32];
        for encoded in [
            URL_SAFE_NO_PAD.encode(raw),
            URL_SAFE.encode(raw),
            STANDARD_NO_PAD.encode(raw),
            STANDARD.encode(raw),
        ] {
            assert_eq!(parse_key(&encoded).unwrap(), raw);
        }
        assert!(parse_key("aaaa").is_err());

        assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
        let mut one = [0u8; 8];
        one[0] = 0xab;
        assert_eq!(parse_short_id("ab").unwrap(), one);
        assert_eq!(parse_short_id("0123456789abcdef").unwrap(), hex_id());
        assert!(parse_short_id("0123456789abcdef00").is_err());
        assert!(parse_short_id("zz").is_err());
    }

    fn hex_id() -> [u8; 8] {
        let mut out = [0u8; 8];
        out.copy_from_slice(&decode_hex("0123456789abcdef").unwrap());
        out
    }
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(err("invalid hex")),
    }
}

/// Bytes moved by io_uring splice since process start.
pub fn spliced_bytes() -> u64 {
    proxy::spliced_bytes()
}
