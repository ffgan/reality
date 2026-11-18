//! TLS 1.3 client that seals the REALITY session id before the transcript hash.
//!
//! Xray's REALITY server requires an X25519MLKEM768 key share. Authentication
//! uses only the X25519 half: HKDF-SHA256 of ECDH(client, server static), salt
//! `random[:20]`, info `REALITY`. The TLS handshake secret is separate. When
//! the peer selects X25519MLKEM768 it is ML-KEM-768 || X25519 (64 bytes).

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::task::{Context, Poll, Waker};

use aes_gcm::aead::{Aead, AeadInOut, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{err, Config, Result, XRAY_VERSION};

const AES_128_GCM_SHA256: u16 = 0x1301;
const X25519MLKEM768: u16 = 0x11ec;
const X25519: u16 = 0x001d;
const MLKEM_EK: usize = 1184;
const MLKEM_CT: usize = 1088;

pub struct Traffic {
    cipher: Aes128Gcm,
    iv: [u8; 12],
    seq: u64,
}

pub struct Session {
    pub read: Traffic,
    pub write: Traffic,
}

pub(crate) trait Transport {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()>;
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;

    async fn read_body(&mut self, len: usize) -> std::io::Result<Vec<u8>> {
        let mut body = vec![0; len];
        self.read_exact(&mut body).await?;
        Ok(body)
    }

    async fn write_record(&mut self, record: Vec<u8>) -> std::io::Result<()> {
        self.write_all(&record).await
    }
}

pub(crate) struct BlockingTransport<'a>(pub(crate) &'a mut TcpStream);

impl Transport for BlockingTransport<'_> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.0.read_exact(buf)
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_all(buf)
    }
}

// Only used with BlockingTransport, whose operations finish in the first poll.
pub(crate) fn run_blocking<T>(operation: impl Future<Output = Result<T>>) -> Result<T> {
    let mut operation = std::pin::pin!(operation);
    match operation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => unreachable!("blocking TLS transport yielded"),
    }
}

pub fn handshake(stream: &mut TcpStream, cfg: &Config) -> Result<Session> {
    run_blocking(handshake_async(&mut BlockingTransport(stream), cfg))
}

pub(crate) async fn handshake_async(stream: &mut impl Transport, cfg: &Config) -> Result<Session> {
    let mut rng = OsRng;
    let x25519 = StaticSecret::random_from_rng(&mut rng);
    let xpub = PublicKey::from(&x25519);
    let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut rng);
    let ek_bytes = mlkem_ek.as_bytes();
    if ek_bytes.as_slice().len() != MLKEM_EK {
        return Err(err(format!(
            "REALITY: unexpected ML-KEM encapsulation key length {}",
            ek_bytes.len()
        )));
    }

    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let mut hello = build_client_hello(
        &random,
        &cfg.server_name,
        ek_bytes.as_slice(),
        xpub.as_bytes(),
    );
    if hello.len() < 39 + 32 || hello[38] != 32 {
        return Err(err("REALITY: client hello has no 32-byte session id"));
    }

    let server_static = PublicKey::from(cfg.public_key);
    let auth_shared = x25519.diffie_hellman(&server_static);
    let auth_key = hkdf_key(auth_shared.as_bytes(), &random[..20], b"REALITY", 32);
    seal_session_id(&mut hello, &auth_key, &random, &cfg.short_id)?;

    let record = wrap_record(0x16, 0x0301, &hello);
    stream.write_record(record).await?;

    let server_hello = read_handshake_message(stream).await?;
    if server_hello.first().copied() != Some(2) {
        return Err(err("REALITY: expected ServerHello"));
    }
    let parsed = parse_server_hello(&server_hello)?;
    if parsed.cipher != AES_128_GCM_SHA256 {
        return Err(err(format!(
            "REALITY: unsupported cipher suite {:#06x}",
            parsed.cipher
        )));
    }

    let mut transcript = Sha256::new();
    transcript.update(&hello);
    transcript.update(&server_hello);

    let shared = tls_shared_secret(&x25519, &mlkem_dk, parsed.group, &parsed.share)?;
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived = expand_label(&early, "derived", &sum(&Sha256::new()), 32);
    let handshake_secret = hkdf_extract(&derived, &shared);
    let client_hs = derive_secret(&handshake_secret, "c hs traffic", &transcript);
    let server_hs = derive_secret(&handshake_secret, "s hs traffic", &transcript);
    let mut read_keys = traffic_keys(&server_hs);
    let mut write_keys = traffic_keys(&client_hs);

    let mut hs_buf = Vec::new();
    let mut verified = false;
    let mut leaf_key = None;
    let mut saw_finished = false;
    while !saw_finished {
        let Some(msg) = take_message(&mut hs_buf) else {
            let (typ, content) = read_inner(stream, &mut read_keys).await?;
            if typ == 0x15 {
                let desc = content.get(1).copied().unwrap_or(0);
                return Err(err(format!("REALITY: alert {desc}")));
            }
            if typ != 0x16 {
                return Err(err(format!("REALITY: unexpected inner type {typ}")));
            }
            hs_buf.extend_from_slice(&content);
            continue;
        };
        let kind = msg[0];
        match kind {
            8 => transcript.update(&msg),
            11 => {
                verify_reality_cert(&msg, &auth_key)?;
                leaf_key = Some(leaf_ed25519(&msg)?);
                verified = true;
                transcript.update(&msg);
            }
            15 => {
                let pk = leaf_key
                    .ok_or_else(|| err("REALITY: CertificateVerify without certificate"))?;
                check_cert_verify(&msg, &transcript, &pk)?;
                transcript.update(&msg);
            }
            20 => {
                let expect = finished_verify(&server_hs, &transcript);
                let got = &msg[4..];
                if got != expect.as_slice() {
                    return Err(err("REALITY: server Finished mismatch"));
                }
                transcript.update(&msg);
                saw_finished = true;
            }
            _ => transcript.update(&msg),
        }
    }
    if !verified {
        return Err(err("REALITY: processed invalid connection"));
    }

    let derived_hs = expand_label(&handshake_secret, "derived", &sum(&Sha256::new()), 32);
    let master = hkdf_extract(&derived_hs, &[0u8; 32]);
    let client_ap = derive_secret(&master, "c ap traffic", &transcript);
    let server_ap = derive_secret(&master, "s ap traffic", &transcript);

    let verify = finished_verify(&client_hs, &transcript);
    let mut fin = Vec::with_capacity(4 + verify.len());
    fin.push(20);
    put_u24(&mut fin, verify.len());
    fin.extend_from_slice(&verify);
    let record = seal_record(&mut write_keys, 0x16, &fin)?;
    stream.write_record(record).await?;

    Ok(Session {
        read: traffic_keys(&server_ap),
        write: traffic_keys(&client_ap),
    })
}

pub fn write_app(stream: &mut TcpStream, traffic: &mut Traffic, data: &[u8]) -> Result<()> {
    run_blocking(write_app_async(
        &mut BlockingTransport(stream),
        traffic,
        data,
    ))
}

pub(crate) async fn write_app_async(
    stream: &mut impl Transport,
    traffic: &mut Traffic,
    data: &[u8],
) -> Result<()> {
    const RECORD_PAYLOAD: usize = 16 * 1024;
    for batch in data.chunks(4 * RECORD_PAYLOAD) {
        let records = batch.len().div_ceil(RECORD_PAYLOAD);
        let mut ciphertext = Vec::with_capacity(batch.len() + records * 22);
        for payload in batch.chunks(RECORD_PAYLOAD) {
            append_record(&mut ciphertext, traffic, 0x17, payload)?;
        }
        stream.write_record(ciphertext).await?;
    }
    Ok(())
}

pub fn read_app(stream: &mut TcpStream, traffic: &mut Traffic) -> Result<Option<Vec<u8>>> {
    run_blocking(read_app_async(&mut BlockingTransport(stream), traffic))
}

pub(crate) async fn read_app_async(
    stream: &mut impl Transport,
    traffic: &mut Traffic,
) -> Result<Option<Vec<u8>>> {
    loop {
        let (typ, content) = read_inner(stream, traffic).await?;
        match typ {
            0x17 => {
                if content.is_empty() {
                    continue;
                }
                return Ok(Some(content));
            }
            0x16 => continue,
            0x15 => {
                let desc = content.get(1).copied().unwrap_or(0);
                if desc == 0 {
                    return Ok(None);
                }
                return Err(err(format!("REALITY: alert {desc}")));
            }
            other => return Err(err(format!("REALITY: unexpected record {other}"))),
        }
    }
}

fn tls_shared_secret(
    secret: &StaticSecret,
    dk: &<MlKem768 as KemCore>::DecapsulationKey,
    group: u16,
    share: &[u8],
) -> Result<Vec<u8>> {
    if group == X25519 {
        if share.len() != 32 {
            return Err(err("REALITY: bad X25519 share"));
        }
        let mut peer = [0u8; 32];
        peer.copy_from_slice(share);
        let shared = secret.diffie_hellman(&PublicKey::from(peer));
        return Ok(shared.as_bytes().to_vec());
    }
    if group != X25519MLKEM768 {
        return Err(err(format!("REALITY: unsupported group {group:#06x}")));
    }
    if share.len() != MLKEM_CT + 32 {
        return Err(err(format!(
            "REALITY: bad hybrid share length {}",
            share.len()
        )));
    }
    let ct = Ciphertext::<MlKem768>::try_from(&share[..MLKEM_CT])
        .map_err(|_| err("REALITY: bad ML-KEM ciphertext"))?;
    let mlkem_ss = dk
        .decapsulate(&ct)
        .map_err(|_| err("REALITY: ML-KEM decapsulation failed"))?;
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&share[MLKEM_CT..]);
    let x_ss = secret.diffie_hellman(&PublicKey::from(peer));
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(mlkem_ss.as_slice());
    out.extend_from_slice(x_ss.as_bytes());
    Ok(out)
}

fn seal_session_id(
    hello: &mut [u8],
    auth_key: &[u8],
    random: &[u8],
    short_id: &[u8; 8],
) -> Result<()> {
    let mut plain = [0u8; 16];
    plain[0] = XRAY_VERSION[0];
    plain[1] = XRAY_VERSION[1];
    plain[2] = XRAY_VERSION[2];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| err("clock"))?
        .as_secs() as u32;
    plain[4..8].copy_from_slice(&now.to_be_bytes());
    plain[8..16].copy_from_slice(short_id);
    let cipher = Aes256Gcm::new_from_slice(auth_key).map_err(|_| err("REALITY: bad auth key"))?;
    let ct = cipher
        .encrypt(
            &Nonce::try_from(&random[20..]).expect("fixed nonce length"),
            Payload {
                msg: &plain,
                aad: hello,
            },
        )
        .map_err(|_| err("REALITY: seal failed"))?;
    if ct.len() != 32 {
        return Err(err("REALITY: unexpected seal length"));
    }
    hello[39..71].copy_from_slice(&ct);
    Ok(())
}

fn verify_reality_cert(msg: &[u8], auth_key: &[u8]) -> Result<()> {
    let der = first_certificate(msg)?;
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| err(format!("REALITY: certificate: {e}")))?;
    let oid = cert.public_key().algorithm.algorithm.to_string();
    if oid != "1.3.101.112" {
        return Err(err("REALITY: processed invalid connection"));
    }
    let pk = cert.public_key().subject_public_key.data.as_ref();
    let sig = cert.signature_value.data.as_ref();
    if pk.len() != 32 || sig.len() != 64 {
        return Err(err("REALITY: processed invalid connection"));
    }
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(auth_key).map_err(|_| err("REALITY: hmac"))?;
    mac.update(pk);
    let got = mac.finalize().into_bytes();
    if got.as_slice() != sig {
        return Err(err("REALITY: processed invalid connection"));
    }
    Ok(())
}

fn first_certificate(msg: &[u8]) -> Result<&[u8]> {
    // Certificate: type + u24 len + u8 context_len + context + u24 list + entry.
    if msg.len() < 4 {
        return Err(err("REALITY: short certificate"));
    }
    let mut i = 4;
    if i >= msg.len() {
        return Err(err("REALITY: short certificate"));
    }
    let ctx = msg[i] as usize;
    i += 1 + ctx;
    if i + 3 > msg.len() {
        return Err(err("REALITY: short certificate"));
    }
    i += 3;
    if i + 3 > msg.len() {
        return Err(err("REALITY: short certificate"));
    }
    let cert_len = be24(&msg[i..]);
    i += 3;
    if i + cert_len > msg.len() {
        return Err(err("REALITY: short certificate"));
    }
    Ok(&msg[i..i + cert_len])
}

struct ServerHello {
    cipher: u16,
    group: u16,
    share: Vec<u8>,
}

fn parse_server_hello(msg: &[u8]) -> Result<ServerHello> {
    if msg.len() < 4 + 2 + 32 + 1 {
        return Err(err("REALITY: short ServerHello"));
    }
    let body = &msg[4..];
    let mut i = 2 + 32;
    let sid_len = body[i] as usize;
    i += 1;
    if i + sid_len + 3 > body.len() {
        return Err(err("REALITY: short ServerHello"));
    }
    i += sid_len;
    let cipher = u16::from_be_bytes([body[i], body[i + 1]]);
    i += 2;
    i += 1;
    if i + 2 > body.len() {
        return Err(err("REALITY: short ServerHello"));
    }
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if i + ext_len > body.len() {
        return Err(err("REALITY: short ServerHello"));
    }
    let end = i + ext_len;
    let mut group = None;
    let mut share = None;
    let mut version_ok = false;
    while i + 4 <= end {
        let et = u16::from_be_bytes([body[i], body[i + 1]]);
        let el = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if i + el > end {
            return Err(err("REALITY: bad ServerHello extension"));
        }
        let data = &body[i..i + el];
        if et == 43 && data == [0x03, 0x04] {
            version_ok = true;
        }
        if et == 51 && data.len() >= 4 {
            let g = u16::from_be_bytes([data[0], data[1]]);
            let kl = u16::from_be_bytes([data[2], data[3]]) as usize;
            if 4 + kl > data.len() {
                return Err(err("REALITY: bad key share"));
            }
            group = Some(g);
            share = Some(data[4..4 + kl].to_vec());
        }
        i += el;
    }
    if !version_ok {
        return Err(err("REALITY: server did not select TLS 1.3"));
    }
    let (Some(group), Some(share)) = (group, share) else {
        return Err(err("REALITY: server hello has no key share"));
    };
    Ok(ServerHello {
        cipher,
        group,
        share,
    })
}

fn build_client_hello(random: &[u8; 32], sni: &str, mlkem_ek: &[u8], xpub: &[u8; 32]) -> Vec<u8> {
    let mut exts = Vec::new();
    exts.extend(extension(0, &server_name(sni)));
    exts.extend(extension(10, &named_groups()));
    exts.extend(extension(13, &sig_algs()));
    exts.extend(extension(43, &[2, 0x03, 0x04]));
    exts.extend(extension(51, &key_shares(mlkem_ek, xpub)));

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&AES_128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(1);
    put_u24(&mut msg, body.len());
    msg.extend_from_slice(&body);
    msg
}

fn server_name(name: &str) -> Vec<u8> {
    let nb = name.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&((3 + nb.len()) as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(nb.len() as u16).to_be_bytes());
    body.extend_from_slice(nb);
    body
}

fn named_groups() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&X25519MLKEM768.to_be_bytes());
    body.extend_from_slice(&X25519.to_be_bytes());
    body
}

fn sig_algs() -> Vec<u8> {
    let algs: [u16; 4] = [0x0807, 0x0403, 0x0804, 0x0401];
    let mut body = Vec::new();
    body.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
    for a in algs {
        body.extend_from_slice(&a.to_be_bytes());
    }
    body
}

fn key_shares(mlkem_ek: &[u8], xpub: &[u8; 32]) -> Vec<u8> {
    let hybrid_len = mlkem_ek.len() + 32;
    let list_len = 4 + hybrid_len + 4 + 32;
    let mut body = Vec::new();
    body.extend_from_slice(&(list_len as u16).to_be_bytes());
    body.extend_from_slice(&X25519MLKEM768.to_be_bytes());
    body.extend_from_slice(&(hybrid_len as u16).to_be_bytes());
    body.extend_from_slice(mlkem_ek);
    body.extend_from_slice(xpub);
    body.extend_from_slice(&X25519.to_be_bytes());
    body.extend_from_slice(&32u16.to_be_bytes());
    body.extend_from_slice(xpub);
    body
}

fn extension(typ: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn wrap_record(typ: u8, version: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(typ);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn read_record(stream: &mut impl Transport) -> Result<(u8, [u8; 5], Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > 18_432 {
        return Err(err("REALITY: record too large"));
    }
    let body = stream.read_body(len).await?;
    Ok((hdr[0], hdr, body))
}

async fn read_handshake_message(stream: &mut impl Transport) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        if buf.len() >= 4 {
            let n = be24(&buf[1..]);
            if buf.len() >= 4 + n {
                if buf.len() != 4 + n {
                    return Err(err("REALITY: coalesced handshake before ServerHello"));
                }
                return Ok(buf);
            }
        }
        let (typ, _, body) = read_record(stream).await?;
        if typ == 0x15 {
            let desc = body.get(1).copied().unwrap_or(0);
            return Err(err(format!("REALITY: alert {desc}")));
        }
        if typ != 0x16 {
            return Err(err(format!("REALITY: expected handshake, got {typ}")));
        }
        buf.extend_from_slice(&body);
    }
}

async fn read_inner(stream: &mut impl Transport, traffic: &mut Traffic) -> Result<(u8, Vec<u8>)> {
    loop {
        let (typ, hdr, mut body) = read_record(stream).await?;
        if typ == 0x14 {
            continue;
        }
        if typ == 0x15 {
            let desc = body.get(1).copied().unwrap_or(0);
            return Err(err(format!("REALITY: alert {desc}")));
        }
        if typ != 0x17 {
            return Err(err(format!(
                "REALITY: expected application data, got {typ}"
            )));
        }
        let nonce = nonce_for(&traffic.iv, traffic.seq);
        traffic
            .cipher
            .decrypt_in_place(&Nonce::from(nonce), &hdr, &mut body)
            .map_err(|_| err("REALITY: decrypt failed"))?;
        traffic.seq += 1;
        return split_inner(body);
    }
}

fn seal_record(traffic: &mut Traffic, inner_type: u8, content: &[u8]) -> Result<Vec<u8>> {
    let mut record = Vec::with_capacity(content.len() + 22);
    append_record(&mut record, traffic, inner_type, content)?;
    Ok(record)
}

fn append_record(
    record: &mut Vec<u8>,
    traffic: &mut Traffic,
    kind: u8,
    content: &[u8],
) -> Result<()> {
    let ct_len = (content.len() + 17) as u16;
    let hdr = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
    record.extend_from_slice(&hdr);
    let start = record.len();
    record.extend_from_slice(content);
    record.push(kind);
    let nonce = nonce_for(&traffic.iv, traffic.seq);
    let tag = traffic
        .cipher
        .encrypt_inout_detached(&Nonce::from(nonce), &hdr, (&mut record[start..]).into())
        .map_err(|_| err("REALITY: encrypt failed"))?;
    traffic.seq += 1;
    record.extend_from_slice(&tag);
    Ok(())
}

fn split_inner(mut plaintext: Vec<u8>) -> Result<(u8, Vec<u8>)> {
    let position = plaintext
        .iter()
        .rposition(|&byte| byte != 0)
        .ok_or_else(|| err("REALITY: empty inner plaintext"))?;
    let kind = plaintext[position];
    plaintext.truncate(position);
    Ok((kind, plaintext))
}

fn nonce_for(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let s = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= s[i];
    }
    n
}

fn take_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 4 {
        return None;
    }
    let n = be24(&buf[1..]);
    if buf.len() < 4 + n {
        return None;
    }
    Some(buf.drain(..4 + n).collect())
}

fn be24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

fn put_u24(out: &mut Vec<u8>, n: usize) {
    out.push((n >> 16) as u8);
    out.push((n >> 8) as u8);
    out.push(n as u8);
}

fn sum(h: &Sha256) -> [u8; 32] {
    h.clone().finalize().into()
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("hmac");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk).expect("hmac");
        mac.update(&prev);
        mac.update(info);
        mac.update(&[counter]);
        prev = mac.finalize().into_bytes().to_vec();
        let take = (length - out.len()).min(prev.len());
        out.extend_from_slice(&prev[..take]);
        counter += 1;
    }
    out
}

fn hkdf_key(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

fn expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, length)
}

fn derive_secret(secret: &[u8], label: &str, transcript: &Sha256) -> Vec<u8> {
    expand_label(secret, label, &sum(transcript), 32)
}

fn traffic_keys(secret: &[u8]) -> Traffic {
    let key = expand_label(secret, "key", &[], 16);
    let iv = expand_label(secret, "iv", &[], 12);
    let mut k = [0u8; 16];
    let mut v = [0u8; 12];
    k.copy_from_slice(&key);
    v.copy_from_slice(&iv);
    Traffic {
        cipher: Aes128Gcm::new((&k).into()),
        iv: v,
        seq: 0,
    }
}

fn finished_verify(base: &[u8], transcript: &Sha256) -> Vec<u8> {
    let key = expand_label(base, "finished", &[], 32);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("hmac");
    mac.update(&sum(transcript));
    mac.finalize().into_bytes().to_vec()
}

fn leaf_ed25519(msg: &[u8]) -> Result<[u8; 32]> {
    let der = first_certificate(msg)?;
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| err(format!("REALITY: certificate: {e}")))?;
    let pk = cert.public_key().subject_public_key.data.as_ref();
    if pk.len() != 32 {
        return Err(err("REALITY: processed invalid connection"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(pk);
    Ok(out)
}

fn check_cert_verify(msg: &[u8], transcript: &Sha256, pk: &[u8; 32]) -> Result<()> {
    if msg.len() < 8 {
        return Err(err("REALITY: short CertificateVerify"));
    }
    let scheme = u16::from_be_bytes([msg[4], msg[5]]);
    let sig_len = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if scheme != 0x0807 || sig_len != 64 || msg.len() < 8 + sig_len {
        return Err(err("REALITY: CertificateVerify is not Ed25519"));
    }
    let mut sigb = [0u8; 64];
    sigb.copy_from_slice(&msg[8..8 + sig_len]);
    let key = VerifyingKey::from_bytes(pk).map_err(|_| err("REALITY: bad ed25519 key"))?;
    let sig = Signature::from_bytes(&sigb);
    let mut message = vec![0x20u8; 64];
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    message.extend_from_slice(&sum(transcript));
    key.verify(&message, &sig)
        .map_err(|_| err("REALITY: CertificateVerify failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_read_resumes_after_header_and_body_waits() {
        struct PendingRead<'a>(&'a [u8]);

        impl Transport for PendingRead<'_> {
            async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
                let mut pending = true;
                std::future::poll_fn(|cx| {
                    if std::mem::take(&mut pending) {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        Poll::Ready(self.0.read_exact(buf))
                    }
                })
                .await
            }

            async fn write_all(&mut self, _: &[u8]) -> std::io::Result<()> {
                unreachable!("record reader does not write")
            }
        }

        let record = wrap_record(0x16, 0x0303, b"hello");
        let mut transport = PendingRead(&record);
        let mut read = std::pin::pin!(read_record(&mut transport));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(read.as_mut().poll(&mut cx).is_pending());
        assert!(read.as_mut().poll(&mut cx).is_pending());
        let Poll::Ready(Ok((kind, _, body))) = read.as_mut().poll(&mut cx) else {
            panic!("record did not finish");
        };
        assert_eq!(kind, 0x16);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn hello_carries_hybrid_share() {
        let random = [7u8; 32];
        let ek = vec![1u8; MLKEM_EK];
        let xpub = [2u8; 32];
        let hello = build_client_hello(&random, "www.example.com", &ek, &xpub);
        assert_eq!(hello[0], 1);
        assert_eq!(hello[38], 32);
        assert!(hello.windows(4).any(|w| w == [0x11, 0xec, 0x04, 0xc0]));
        let mut sealed = hello.clone();
        let key = [9u8; 32];
        let sid = [0u8; 8];
        seal_session_id(&mut sealed, &key, &random, &sid).unwrap();
        assert_ne!(&sealed[39..71], &[0u8; 32]);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut aad = sealed.clone();
        aad[39..71].fill(0);
        let opened = cipher
            .decrypt(
                &Nonce::try_from(&random[20..]).expect("fixed nonce length"),
                Payload {
                    msg: &sealed[39..71],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(&opened[..3], &XRAY_VERSION);
    }
}
