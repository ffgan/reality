//! VLESS request encoding and xtls-rprx-vision framing.
//!
//! Padding, filtering, and the direct-mode switch follow Xray's VisionWriter.
//! A complete TLS record is kept in one chunk so the direct command can see it.
//! Content length is a uint16, so anything larger is split at 8192 bytes.

use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

use crate::tls::{self, Traffic};
use crate::{err, Config, Result};

const PAD_CONTINUE: u8 = 0;
const PAD_END: u8 = 1;
const PAD_DIRECT: u8 = 2;
const BUF_SIZE: usize = 8192;
const TLS13_VERSIONS: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const FLOW: &str = "xtls-rprx-vision";

pub struct Tunnel {
    sending: Mutex<()>,
    shutdown_fd: std::os::fd::RawFd,
    read: Mutex<TcpStream>,
    write: Mutex<TcpStream>,
    read_keys: Mutex<Traffic>,
    write_keys: Mutex<Traffic>,
    state: Mutex<State>,
}

struct State {
    uuid: [u8; 16],
    request: Vec<u8>,
    uuid_sent: bool,
    is_padding: bool,
    enable_xtls: bool,
    is_tls: bool,
    is_tls12: bool,
    filter_left: i32,
    server_hello: i32,
    cipher: u16,
    direct_armed: bool,
    raw_write: bool,
    direct_read: bool,
    copy_only: bool,
    within: bool,
    rem_cmd: i32,
    rem_content: i32,
    rem_pad: i32,
    cur_cmd: i32,
    pending: Vec<u8>,
    carry: Vec<u8>,
    header_sent: bool,
    response_done: bool,
}

pub enum ReadOut {
    Data(usize),
    Eof,
    Splice,
}

impl Tunnel {
    pub fn dial_udp(
        server: &str,
        cfg: &Config,
        uuid: [u8; 16],
        host: &str,
        port: u16,
    ) -> Result<Self> {
        let tunnel = Self::dial(server, cfg, uuid, host, port)?;
        {
            let mut state = tunnel.state.lock().expect("state");
            state.request = encode_request_for(&uuid, host, port, 2, "");
            state.is_padding = false;
            state.within = false;
            state.filter_left = 0;
        }
        Ok(tunnel)
    }

    pub fn dial(server: &str, cfg: &Config, uuid: [u8; 16], host: &str, port: u16) -> Result<Self> {
        let addr = server
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| err(format!("REALITY: cannot resolve {server}")))?;
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        // Set the bypass mark before connect: the SYN itself must escape the
        // router's transparent proxy, otherwise the client loops into itself.
        if let Ok(mark) = std::env::var("REALITY_OUTBOUND_MARK") {
            let mark: u32 = mark
                .parse()
                .map_err(|_| err("invalid REALITY_OUTBOUND_MARK"))?;
            socket.set_mark(mark)?;
        }
        socket.connect_timeout(&addr.into(), Duration::from_secs(10))?;
        let mut stream: TcpStream = socket.into();
        stream.set_nodelay(true)?;
        let deadline = Duration::from_secs(10);
        stream.set_read_timeout(Some(deadline))?;
        stream.set_write_timeout(Some(deadline))?;
        let session = tls::handshake(&mut stream, cfg)?;
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        let write = stream.try_clone()?;
        use std::os::fd::AsRawFd;
        let shutdown_fd = write.as_raw_fd();
        Ok(Self {
            sending: Mutex::new(()),
            shutdown_fd,
            read: Mutex::new(stream),
            write: Mutex::new(write),
            read_keys: Mutex::new(session.read),
            write_keys: Mutex::new(session.write),
            state: Mutex::new(State::new(uuid, host, port)),
        })
    }

    pub fn read_some(&self, buf: &mut [u8]) -> Result<ReadOut> {
        self.ensure_response()?;
        loop {
            {
                let mut st = self.state.lock().expect("state");
                if !st.pending.is_empty() {
                    let n = buf.len().min(st.pending.len());
                    buf[..n].copy_from_slice(&st.pending[..n]);
                    st.pending.drain(..n);
                    return Ok(ReadOut::Data(n));
                }
                if !st.copy_only && st.direct_read && (st.direct_armed || st.raw_write) {
                    return Ok(ReadOut::Splice);
                }
            }
            let (direct, copy_only) = {
                let st = self.state.lock().expect("state");
                (st.direct_read, st.copy_only)
            };
            if direct {
                let mut sock = self.read.lock().expect("read");
                if !copy_only {
                    sock.set_read_timeout(Some(Duration::from_millis(20)))?;
                }
                let mut tmp = [0u8; 16 * 1024];
                match sock.read(&mut tmp) {
                    Ok(0) => return Ok(ReadOut::Eof),
                    Ok(n) => {
                        if !copy_only {
                            let _ = sock.set_read_timeout(None);
                        }
                        self.state
                            .lock()
                            .expect("state")
                            .pending
                            .extend_from_slice(&tmp[..n]);
                    }
                    Err(e) if is_timeout(&e) => {
                        drop(sock);
                        if !copy_only && self.ready_to_splice() {
                            return Ok(ReadOut::Splice);
                        }
                        if copy_only {
                            return Err(e.into());
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            } else {
                let mut keys = self.read_keys.lock().expect("keys");
                let mut sock = self.read.lock().expect("read");
                let plain = match tls::read_app(&mut sock, &mut keys)? {
                    Some(p) => p,
                    None => return Ok(ReadOut::Eof),
                };
                drop(keys);
                let mut st = self.state.lock().expect("state");
                let unpadded = st.unpad(&plain);
                if st.filter_left > 0 && !unpadded.is_empty() {
                    st.filter(&unpadded);
                }
                st.pending.extend(unpadded);
            }
        }
    }

    pub fn write_all_chunks(&self, mut data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return self.write_chunk(&[]);
        }
        while !data.is_empty() {
            let n = if data.len() <= BUF_SIZE || (data.len() <= 0xffff && is_complete_record(data))
            {
                data.len()
            } else {
                BUF_SIZE.min(data.len())
            };
            self.write_chunk(&data[..n])?;
            data = &data[n..];
        }
        Ok(())
    }

    pub fn ready_to_splice(&self) -> bool {
        let st = self.state.lock().expect("state");
        st.direct_read && (st.direct_armed || st.raw_write) && st.pending.is_empty()
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        let sock = self.read.lock().expect("read");
        sock.set_read_timeout(timeout)?;
        sock.set_write_timeout(timeout)?;
        Ok(())
    }

    pub fn clear_timeouts(&self) -> Result<()> {
        self.set_timeout(None)
    }

    pub fn shutdown_write(&self) -> Result<()> {
        self.write
            .lock()
            .expect("write")
            .shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    pub fn shutdown(&self) {
        // The descriptor remains owned by self. Do not wait for a writer
        // mutex: shutdown must interrupt a blocked writer/reader as well.
        unsafe {
            libc::shutdown(self.shutdown_fd, libc::SHUT_RDWR);
        }
    }

    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.read.lock().expect("read").as_raw_fd()
    }

    fn write_chunk(&self, data: &[u8]) -> Result<()> {
        let _sending = self.sending.lock().expect("sending");
        let (packet, raw) = {
            let mut st = self.state.lock().expect("state");
            let raw = if st.direct_armed {
                st.direct_armed = false;
                st.raw_write = true;
                true
            } else {
                st.raw_write
            };
            if st.filter_left > 0 && !data.is_empty() {
                st.filter(data);
            }
            let frame = st.pad(data);
            let first = !st.header_sent;
            if first {
                st.header_sent = true;
            }
            let packet = if first {
                let mut p = st.request.clone();
                p.extend_from_slice(&frame);
                p
            } else {
                frame
            };
            (packet, raw)
        };
        if raw {
            let mut w = self.write.lock().expect("write");
            w.write_all(&packet)?;
        } else {
            let mut keys = self.write_keys.lock().expect("keys");
            let mut w = self.write.lock().expect("write");
            tls::write_app(&mut w, &mut keys, &packet)?;
        }
        Ok(())
    }

    fn ensure_response(&self) -> Result<()> {
        if !self.state.lock().expect("state").header_sent {
            // Serialize state preparation with the actual write. Otherwise the
            // upload thread can see header_sent and send body bytes before this
            // reader has written the VLESS request header to the wire.
            let _sending = self.sending.lock().expect("sending");
            let packet = {
                let mut st = self.state.lock().expect("state");
                if st.header_sent && st.response_done {
                    return Ok(());
                }
                if st.header_sent {
                    None
                } else {
                    let frame = st.pad(&[]);
                    st.header_sent = true;
                    let mut p = st.request.clone();
                    p.extend_from_slice(&frame);
                    Some(p)
                }
            };
            if let Some(packet) = packet {
                let mut keys = self.write_keys.lock().expect("keys");
                let mut w = self.write.lock().expect("write");
                tls::write_app(&mut w, &mut keys, &packet)?;
            }
        }
        while !self.state.lock().expect("state").response_done {
            let mut keys = self.read_keys.lock().expect("keys");
            let mut sock = self.read.lock().expect("read");
            let plain = match tls::read_app(&mut sock, &mut keys)? {
                Some(p) => p,
                None => return Err(err("REALITY: eof before response")),
            };
            drop(keys);
            let mut st = self.state.lock().expect("state");
            st.pending.extend(plain);
            match take_response(&st.pending) {
                Resp::NeedMore => continue,
                Resp::Bad => return Err(err("REALITY: bad vless response")),
                Resp::Done(rest) => {
                    let unpadded = st.unpad(&rest);
                    if st.filter_left > 0 && !unpadded.is_empty() {
                        st.filter(&unpadded);
                    }
                    st.pending = unpadded;
                    st.response_done = true;
                }
            }
        }
        Ok(())
    }
}

impl Read for Tunnel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Callers of Read keep copying. The SOCKS relay uses read_some and
        // is the only path that switches to splice.
        self.state.lock().expect("state").copy_only = true;
        match self.read_some(buf) {
            Ok(ReadOut::Data(n)) => Ok(n),
            Ok(ReadOut::Eof) => Ok(0),
            Ok(ReadOut::Splice) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "splice requested on a copied tunnel",
            )),
            Err(e) => Err(into_io(e)),
        }
    }
}

impl Write for Tunnel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all_chunks(buf).map_err(into_io)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.write.lock().expect("write").flush()
    }
}

fn into_io(err: Box<dyn std::error::Error + Send + Sync>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}

fn is_timeout(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::TimedOut || err.kind() == std::io::ErrorKind::WouldBlock
}

enum Resp {
    NeedMore,
    Bad,
    Done(Vec<u8>),
}

fn take_response(buf: &[u8]) -> Resp {
    if buf.len() < 2 {
        return Resp::NeedMore;
    }
    if buf[0] != 0 {
        return Resp::Bad;
    }
    let n = buf[1] as usize;
    if buf.len() < 2 + n {
        return Resp::NeedMore;
    }
    Resp::Done(buf[2 + n..].to_vec())
}

impl State {
    fn new(uuid: [u8; 16], host: &str, port: u16) -> Self {
        Self {
            uuid,
            request: encode_request(&uuid, host, port),
            uuid_sent: false,
            is_padding: true,
            enable_xtls: false,
            is_tls: false,
            is_tls12: false,
            filter_left: 8,
            server_hello: -1,
            cipher: 0,
            direct_armed: false,
            raw_write: false,
            direct_read: false,
            copy_only: false,
            within: true,
            rem_cmd: -1,
            rem_content: -1,
            rem_pad: -1,
            cur_cmd: 0,
            pending: Vec::new(),
            carry: Vec::new(),
            header_sent: false,
            response_done: false,
        }
    }

    fn pad(&mut self, content: &[u8]) -> Vec<u8> {
        if !self.is_padding {
            return content.to_vec();
        }
        let content_len = content.len();
        let mut command = PAD_CONTINUE;
        let mut long = self.is_tls;
        let complete = is_complete_record(content);
        if self.is_tls && content_len >= 6 && content.starts_with(&[0x17, 0x03, 0x03]) && complete {
            command = PAD_END;
            if self.enable_xtls {
                command = PAD_DIRECT;
                self.direct_armed = true;
            }
            self.is_padding = false;
            long = true;
        } else if !self.is_tls12 && self.filter_left <= 1 {
            command = PAD_END;
            self.is_padding = false;
        }
        let mut padding_len = if content_len < 900 && long {
            rand_below(500) as usize + 900 - content_len
        } else {
            rand_below(256) as usize
        };
        let cap = BUF_SIZE as isize - 21 - content_len as isize;
        if padding_len as isize > cap {
            padding_len = cap.max(0) as usize;
        }
        let mut out = Vec::with_capacity(16 + 5 + content_len + padding_len);
        if !self.uuid_sent {
            out.extend_from_slice(&self.uuid);
            self.uuid_sent = true;
        }
        out.push(command);
        out.push((content_len >> 8) as u8);
        out.push(content_len as u8);
        out.push((padding_len >> 8) as u8);
        out.push(padding_len as u8);
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len, 0);
        out
    }

    fn unpad(&mut self, input: &[u8]) -> Vec<u8> {
        if self.direct_read {
            return input.to_vec();
        }
        let mut b = if self.carry.is_empty() {
            input.to_vec()
        } else {
            let mut c = std::mem::take(&mut self.carry);
            c.extend_from_slice(input);
            c
        };
        let mut out = Vec::new();
        while !b.is_empty() {
            if self.rem_cmd == -1 && self.rem_content == -1 && self.rem_pad == -1 {
                if self.within && b.len() < 21 {
                    self.carry = b;
                    break;
                }
                if self.within && b.len() >= 16 && b[..16] == self.uuid {
                    b.drain(..16);
                    self.rem_cmd = 5;
                } else {
                    out.extend_from_slice(&b);
                    break;
                }
            }
            if self.rem_cmd > 0 {
                let data = b[0];
                b.drain(..1);
                match self.rem_cmd {
                    5 => self.cur_cmd = data as i32,
                    4 => self.rem_content = (data as i32) << 8,
                    3 => self.rem_content |= data as i32,
                    2 => self.rem_pad = (data as i32) << 8,
                    1 => self.rem_pad |= data as i32,
                    _ => {}
                }
                self.rem_cmd -= 1;
                continue;
            }
            if self.rem_content > 0 {
                let n = (self.rem_content as usize).min(b.len());
                out.extend_from_slice(&b[..n]);
                b.drain(..n);
                self.rem_content -= n as i32;
                continue;
            }
            let n = (self.rem_pad as usize).min(b.len());
            b.drain(..n);
            self.rem_pad -= n as i32;
            if self.rem_cmd <= 0 && self.rem_content <= 0 && self.rem_pad <= 0 {
                if self.cur_cmd == 0 {
                    self.rem_cmd = 5;
                } else {
                    self.rem_cmd = -1;
                    self.rem_content = -1;
                    self.rem_pad = -1;
                    self.within = false;
                    if self.cur_cmd == PAD_DIRECT as i32 {
                        self.direct_read = true;
                    }
                    if !b.is_empty() {
                        out.extend_from_slice(&b);
                    }
                    break;
                }
            }
        }
        out
    }

    fn filter(&mut self, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        self.filter_left -= 1;
        if b.len() >= 6 {
            if b.starts_with(&[0x16, 0x03, 0x03]) && b[5] == 0x02 {
                self.server_hello = ((b[3] as i32) << 8 | b[4] as i32) + 5;
                self.is_tls12 = true;
                self.is_tls = true;
                if b.len() >= 79 && self.server_hello >= 79 {
                    let sid = b[43] as usize;
                    let off = 43 + sid + 1;
                    if off + 2 <= b.len() {
                        self.cipher = u16::from_be_bytes([b[off], b[off + 1]]);
                    }
                }
            } else if b.starts_with(&[0x16, 0x03]) && b[5] == 0x01 {
                self.is_tls = true;
            }
        }
        if self.server_hello > 0 {
            let end = (self.server_hello as usize).min(b.len());
            self.server_hello -= b.len() as i32;
            if b[..end]
                .windows(TLS13_VERSIONS.len())
                .any(|w| w == TLS13_VERSIONS)
            {
                if matches!(self.cipher, 0x1301 | 0x1302 | 0x1303 | 0x1304) {
                    self.enable_xtls = true;
                }
                self.filter_left = 0;
                return;
            }
            if self.server_hello <= 0 {
                self.filter_left = 0;
            }
        }
    }
}

fn encode_request(uuid: &[u8], host: &str, port: u16) -> Vec<u8> {
    encode_request_for(uuid, host, port, 1, FLOW)
}

fn encode_request_for(uuid: &[u8], host: &str, port: u16, command: u8, flow: &str) -> Vec<u8> {
    let addons = if flow.is_empty() {
        Vec::new()
    } else {
        encode_addons(flow)
    };
    let mut out = Vec::new();
    out.push(0);
    out.extend_from_slice(uuid);
    out.push(addons.len() as u8);
    out.extend_from_slice(&addons);
    out.push(command);
    out.extend_from_slice(&port.to_be_bytes());
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(3);
                out.extend_from_slice(&v6.octets());
            }
        }
        return out;
    }
    out.push(2);
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    out
}

fn encode_addons(flow: &str) -> Vec<u8> {
    let mut body = vec![0x0a, flow.len() as u8];
    body.extend_from_slice(flow.as_bytes());
    body
}

fn is_complete_record(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let mut header = 5i32;
    let mut record = 0i32;
    let mut i = 0;
    while i < b.len() {
        if header > 0 {
            let data = b[i];
            i += 1;
            match header {
                5 => {
                    if data != 0x17 {
                        return false;
                    }
                }
                4 | 3 => {
                    if data != 0x03 {
                        return false;
                    }
                }
                2 => record = (data as i32) << 8,
                1 => record |= data as i32,
                _ => {}
            }
            header -= 1;
            continue;
        }
        if b.len() - i < record as usize {
            return false;
        }
        i += record as usize;
        record = 0;
        header = 5;
    }
    header == 5 && record == 0
}

fn rand_below(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).ok();
    u32::from_ne_bytes(buf) % n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_roundtrip_and_addresses() {
        let mut st = State::new([9u8; 16], "example.com", 443);
        let frame = st.pad(b"abc");
        assert!(frame.starts_with(&[9u8; 16]));
        let mut rd = State::new([9u8; 16], "example.com", 443);
        let plain = rd.unpad(&frame);
        assert_eq!(plain, b"abc");

        let v4 = encode_request(&[1u8; 16], "1.2.3.4", 80);
        assert_eq!(v4[v4.len() - 5], 1);
        assert_eq!(&v4[v4.len() - 4..], &[1, 2, 3, 4]);
        let v6 = encode_request(&[1u8; 16], "::1", 80);
        assert_eq!(v6[v6.len() - 17], 3);

        let rec = [0x17u8, 0x03, 0x03, 0x00, 0x01, 0xff];
        assert!(is_complete_record(&rec));
        assert!(!is_complete_record(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff]));

        let dom = encode_request(&[2u8; 16], "example.com", 80);
        assert!(dom.windows(13).any(|w| w == b"\x02\x0bexample.com"));
        let v4_port = encode_request(&[1u8; 16], "1.2.3.4", 443);
        let atyp = v4_port.len() - 5;
        assert_eq!(&v4_port[atyp - 2..atyp], &[0x01, 0xbb]);
    }

    #[test]
    fn unpad_one_byte_at_a_time() {
        let mut writer = State::new([0x11; 16], "example.com", 443);
        let frame = writer.pad(b"abcdefghij");
        let mut reader = State::new([0x11; 16], "example.com", 443);
        let mut got = Vec::new();
        for byte in frame {
            got.extend(reader.unpad(&[byte]));
        }
        assert_eq!(got, b"abcdefghij");
        let second = writer.pad(b"more");
        assert_ne!(&second[..16], &[0x11; 16]);
        assert_eq!(reader.unpad(&second), b"more");
    }

    #[test]
    fn direct_command_on_tls_record() {
        let mut st = State::new([0x22; 16], "example.com", 443);
        st.is_tls = true;
        st.enable_xtls = true;
        let record = [0x17u8, 0x03, 0x03, 0x00, 0x01, 0xff];
        let frame = st.pad(&record);
        assert!(st.direct_armed);
        assert!(!st.is_padding);
        let mut reader = State::new([0x22; 16], "example.com", 443);
        let plain = reader.unpad(&frame);
        assert_eq!(plain, record);
        assert_eq!(reader.cur_cmd, PAD_DIRECT as i32);
        assert!(reader.direct_read);
    }

    #[test]
    fn filter_enables_xtls_for_tls13() {
        let mut st = State::new([1; 16], "example.com", 443);
        let mut hello = vec![0u8; 90];
        hello[..6].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x55, 0x02]);
        hello[43] = 32;
        hello[43 + 32 + 1] = 0x13;
        hello[43 + 32 + 2] = 0x01;
        hello[70..76].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        st.filter(&hello);
        assert!(st.is_tls && st.is_tls12 && st.enable_xtls);
        assert_eq!(st.cipher, 0x1301);
        assert_eq!(st.filter_left, 0);
    }
}
