//! SOCKS5 and kernel splice forwarding once Vision is raw.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use io_uring::{opcode, types, IoUring};

use crate::tunnel::{ReadOut, Tunnel};
use crate::{err, Config, Result};

static SPLICED: AtomicU64 = AtomicU64::new(0);

pub fn spliced_bytes() -> u64 {
    SPLICED.load(Ordering::Relaxed)
}

#[derive(Clone)]
pub struct Endpoint {
    pub server: String,
    pub cfg: Config,
    pub uuid: [u8; 16],
}

pub fn serve_listener(ln: TcpListener, endpoint: Endpoint) -> Result<()> {
    let endpoint = Arc::new(endpoint);
    for conn in ln.incoming() {
        let conn = conn?;
        let endpoint = endpoint.clone();
        thread::spawn(move || {
            if let Err(e) = handle(conn, &endpoint) {
                eprintln!("reality: {e}");
            }
        });
    }
    Ok(())
}

fn handle(mut local: TcpStream, endpoint: &Endpoint) -> Result<()> {
    local.set_nodelay(true)?;
    let (host, port) = socks5(&mut local)?;
    let remote = match Tunnel::dial(&endpoint.server, &endpoint.cfg, endpoint.uuid, &host, port) {
        Ok(remote) => remote,
        Err(e) => {
            let _ = local.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Err(e);
        }
    };
    local.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    relay(local, remote)
}

pub(crate) fn relay(mut local: TcpStream, remote: Tunnel) -> Result<()> {
    local.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut download = local.try_clone()?;
    let local_fd = local.as_raw_fd();
    let remote_fd = remote.raw_fd();
    let splice = thread::scope(|scope| -> Result<bool> {
        let upload = scope.spawn(|| -> Result<bool> {
            let mut buf = [0u8; 32 * 1024];
            loop {
                if remote.ready_to_splice() {
                    return Ok(true);
                }
                match local.read(&mut buf) {
                    Ok(0) => {
                        if !remote.ready_to_splice() {
                            let _ = remote.shutdown_write();
                        }
                        return Ok(false);
                    }
                    Ok(n) => write_records(&remote, &buf[..n])?,
                    Err(e) if is_timeout(&e) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        });
        let mut buf = [0u8; 32 * 1024];
        let mut down = false;
        loop {
            if remote.ready_to_splice() {
                down = true;
                break;
            }
            match remote.read_some(&mut buf) {
                Ok(ReadOut::Data(n)) => download.write_all(&buf[..n])?,
                Ok(ReadOut::Eof) => {
                    // The client is blocked in read_to_end until this write
                    // side closes. Shut it down before joining upload.
                    let _ = download.shutdown(std::net::Shutdown::Write);
                    break;
                }
                Ok(ReadOut::Splice) => {
                    down = true;
                    break;
                }
                Err(e) => {
                    let _ = download.shutdown(std::net::Shutdown::Both);
                    let _ = upload.join();
                    return Err(e);
                }
            }
        }
        let up = upload.join().map_err(|_| err("upload thread"))??;
        Ok(down || up)
    })?;
    if splice {
        remote.clear_timeouts()?;
        local.set_read_timeout(None)?;
        local.set_write_timeout(None)?;
        download.set_read_timeout(None)?;
        download.set_write_timeout(None)?;
        splice_pair(local_fd, remote_fd)?;
    }
    Ok(())
}

fn write_records(remote: &Tunnel, mut data: &[u8]) -> Result<()> {
    while data.len() >= 5 {
        let kind = data[0];
        if kind != 0x14 && kind != 0x15 && kind != 0x16 && kind != 0x17 {
            break;
        }
        if data[1] != 0x03 {
            break;
        }
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + len {
            break;
        }
        remote.write_all_chunks(&data[..5 + len])?;
        data = &data[5 + len..];
    }
    if !data.is_empty() {
        remote.write_all_chunks(data)?;
    }
    Ok(())
}

fn is_timeout(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::TimedOut || err.kind() == std::io::ErrorKind::WouldBlock
}

struct Pipe {
    r: RawFd,
    w: RawFd,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.r);
            libc::close(self.w);
        }
    }
}

fn make_pipe() -> Result<Pipe> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(err("pipe"));
    }
    unsafe {
        libc::fcntl(fds[0], libc::F_SETPIPE_SZ, 1 << 20);
    }
    Ok(Pipe {
        r: fds[0],
        w: fds[1],
    })
}

struct Leg {
    sock_in: RawFd,
    sock_out: RawFd,
    pipe_r: RawFd,
    pipe_w: RawFd,
    remain: u32,
    phase: u8,
    inflight: bool,
    done: bool,
}

fn splice_pair(local: RawFd, remote: RawFd) -> Result<()> {
    splice_pair_with_ring(local, remote, IoUring::new(16).ok())
}

fn splice_pair_with_ring(local: RawFd, remote: RawFd, ring: Option<IoUring>) -> Result<()> {
    let p0 = make_pipe()?;
    let p1 = make_pipe()?;
    let mut legs = [
        Leg {
            sock_in: local,
            sock_out: remote,
            pipe_r: p0.r,
            pipe_w: p0.w,
            remain: 0,
            phase: 0,
            inflight: false,
            done: false,
        },
        Leg {
            sock_in: remote,
            sock_out: local,
            pipe_r: p1.r,
            pipe_w: p1.w,
            remain: 0,
            phase: 0,
            inflight: false,
            done: false,
        },
    ];
    let Some(mut ring) = ring else {
        for fd in [local, remote] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        return splice_with_poll(&mut legs);
    };
    loop {
        if legs.iter().all(|leg| leg.done) {
            return Ok(());
        }
        for (i, leg) in legs.iter_mut().enumerate() {
            if leg.done || leg.inflight {
                continue;
            }
            submit(&mut ring, leg, i as u64)?;
            leg.inflight = true;
        }
        if legs.iter().all(|leg| leg.done || !leg.inflight) {
            return Err(err("splice made no progress"));
        }
        match ring.submit_and_wait(1) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
        while let Some(cqe) = ring.completion().next() {
            let idx = cqe.user_data() as usize;
            if idx >= legs.len() {
                continue;
            }
            let res = cqe.result();
            let leg = &mut legs[idx];
            leg.inflight = false;
            if res != -libc::EAGAIN && res != -libc::EINTR {
                complete_splice(leg, res)?;
            }
        }
    }
}

fn complete_splice(leg: &mut Leg, result: i32) -> Result<()> {
    match result {
        0 => finish_leg(leg),
        n if n == -libc::EPIPE || n == -libc::ECONNRESET => finish_leg(leg),
        n if n < 0 => return Err(std::io::Error::from_raw_os_error(-n).into()),
        n if leg.phase == 0 => {
            leg.remain = n as u32;
            leg.phase = 1;
        }
        n => {
            SPLICED.fetch_add(n as u64, Ordering::Relaxed);
            leg.remain -= n as u32;
            if leg.remain == 0 {
                leg.phase = 0;
            }
        }
    }
    Ok(())
}

fn splice_with_poll(legs: &mut [Leg; 2]) -> Result<()> {
    while legs.iter().any(|leg| !leg.done) {
        let mut fds = legs.each_ref().map(|leg| {
            let (fd, events) = if leg.phase == 0 {
                (leg.sock_in, libc::POLLIN)
            } else {
                (leg.sock_out, libc::POLLOUT)
            };
            libc::pollfd {
                fd: if leg.done { -1 } else { fd },
                events,
                revents: 0,
            }
        });
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        for (leg, fd) in legs.iter_mut().zip(fds) {
            if fd.revents == 0 {
                continue;
            }
            let (input, output, len) = leg.transfer();
            let result = unsafe {
                libc::splice(
                    input,
                    std::ptr::null_mut(),
                    output,
                    std::ptr::null_mut(),
                    len as usize,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };
            let result = if result < 0 {
                -std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                result as i32
            };
            if result != -libc::EAGAIN && result != -libc::EINTR {
                complete_splice(leg, result)?;
            }
        }
    }
    Ok(())
}

fn finish_leg(leg: &mut Leg) {
    leg.done = true;
    unsafe { libc::shutdown(leg.sock_out, libc::SHUT_WR) };
}

impl Leg {
    fn transfer(&self) -> (RawFd, RawFd, u32) {
        if self.phase == 0 {
            (self.sock_in, self.pipe_w, 256 * 1024)
        } else {
            (self.pipe_r, self.sock_out, self.remain)
        }
    }
}

fn submit(ring: &mut IoUring, leg: &Leg, user: u64) -> Result<()> {
    let (fd_in, fd_out, len) = leg.transfer();
    let op = opcode::Splice::new(types::Fd(fd_in), -1, types::Fd(fd_out), -1, len)
        .flags(libc::SPLICE_F_MOVE)
        .build()
        .user_data(user);
    unsafe {
        ring.submission()
            .push(&op)
            .map_err(|_| err("io_uring submission full"))?;
    }
    Ok(())
}

fn socks5(conn: &mut TcpStream) -> Result<(String, u16)> {
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    conn.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut head = [0u8; 2];
    conn.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(err(format!("socks version {}", head[0])));
    }
    let mut methods = vec![0u8; head[1] as usize];
    conn.read_exact(&mut methods)?;
    conn.write_all(&[5, 0])?;
    let mut req = [0u8; 4];
    conn.read_exact(&mut req)?;
    if req[0] != 5 || req[1] != 1 {
        return Err(err(format!("unsupported socks command {}", req[1])));
    }
    let host = match req[3] {
        1 => {
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf)?;
            std::net::Ipv4Addr::from(buf).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            conn.read_exact(&mut n)?;
            let mut buf = vec![0u8; n[0] as usize];
            conn.read_exact(&mut buf)?;
            String::from_utf8(buf).map_err(|_| err("socks domain"))?
        }
        4 => {
            let mut buf = [0u8; 16];
            conn.read_exact(&mut buf)?;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        other => return Err(err(format!("bad atyp {other}"))),
    };
    let mut portb = [0u8; 2];
    conn.read_exact(&mut portb)?;
    conn.set_read_timeout(None)?;
    conn.set_write_timeout(None)?;
    Ok((host, u16::from_be_bytes(portb)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    #[test]
    fn poll_splice_relays_both_directions_and_half_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let first = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (local, _) = listener.accept().unwrap();
        let second = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (remote, _) = listener.accept().unwrap();
        thread::scope(|scope| {
            let relay = scope
                .spawn(move || splice_pair_with_ring(local.as_raw_fd(), remote.as_raw_fd(), None));
            for (mut peer, sent, expected) in [(first, 0xA1, 0xB2), (second, 0xB2, 0xA1)] {
                scope.spawn(move || {
                    let timeout = Some(Duration::from_secs(10));
                    peer.set_read_timeout(timeout).unwrap();
                    peer.set_write_timeout(timeout).unwrap();
                    peer.write_all(&vec![sent; 512 * 1024]).unwrap();
                    peer.shutdown(Shutdown::Write).unwrap();
                    let mut received = Vec::new();
                    peer.read_to_end(&mut received).unwrap();
                    assert_eq!(received.len(), 512 * 1024);
                    assert!(received.iter().all(|&byte| byte == expected));
                });
            }
            relay.join().unwrap().unwrap();
        });
    }
}
