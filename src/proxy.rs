//! SOCKS5 and the io_uring splice that takes over once Vision is raw.

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
        if let Err(e) = splice_pair(local_fd, remote_fd) {
            if e.to_string().starts_with("io_uring") {
                copy_rest(&mut download, &remote)?;
            } else {
                return Err(e);
            }
        }
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

fn copy_rest(local: &mut TcpStream, remote: &Tunnel) -> Result<()> {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match remote.read_some(&mut buf) {
            Ok(ReadOut::Data(n)) => local.write_all(&buf[..n])?,
            _ => return Ok(()),
        }
    }
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
        libc::fcntl(fds[1], libc::F_SETPIPE_SZ, 1 << 20);
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
    let mut ring = IoUring::new(16).map_err(|e| err(format!("io_uring: {e}")))?;
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
        ring.submit_and_wait(1)
            .map_err(|e| err(format!("io_uring enter: {e}")))?;
        while let Some(cqe) = ring.completion().next() {
            let idx = cqe.user_data() as usize;
            if idx >= legs.len() {
                continue;
            }
            let res = cqe.result();
            let leg = &mut legs[idx];
            leg.inflight = false;
            if leg.phase == 0 {
                if res > 0 {
                    leg.remain = res as u32;
                    leg.phase = 1;
                } else if res == 0 || res == -libc::EPIPE || res == -libc::ECONNRESET {
                    finish_leg(leg);
                } else if res != -libc::EAGAIN && res != -libc::EINTR {
                    return Err(err(format!("splice in: {res}")));
                }
            } else if res > 0 {
                SPLICED.fetch_add(res as u64, Ordering::Relaxed);
                leg.remain = leg.remain.saturating_sub(res as u32);
                if leg.remain == 0 {
                    leg.phase = 0;
                }
            } else if res == 0 || res == -libc::EPIPE || res == -libc::ECONNRESET {
                finish_leg(leg);
            } else if res != -libc::EAGAIN && res != -libc::EINTR {
                return Err(err(format!("splice out: {res}")));
            }
        }
    }
}

fn finish_leg(leg: &mut Leg) {
    leg.done = true;
    unsafe { libc::shutdown(leg.sock_out, libc::SHUT_WR) };
}

fn submit(ring: &mut IoUring, leg: &Leg, user: u64) -> Result<()> {
    let (fd_in, fd_out, len) = if leg.phase == 0 {
        (leg.sock_in, leg.pipe_w, 256 * 1024)
    } else {
        (leg.pipe_r, leg.sock_out, leg.remain.max(1))
    };
    let op = opcode::Splice::new(types::Fd(fd_in), -1, types::Fd(fd_out), -1, len)
        .flags(1)
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
