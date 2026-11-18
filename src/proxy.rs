//! SOCKS5 and kernel splice forwarding once Vision is raw.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::tunnel::{ReadOut, Tunnel};
use crate::{err, Config, Result};

pub(crate) const SPLICE_BATCH: u32 = 256 * 1024;

static SPLICED: AtomicU64 = AtomicU64::new(0);

pub fn spliced_bytes() -> u64 {
    SPLICED.load(Ordering::Relaxed)
}

pub(crate) fn record_splice(bytes: u32) {
    SPLICED.fetch_add(u64::from(bytes), Ordering::Relaxed);
}

#[derive(Clone)]
pub struct Endpoint {
    pub server: String,
    pub cfg: Config,
    pub uuid: [u8; 16],
}

pub fn serve_listener(ln: TcpListener, endpoint: Endpoint) -> Result<()> {
    if let Some(result) = crate::ring_proxy::try_serve(&ln, &endpoint, None)? {
        return result;
    }
    serve_listener_blocking(ln, endpoint)
}

pub(crate) fn serve_listener_blocking(ln: TcpListener, endpoint: Endpoint) -> Result<()> {
    let endpoint = Arc::new(endpoint);
    loop {
        let conn = accept_tcp(&ln)?;
        let endpoint = endpoint.clone();
        if let Err(error) = thread::Builder::new()
            .name("socks-client".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                if let Err(e) = handle(conn, &endpoint) {
                    eprintln!("reality: {e}");
                }
            })
        {
            eprintln!("reality worker unavailable: {error}");
        }
    }
}

// An exhausted descriptor table is temporary, not a reason to terminate every
// existing relay. Back off until active clients release their descriptors.
pub(crate) fn accept_tcp(listener: &TcpListener) -> std::io::Result<TcpStream> {
    let mut last_warning: Option<Instant> = None;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error)
                if matches!(error.raw_os_error(), Some(libc::EINTR | libc::ECONNABORTED)) =>
            {
                continue
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
                ) =>
            {
                if last_warning.is_none_or(|last| last.elapsed() >= Duration::from_secs(10)) {
                    eprintln!("reality accept temporarily unavailable: {error}");
                    last_warning = Some(Instant::now());
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
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
    relay(local, remote).map_err(|e| err(format!("relay {host}:{port}: {e}")))
}

pub(crate) fn relay(mut local: TcpStream, remote: Tunnel) -> Result<()> {
    local.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut download = local.try_clone()?;
    let local_fd = local.as_raw_fd();
    let remote_fd = remote.raw_fd();
    let splice = thread::scope(|scope| -> Result<bool> {
        let upload = scope.spawn(|| -> Result<bool> {
            let result = (|| -> Result<bool> {
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
            })();
            if result.is_err() {
                remote.shutdown();
                let _ = local.shutdown(std::net::Shutdown::Both);
            }
            result
        });
        let mut buf = [0u8; 32 * 1024];
        let mut down = false;
        loop {
            if remote.ready_to_splice() {
                down = true;
                break;
            }
            match remote.read_some(&mut buf) {
                Ok(ReadOut::Data(n)) => {
                    if let Err(e) = download.write_all(&buf[..n]) {
                        remote.shutdown();
                        let _ = download.shutdown(std::net::Shutdown::Both);
                        let _ = upload.join();
                        return Err(e.into());
                    }
                }
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
                    remote.shutdown();
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

pub(crate) fn record_chunks(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        let len = if data.len() >= 5 && (0x14..=0x17).contains(&data[0]) && data[1] == 0x03 {
            let len = u16::from_be_bytes([data[3], data[4]]) as usize + 5;
            len.min(data.len())
        } else {
            data.len()
        };
        let (record, tail) = data.split_at(len);
        data = tail;
        Some(record)
    })
}

fn write_records(remote: &Tunnel, data: &[u8]) -> Result<()> {
    for record in record_chunks(data) {
        remote.write_all_chunks(record)?;
    }
    Ok(())
}

fn is_timeout(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::TimedOut || err.kind() == std::io::ErrorKind::WouldBlock
}

pub(crate) struct Pipe {
    pub(crate) r: RawFd,
    pub(crate) w: RawFd,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.r);
            libc::close(self.w);
        }
    }
}

pub(crate) fn make_pipe() -> Result<Pipe> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    unsafe {
        libc::fcntl(fds[0], libc::F_SETPIPE_SZ, SPLICE_BATCH as libc::c_int);
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
    done: bool,
}

fn splice_pair(local: RawFd, remote: RawFd) -> Result<()> {
    set_nonblocking(local)?;
    set_nonblocking(remote)?;
    let pipes = [make_pipe()?, make_pipe()?];
    let sockets = [local, remote];
    let mut legs = std::array::from_fn(|i| Leg {
        sock_in: sockets[i],
        sock_out: sockets[1 - i],
        pipe_r: pipes[i].r,
        pipe_w: pipes[i].w,
        remain: 0,
        phase: 0,
        done: false,
    });
    splice_with_poll(&mut legs)
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
            record_splice(n as u32);
            leg.remain -= n as u32;
            if leg.remain == 0 {
                leg.phase = 0;
            }
        }
    }
    Ok(())
}

pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn splice_nonblocking(input: RawFd, output: RawFd, len: u32) -> io::Result<u32> {
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
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as u32)
    }
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
            let result = match splice_nonblocking(input, output, len) {
                Ok(n) => n as i32,
                Err(error) => -error.raw_os_error().unwrap_or(libc::EIO),
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
            (self.sock_in, self.pipe_w, SPLICE_BATCH)
        } else {
            (self.pipe_r, self.sock_out, self.remain)
        }
    }
}

fn socks5(conn: &mut TcpStream) -> Result<(String, u16)> {
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    conn.set_write_timeout(Some(Duration::from_secs(30)))?;
    let result = crate::tls::run_blocking(socks_request(&mut crate::tls::BlockingTransport(conn)));
    conn.set_read_timeout(None)?;
    conn.set_write_timeout(None)?;
    result
}

pub(crate) async fn socks_request(conn: &mut impl crate::tls::Transport) -> Result<(String, u16)> {
    let mut head = [0u8; 2];
    conn.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(err(format!("socks version {}", head[0])));
    }
    let mut methods = vec![0u8; head[1] as usize];
    conn.read_exact(&mut methods).await?;
    conn.write_all(&[5, 0]).await?;
    let mut req = [0u8; 4];
    conn.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        return Err(err(format!("unsupported socks command {}", req[1])));
    }
    let host = match req[3] {
        1 => {
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await?;
            std::net::Ipv4Addr::from(buf).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            conn.read_exact(&mut n).await?;
            let mut buf = vec![0u8; n[0] as usize];
            conn.read_exact(&mut buf).await?;
            String::from_utf8(buf).map_err(|_| err("socks domain"))?
        }
        4 => {
            let mut buf = [0u8; 16];
            conn.read_exact(&mut buf).await?;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        other => return Err(err(format!("bad atyp {other}"))),
    };
    let mut portb = [0u8; 2];
    conn.read_exact(&mut portb).await?;
    Ok((host, u16::from_be_bytes(portb)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    #[test]
    fn poll_splice_relays_both_directions_and_half_closes() {
        check_duplex(splice_pair);
    }

    fn check_duplex(relay_pair: impl FnOnce(RawFd, RawFd) -> Result<()> + Send) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let first = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (local, _) = listener.accept().unwrap();
        let second = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (remote, _) = listener.accept().unwrap();
        thread::scope(|scope| {
            let relay = scope.spawn(move || relay_pair(local.as_raw_fd(), remote.as_raw_fd()));
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
