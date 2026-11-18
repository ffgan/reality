//! Linux REDIRECT/TProxy listeners. Firewall policy stays with Passwall.
use crate::{err, proxy, Endpoint, Result, Tunnel, UdpTunnel};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{sync_channel, SyncSender},
    Arc,
};
use std::thread;
use std::time::Duration;

const MAX_SESSIONS: usize = 64;

fn set_int(fd: RawFd, level: i32, option: i32, value: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &value as *const _ as *const _,
            size_of::<i32>() as _,
        )
    };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socket(ipv6: bool, udp: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
        if udp { Type::DGRAM } else { Type::STREAM },
        Some(if udp { Protocol::UDP } else { Protocol::TCP }),
    )?;
    socket.set_reuse_address(true)?;
    if ipv6 {
        socket.set_only_v6(true)?;
        socket.set_ip_transparent_v6(true)?;
    } else {
        socket.set_ip_transparent_v4(true)?;
    }
    // Reply packets and upstream sockets must never re-enter proxy rules.
    socket.set_mark(255)?;
    Ok(socket)
}

fn bind(port: u16, ipv6: bool, udp: bool) -> io::Result<Socket> {
    let socket = socket(ipv6, udp)?;
    if udp {
        set_int(
            socket.as_raw_fd(),
            if ipv6 { libc::SOL_IPV6 } else { libc::SOL_IP },
            if ipv6 {
                libc::IPV6_RECVORIGDSTADDR
            } else {
                libc::IP_RECVORIGDSTADDR
            },
            1,
        )?;
    }
    let ip = if ipv6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    socket.bind(&SocketAddr::new(ip, port).into())?;
    if !udp {
        socket.listen(128)?;
    }
    Ok(socket)
}

pub fn serve_transparent(port: u16, tproxy: bool, endpoint: Endpoint) -> Result<()> {
    let tcp4: TcpListener = bind(port, false, false)?.into();
    let tcp6: TcpListener = bind(port, true, false)?.into();
    let udp4: UdpSocket = bind(port, false, true)?.into();
    let udp6: UdpSocket = bind(port, true, true)?.into();
    let endpoint = Arc::new(endpoint);
    for listener in [tcp4, tcp6] {
        let endpoint = endpoint.clone();
        thread::Builder::new()
            .name("redirect-tcp".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    match conn {
                        Ok(conn) => {
                            let endpoint = endpoint.clone();
                            if let Err(e) = thread::Builder::new()
                                .name("transparent-tcp".into())
                                .stack_size(256 * 1024)
                                .spawn(move || {
                                    if let Err(e) = tcp(conn, tproxy, &endpoint) {
                                        eprintln!("reality transparent TCP: {e}");
                                    }
                                })
                            {
                                eprintln!("reality TCP worker: {e}");
                            }
                        }
                        Err(e) => eprintln!("reality accept: {e}"),
                    }
                }
            })?;
    }
    let endpoint6 = endpoint.clone();
    thread::Builder::new()
        .name("tproxy-udp6".into())
        .spawn(move || {
            if let Err(e) = udp(udp6, endpoint6) {
                eprintln!("reality UDP6: {e}");
                std::process::exit(1);
            }
        })?;
    eprintln!(
        "reality transparent TCP/UDP :{port} ({})",
        if tproxy {
            "tproxy"
        } else {
            "redirect TCP, tproxy UDP"
        }
    );
    udp(udp4, endpoint)
}

fn tcp(local: TcpStream, tproxy: bool, endpoint: &Endpoint) -> Result<()> {
    let dest = if tproxy {
        local.local_addr()?
    } else {
        let sock = SockRef::from(&local);
        let addr = if local.local_addr()?.is_ipv6() {
            sock.original_dst_v6()?
        } else {
            sock.original_dst_v4()?
        };
        addr.as_socket()
            .ok_or_else(|| err("missing original TCP destination"))?
    };
    local.set_nodelay(true)?;
    let remote = Tunnel::dial(
        &endpoint.server,
        &endpoint.cfg,
        endpoint.uuid,
        &dest.ip().to_string(),
        dest.port(),
    )?;
    proxy::relay(local, remote)
}

struct Session {
    sender: SyncSender<Vec<u8>>,
    alive: Arc<AtomicBool>,
}

fn udp(socket: UdpSocket, endpoint: Arc<Endpoint>) -> Result<()> {
    let mut sessions: HashMap<(SocketAddr, SocketAddr), Session> = HashMap::new();
    let mut packet = vec![0u8; 65535];
    loop {
        let (len, source, dest) = recv_original(&socket, &mut packet)?;
        let key = (source, dest);
        sessions.retain(|_, session| session.alive.load(Ordering::Acquire));
        if !sessions.contains_key(&key) {
            if sessions.len() >= MAX_SESSIONS {
                continue;
            }
            let (sender, receiver) = sync_channel::<Vec<u8>>(8);
            let alive = Arc::new(AtomicBool::new(true));
            let active = alive.clone();
            let endpoint = endpoint.clone();
            thread::Builder::new()
                .name("udp-session".into())
                .stack_size(256 * 1024)
                .spawn(move || {
                    let result = (|| -> Result<()> {
                        let tunnel = Arc::new(UdpTunnel::dial(
                            &endpoint.server,
                            &endpoint.cfg,
                            endpoint.uuid,
                            &dest.ip().to_string(),
                            dest.port(),
                        )?);
                        let reply = self::socket(dest.is_ipv6(), true)?;
                        reply.set_reuse_port(true)?;
                        reply.bind(&dest.into())?;
                        let reply: UdpSocket = reply.into();
                        let first = receiver.recv_timeout(Duration::from_secs(10))?;
                        tunnel.send(&first)?;
                        let remote = tunnel.clone();
                        let receiving = active.clone();
                        let reader = thread::Builder::new()
                            .name("udp-reply".into())
                            .stack_size(128 * 1024)
                            .spawn(move || {
                                while receiving.load(Ordering::Acquire) {
                                    match remote.recv() {
                                        Ok(data) => {
                                            if reply.send_to(&data, source).is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                receiving.store(false, Ordering::Release);
                                remote.shutdown();
                            })?;
                        while active.load(Ordering::Acquire) {
                            match receiver.recv_timeout(Duration::from_secs(60)) {
                                Ok(data) => {
                                    if tunnel.send(&data).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        active.store(false, Ordering::Release);
                        tunnel.shutdown();
                        let _ = reader.join();
                        Ok(())
                    })();
                    active.store(false, Ordering::Release);
                    if let Err(e) = result {
                        eprintln!("reality UDP {dest}: {e}");
                    }
                })?;
            sessions.insert(key, Session { sender, alive });
        }
        // Never let a slow or dead peer block the UDP listener or grow memory.
        if let Some(session) = sessions.get(&key) {
            let _ = session.sender.try_send(packet[..len].to_vec());
        }
    }
}

fn recv_original(socket: &UdpSocket, packet: &mut [u8]) -> Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut peer: libc::sockaddr_storage = zeroed();
        let mut control = [0usize; 64]; // aligned ancillary buffer
        let mut iov = libc::iovec {
            iov_base: packet.as_mut_ptr() as _,
            iov_len: packet.len(),
        };
        let mut msg: libc::msghdr = zeroed();
        msg.msg_name = &mut peer as *mut _ as _;
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as _;
        msg.msg_controllen = size_of_val(&control) as _;
        let n = libc::recvmsg(socket.as_raw_fd(), &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(err("truncated transparent UDP packet"));
        }
        let source = raw_addr(&peer as *const _ as *const u8, msg.msg_namelen as usize)?;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let header = &*cmsg;
            let len =
                if header.cmsg_level == libc::SOL_IP && header.cmsg_type == libc::IP_ORIGDSTADDR {
                    size_of::<libc::sockaddr_in>()
                } else if header.cmsg_level == libc::SOL_IPV6
                    && header.cmsg_type == libc::IPV6_ORIGDSTADDR
                {
                    size_of::<libc::sockaddr_in6>()
                } else {
                    0
                };
            if len > 0 && header.cmsg_len as usize >= libc::CMSG_LEN(len as _) as usize {
                let dest = raw_addr(libc::CMSG_DATA(cmsg), len)?;
                return Ok((n as usize, source, dest));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        Err(err("missing original UDP destination"))
    }
}

// Copy a kernel-provided sockaddr into socket2's platform-sized storage.
unsafe fn raw_addr(data: *const u8, len: usize) -> Result<SocketAddr> {
    let (_, addr) = unsafe {
        SockAddr::try_init(|storage, size| {
            if len > *size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sockaddr length",
                ));
            }
            std::ptr::copy_nonoverlapping(data, storage as *mut u8, len);
            *size = len as _;
            Ok(())
        })
    }?;
    addr.as_socket()
        .ok_or_else(|| err("invalid socket address"))
}
