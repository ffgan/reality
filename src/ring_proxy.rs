//! TCP and transparent UDP sessions driven by a shared ring.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use monoio::net::udp::UdpSocket;
use monoio::net::{TcpListener, TcpStream};

use crate::proxy::{
    make_pipe, record_chunks, set_nonblocking, socks_request, splice_nonblocking, SPLICE_BATCH,
};
use crate::ring_io::{clone_stream, RingTransport};
use crate::tls::Transport;
use crate::transparent;
use crate::tunnel::ring::{self, Packet};
use crate::{err, Endpoint, Result};

struct Listeners {
    socks: std::net::TcpListener,
    transparent: Option<TransparentListeners>,
    udp: Option<[std::net::UdpSocket; 2]>,
}

type TransparentListeners = ([std::net::TcpListener; 2], u16, bool);

fn bind_udp_pair(port: u16) -> io::Result<[std::net::UdpSocket; 2]> {
    let bind = |ipv6| {
        let socket = transparent::bind_listener(port, ipv6, true, true)?;
        socket.set_nonblocking(true)?;
        Ok::<_, io::Error>(socket.into())
    };
    Ok([bind(false)?, bind(true)?])
}

impl Listeners {
    fn open(listener: &std::net::TcpListener, config: Option<(u16, bool)>) -> Result<Self> {
        let transparent = if let Some((port, tproxy)) = config {
            Some((
                [
                    transparent::bind(port, false, false)?.into(),
                    transparent::bind(port, true, false)?.into(),
                ],
                port,
                tproxy,
            ))
        } else {
            None
        };
        Ok(Self {
            socks: listener.try_clone()?,
            udp: config.map(|(port, _)| bind_udp_pair(port)).transpose()?,
            transparent,
        })
    }

    fn try_clone(&self) -> io::Result<Self> {
        let transparent = match &self.transparent {
            Some(([v4, v6], port, tproxy)) => {
                Some(([v4.try_clone()?, v6.try_clone()?], *port, *tproxy))
            }
            None => None,
        };
        Ok(Self {
            socks: self.socks.try_clone()?,
            udp: self
                .transparent
                .as_ref()
                .map(|(_, port, _)| bind_udp_pair(*port))
                .transpose()?,
            transparent,
        })
    }

    async fn tcp(self, endpoint: Rc<Endpoint>) -> Result<()> {
        let socks = TcpListener::from_std(self.socks)?;
        match self.transparent {
            Some(([v4, v6], _, tproxy)) => {
                monoio::try_join!(
                    serve(socks, endpoint.clone(), None),
                    serve(TcpListener::from_std(v4)?, endpoint.clone(), Some(tproxy)),
                    serve(TcpListener::from_std(v6)?, endpoint, Some(tproxy)),
                )?;
                Ok(())
            }
            None => serve(socks, endpoint, None).await,
        }
    }
}

async fn serve_all(
    mut listeners: Listeners,
    endpoint: Rc<Endpoint>,
    session_limits: Arc<[AtomicUsize; 2]>,
) -> Result<()> {
    if let Some([udp4, udp6]) = listeners.udp.take() {
        monoio::try_join!(
            listeners.tcp(endpoint.clone()),
            serve_udp(
                UdpSocket::from_std(udp4)?,
                endpoint.clone(),
                session_limits.clone(),
                0
            ),
            serve_udp(UdpSocket::from_std(udp6)?, endpoint, session_limits, 1),
        )?;
        Ok(())
    } else {
        listeners.tcp(endpoint).await
    }
}

fn build_runtime(
    pool: monoio::blocking::DefaultThreadPool,
) -> io::Result<monoio::Runtime<monoio::time::TimeDriver<monoio::IoUringDriver>>> {
    let mut optimized = io_uring::IoUring::builder();
    optimized.setup_single_issuer().setup_defer_taskrun();
    let build = |ring, pool| {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .with_entries(256)
            .uring_builder(ring)
            .attach_thread_pool(Box::new(pool))
            .enable_timer()
            .build()
    };
    build(optimized, pool.clone()).or_else(|_| build(io_uring::IoUring::builder(), pool))
}

pub(crate) fn try_serve(
    listener: &std::net::TcpListener,
    endpoint: &Endpoint,
    transparent: Option<(u16, bool)>,
) -> Result<Option<Result<()>>> {
    let pool = monoio::blocking::DefaultThreadPool::new(2);
    let Ok(mut runtime) = build_runtime(pool.clone()) else {
        return Ok(None);
    };
    let listeners = Listeners::open(listener, transparent)?;
    let secondary = listeners.try_clone()?;
    let (stop, stopped) = flume::bounded::<()>(1);
    let (report, reports) = flume::bounded(1);
    let session_limits = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let secondary_limits = session_limits.clone();
    let worker_endpoint = endpoint.clone();
    let worker = std::thread::Builder::new()
        .name("reality-ring".into())
        .spawn(move || {
            let result = (|| {
                let mut runtime = build_runtime(pool)?;
                runtime.block_on(async move {
                    use futures_util::future::{select, Either};
                    let service = std::pin::pin!(serve_all(
                        secondary,
                        Rc::new(worker_endpoint),
                        secondary_limits
                    ));
                    let stop = std::pin::pin!(stopped.recv_async());
                    match select(service, stop).await {
                        Either::Left((result, _)) => result,
                        Either::Right(_) => Ok(()),
                    }
                })
            })();
            let _ = report.try_send(result);
        })?;
    let endpoint = Rc::new(endpoint.clone());
    let result = runtime.block_on(async move {
        let service = serve_all(listeners, endpoint, session_limits);
        use futures_util::future::{select, Either};
        match select(
            std::pin::pin!(service),
            std::pin::pin!(reports.recv_async()),
        )
        .await
        {
            Either::Left((result, _)) => result,
            Either::Right((report, _)) => report.map_err(|_| err("I/O worker exited"))?,
        }
    });
    let _ = stop.try_send(());
    worker.join().map_err(|_| err("I/O worker panicked"))?;
    Ok(Some(result))
}

async fn serve(
    listener: TcpListener,
    endpoint: Rc<Endpoint>,
    transparent: Option<bool>,
) -> Result<()> {
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR | libc::ECONNABORTED)) => {
                continue
            }
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS)
                ) =>
            {
                monoio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let endpoint = endpoint.clone();
        monoio::spawn(async move {
            let result = match transparent {
                Some(tproxy) => handle_transparent(socket, &endpoint, tproxy).await,
                None => handle_socks(socket, &endpoint).await,
            };
            if let Err(error) = result {
                eprintln!("reality TCP: {error}");
            }
        });
    }
}

static DNS_REQUESTS: AtomicUsize = AtomicUsize::new(0);

struct DnsSlot;

impl Drop for DnsSlot {
    fn drop(&mut self) {
        DNS_REQUESTS.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn resolve(server: &str) -> Result<SocketAddr> {
    if let Ok(addr) = server.parse() {
        return Ok(addr);
    }
    DNS_REQUESTS
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < 128).then_some(count + 1)
        })
        .map_err(|_| err("REALITY DNS queue full"))?;
    let slot = DnsSlot;
    let server = server.to_owned();
    monoio::spawn_blocking(move || {
        let _slot = slot;
        server
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| err(format!("REALITY: cannot resolve {server}")))
    })
    .await
    .map_err(|_| err("REALITY DNS worker failed"))?
}

async fn handle_socks(socket: TcpStream, endpoint: &Endpoint) -> Result<()> {
    socket.set_nodelay(true)?;
    let mut local = RingTransport::new(socket);
    let (host, port) =
        monoio::time::timeout(Duration::from_secs(30), socks_request(&mut local)).await??;
    let dial = async {
        let address = resolve(&endpoint.server).await?;
        ring::dial(address, &endpoint.cfg, endpoint.uuid, &host, port, false).await
    };
    let (read, write) = match dial.await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            let _ = local.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return Err(error);
        }
    };
    local.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    relay(local, read, write).await
}

async fn handle_transparent(socket: TcpStream, endpoint: &Endpoint, tproxy: bool) -> Result<()> {
    // The destination is obtained before yielding or moving the socket.
    let fd = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
    let address = transparent::tcp_destination(&fd, tproxy)?;
    socket.set_nodelay(true)?;
    let server = resolve(&endpoint.server).await?;
    let (reader, writer) = ring::dial(
        server,
        &endpoint.cfg,
        endpoint.uuid,
        &address.ip().to_string(),
        address.port(),
        false,
    )
    .await?;
    relay(RingTransport::new(socket), reader, writer).await
}

const UDP_IDLE: Duration = Duration::from_secs(60);
type UdpKey = (SocketAddr, SocketAddr);
type UdpSessions = Rc<RefCell<HashMap<UdpKey, flume::Sender<Vec<u8>>>>>;

struct UdpSlot(Arc<[AtomicUsize; 2]>, usize);

impl Drop for UdpSlot {
    fn drop(&mut self) {
        self.0[self.1].fetch_sub(1, Ordering::Relaxed);
    }
}

async fn serve_udp(
    socket: UdpSocket,
    endpoint: Rc<Endpoint>,
    limits: Arc<[AtomicUsize; 2]>,
    family: usize,
) -> Result<()> {
    let sessions = UdpSessions::default();
    let mut packet = vec![0; 65535];
    loop {
        socket.readable(false).await?;
        let (len, source, destination) =
            match transparent::recv_original(socket.as_raw_fd(), &mut packet) {
                Ok(packet) => packet,
                Err(error) => match error.downcast_ref::<io::Error>().map(io::Error::kind) {
                    Some(io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) | None => continue,
                    _ => return Err(error),
                },
            };
        let key = (source, destination);
        let mut active = sessions.borrow_mut();
        if let Some(sender) = active.get(&key) {
            let _ = sender.try_send(packet[..len].to_vec());
            continue;
        }
        if limits[family]
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < transparent::MAX_SESSIONS).then_some(count + 1)
            })
            .is_err()
        {
            continue;
        }
        let slot = UdpSlot(limits.clone(), family);
        let (sender, receiver) = flume::bounded(8);
        sender
            .try_send(packet[..len].to_vec())
            .expect("empty UDP queue");
        active.insert(key, sender);
        let sessions = sessions.clone();
        let endpoint = endpoint.clone();
        monoio::spawn(async move {
            let _slot = slot;
            let result = udp_session(&endpoint, key, receiver).await;
            sessions.borrow_mut().remove(&key);
            if let Err(error) = result {
                eprintln!("reality UDP {destination}: {error}");
            }
        });
    }
}

async fn udp_session(
    endpoint: &Endpoint,
    (source, destination): UdpKey,
    packets: flume::Receiver<Vec<u8>>,
) -> Result<()> {
    let server = resolve(&endpoint.server).await?;
    let (mut input, mut output) = ring::dial(
        server,
        &endpoint.cfg,
        endpoint.uuid,
        &destination.ip().to_string(),
        destination.port(),
        true,
    )
    .await?;
    let reply = transparent::socket(destination.is_ipv6(), true)?;
    reply.set_reuse_port(true)?;
    reply.bind(&destination.into())?;
    let reply = UdpSocket::from_std(reply.into())?;
    let remote_fd = input.fd;
    let upload = async {
        while let Ok(Ok(packet)) = monoio::time::timeout(UDP_IDLE, packets.recv_async()).await {
            let len = u16::try_from(packet.len()).map_err(|_| err("UDP packet too large"))?;
            let mut frame = Vec::with_capacity(packet.len() + 2);
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&packet);
            monoio::time::timeout(UDP_IDLE, output.write(&frame)).await??;
        }
        Ok(())
    };
    let download = async {
        let mut pending = Vec::new();
        loop {
            let read = monoio::time::timeout(UDP_IDLE, input.read()).await?;
            match read? {
                Packet::Data(data) => pending.extend(data),
                Packet::Eof => return Ok(()),
                Packet::Splice => return Err(err("UDP tunnel entered Vision direct mode")),
            }
            let mut offset = 0;
            while pending.len() - offset >= 2 {
                let len = usize::from(u16::from_be_bytes([pending[offset], pending[offset + 1]]));
                let end = offset + 2 + len;
                if end > pending.len() {
                    break;
                }
                let (sent, _) = reply
                    .send_to(pending[offset + 2..end].to_vec(), source)
                    .await;
                if sent? != len {
                    return Err(err("short UDP reply"));
                }
                offset = end;
            }
            pending.drain(..offset);
        }
    };
    use futures_util::future::{select, Either};
    let result = match select(std::pin::pin!(upload), std::pin::pin!(download)).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    };
    shutdown(remote_fd, libc::SHUT_RDWR);
    result
}

async fn relay(
    mut local: RingTransport<TcpStream>,
    mut remote_in: ring::Reader,
    mut remote_out: ring::Writer,
) -> Result<()> {
    let local_fd = local.get_ref().as_raw_fd();
    let remote_fd = remote_in.fd;
    let mut download_socket = RingTransport::new(clone_stream(local.get_ref())?);
    remote_out.write(&[]).await?;
    let upload = async {
        let mut buffer = Vec::new();
        let mut pending = Vec::new();
        while !remote_out.ready_to_splice() {
            buffer = local.read_chunk(buffer).await?;
            if buffer.is_empty() {
                if !pending.is_empty() {
                    remote_out.write(&pending).await?;
                }
                shutdown(remote_out.fd, libc::SHUT_WR);
                return Ok(());
            }
            if pending.is_empty() {
                write_vision_records(&mut remote_out, &buffer, &mut pending).await?;
            } else {
                let mut joined = std::mem::take(&mut pending);
                joined.extend_from_slice(&buffer);
                write_vision_records(&mut remote_out, &joined, &mut pending).await?;
            }
        }
        debug_assert!(pending.is_empty());
        splice_direction(local.get_ref(), remote_out.stream()).await
    };
    let download = async {
        loop {
            match remote_in.read().await? {
                Packet::Data(data) => download_socket.write_record(data).await?,
                Packet::Eof => {
                    shutdown(local_fd, libc::SHUT_WR);
                    return Ok(());
                }
                Packet::Splice => {
                    return splice_direction(remote_in.stream(), download_socket.get_ref()).await;
                }
            }
        }
    };
    match monoio::try_join!(upload, download) {
        Ok(_) => Ok(()),
        Err(error) => {
            shutdown(local_fd, libc::SHUT_RDWR);
            shutdown(remote_fd, libc::SHUT_RDWR);
            Err(error)
        }
    }
}

async fn write_vision_records(
    output: &mut ring::Writer,
    data: &[u8],
    pending: &mut Vec<u8>,
) -> Result<()> {
    for record in record_chunks(data) {
        // A completion can split an inner TLS record at any byte. Keep the
        // final fragment together while a complete record can arm Vision.
        if output.assembling_vision_record() && incomplete_tls_record(record) {
            pending.extend_from_slice(record);
            break;
        }
        output.write(record).await?;
    }
    Ok(())
}

fn incomplete_tls_record(data: &[u8]) -> bool {
    if !data
        .first()
        .is_some_and(|kind| (0x14..=0x17).contains(kind))
        || data.get(1).is_some_and(|&major| major != 3)
    {
        return false;
    }
    if data.len() < 5 {
        return true;
    }
    let body = usize::from(u16::from_be_bytes([data[3], data[4]]));
    body <= 18_432 && data.len() < 5 + body
}

async fn splice_direction(input: &TcpStream, output: &TcpStream) -> Result<()> {
    let output_fd = output.as_raw_fd();
    let result = splice_bytes(input, output).await;
    if result.is_err() {
        shutdown(input.as_raw_fd(), libc::SHUT_RDWR);
        shutdown(output_fd, libc::SHUT_RDWR);
    } else {
        shutdown(output_fd, libc::SHUT_WR);
    }
    result
}

async fn splice_bytes(input: &TcpStream, output: &TcpStream) -> Result<()> {
    let pipe = make_pipe()?;
    set_nonblocking(input.as_raw_fd())?;
    set_nonblocking(output.as_raw_fd())?;
    let mut transferred = 0;
    loop {
        let mut remaining = match splice_nonblocking(input.as_raw_fd(), pipe.w, SPLICE_BATCH) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                input.readable(false).await?;
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        while remaining > 0 {
            match splice_nonblocking(pipe.r, output.as_raw_fd(), remaining) {
                Ok(0) => return Err(err("Vision splice stopped with bytes in the pipe")),
                Ok(n) => {
                    crate::proxy::record_splice(n);
                    remaining -= n;
                    transferred += n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => output.writable(false).await?,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(())
                }
                Err(e) => return Err(e.into()),
            }
        }
        if transferred >= SPLICE_BATCH {
            // A continuously ready socket must give other ring tasks a turn.
            transferred = 0;
            let mut yielded = false;
            std::future::poll_fn(|cx| {
                if std::mem::replace(&mut yielded, true) {
                    std::task::Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
        }
    }
}

fn shutdown(fd: RawFd, direction: libc::c_int) {
    unsafe { libc::shutdown(fd, direction) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires Linux io_uring"]
    fn dns_worker_wakes_the_ring() {
        let mut runtime = build_runtime(monoio::blocking::DefaultThreadPool::new(1)).unwrap();
        runtime.block_on(async {
            let address = monoio::time::timeout(Duration::from_secs(5), resolve("localhost:80"))
                .await
                .unwrap()
                .unwrap();
            assert!(address.ip().is_loopback());
            assert_eq!(address.port(), 80);
        });
    }

    #[test]
    #[ignore = "requires Linux io_uring"]
    fn shared_ring_splice_preserves_duplex_data_and_half_closes_under_backpressure() {
        let mut runtime = build_runtime(monoio::blocking::DefaultThreadPool::new(1)).unwrap();
        runtime.block_on(async {
            let test = async {
                let mut sessions = Vec::new();
                for _ in 0..16 {
                    sessions.push(monoio::spawn(check_splice()));
                }
                for session in sessions {
                    session.await.unwrap();
                }
            };
            monoio::time::timeout(Duration::from_secs(15), test)
                .await
                .unwrap();
        });
    }

    async fn check_splice() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let left = TcpStream::connect_addr(address).await?;
        let (left_relay, _) = listener.accept().await?;
        let right = TcpStream::connect_addr(address).await?;
        let (right_relay, _) = listener.accept().await?;
        for socket in [&left_relay, &right_relay] {
            // Both socket owners outlive this borrowed descriptor.
            let fd = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
            socket2::SockRef::from(&fd).set_send_buffer_size(8192)?;
        }
        let left_output = clone_stream(&left_relay)?;
        let right_output = clone_stream(&right_relay)?;
        monoio::try_join!(
            splice_direction(&left_relay, &right_output),
            splice_direction(&right_relay, &left_output),
            exchange(left, 0xA1, 0xB2),
            exchange(right, 0xB2, 0xA1),
        )?;
        Ok(())
    }

    async fn exchange(stream: TcpStream, outgoing: u8, incoming: u8) -> Result<()> {
        const LEN: usize = 512 * 1024;
        let mut send = RingTransport::new(clone_stream(&stream)?);
        let mut receive = RingTransport::new(stream);
        let upload = async {
            send.write_record(vec![outgoing; LEN]).await?;
            shutdown(send.get_ref().as_raw_fd(), libc::SHUT_WR);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let download = async {
            let data = receive.read_body(LEN).await?;
            assert_eq!(data, vec![incoming; LEN]);
            assert!(receive.read_chunk(Vec::new()).await?.is_empty());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        monoio::try_join!(upload, download)?;
        Ok(())
    }
}
