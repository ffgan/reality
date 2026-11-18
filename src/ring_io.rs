//! Owned-buffer socket I/O for TLS operations on the shared ring.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

use monoio::buf::IoBufMut;
use monoio::io::{AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt};

use monoio::net::TcpStream;
use socket2::SockRef;

use crate::tls::{self, Session, Transport};
use crate::tunnel::upstream_socket;
use crate::{Config, Result};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn connect_upstream(addr: SocketAddr) -> Result<TcpStream> {
    let socket = upstream_socket(addr)?;
    socket.set_nonblocking(true)?;
    let pending = match socket.connect(&addr.into()) {
        Ok(()) => false,
        Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => true,
        Err(error) => return Err(error.into()),
    };
    let standard: std::net::TcpStream = socket.into();
    standard.set_nodelay(true)?;
    let stream = TcpStream::from_std(standard)?;
    if pending {
        monoio::time::timeout(UPSTREAM_TIMEOUT, stream.writable(false)).await??;
        // The stream keeps the borrowed descriptor open during SO_ERROR.
        let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
        if let Some(error) = SockRef::from(&fd).take_error()? {
            return Err(error.into());
        }
    }
    Ok(stream)
}

pub(crate) async fn handshake_upstream(
    addr: SocketAddr,
    config: &Config,
) -> Result<(TcpStream, Session)> {
    let mut transport = RingTransport::new(connect_upstream(addr).await?);
    let session = monoio::time::timeout(
        UPSTREAM_TIMEOUT,
        tls::handshake_async(&mut transport, config),
    )
    .await??;
    Ok((transport.into_inner(), session))
}

pub(crate) struct RingTransport<T> {
    stream: T,
    buffer: Vec<u8>,
    read_ahead: Option<ReadAhead>,
}

#[derive(Default)]
struct ReadAhead {
    buffer: Vec<u8>,
    offset: usize,
}

impl<T> RingTransport<T> {
    pub(crate) fn new(stream: T) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
            read_ahead: None,
        }
    }

    pub(crate) fn enable_read_ahead(&mut self) {
        self.read_ahead.get_or_insert_with(ReadAhead::default);
    }

    pub(crate) fn get_ref(&self) -> &T {
        &self.stream
    }

    pub(crate) fn into_inner(self) -> T {
        self.stream
    }
}

pub(crate) fn clone_stream(stream: &TcpStream) -> io::Result<TcpStream> {
    // The source stream remains alive until its descriptor has been duplicated.
    let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    TcpStream::from_std(std::net::TcpStream::from(fd.try_clone_to_owned()?))
}

impl<T: AsyncReadRent> RingTransport<T> {
    async fn buffered_read(&mut self, output: &mut [u8]) -> io::Result<()> {
        let ahead = self.read_ahead.as_mut().expect("read-ahead enabled");
        let mut written = 0;
        while written < output.len() {
            if ahead.offset == ahead.buffer.len() {
                let mut buffer = std::mem::take(&mut ahead.buffer);
                buffer.clear();
                buffer.reserve(32 * 1024);
                let (result, filled) = self.stream.read(buffer.slice_mut(..32 * 1024)).await;
                ahead.buffer = filled.into_inner();
                ahead.offset = 0;
                match result {
                    Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            let count = (ahead.buffer.len() - ahead.offset).min(output.len() - written);
            output[written..written + count]
                .copy_from_slice(&ahead.buffer[ahead.offset..ahead.offset + count]);
            written += count;
            ahead.offset += count;
        }
        Ok(())
    }

    pub(crate) async fn read_chunk(&mut self, mut buffer: Vec<u8>) -> io::Result<Vec<u8>> {
        buffer.clear();
        buffer.reserve(32 * 1024);
        let (result, buffer) = self.stream.read(buffer.slice_mut(..32 * 1024)).await;
        result.map(|_| buffer.into_inner())
    }
}

impl<T: AsyncReadRent + AsyncWriteRent> Transport for RingTransport<T> {
    async fn read_exact(&mut self, output: &mut [u8]) -> io::Result<()> {
        if self.read_ahead.is_some() {
            return self.buffered_read(output).await;
        }
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.clear();
        buffer.reserve(output.len());
        let (result, buffer) = self
            .stream
            .read_exact(buffer.slice_mut(..output.len()))
            .await;
        let buffer = buffer.into_inner();
        if result.is_ok() {
            output.copy_from_slice(&buffer);
        }
        self.buffer = buffer;
        result.map(|_| ())
    }

    async fn write_all(&mut self, input: &[u8]) -> io::Result<()> {
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.clear();
        buffer.extend_from_slice(input);
        let (result, buffer) = self.stream.write_all(buffer).await;
        self.buffer = buffer;
        result.map(|_| ())
    }

    async fn read_body(&mut self, len: usize) -> io::Result<Vec<u8>> {
        if self.read_ahead.is_some() {
            let mut body = vec![0; len];
            self.buffered_read(&mut body).await?;
            return Ok(body);
        }
        let body = Vec::with_capacity(len).slice_mut(..len);
        let (result, body) = self.stream.read_exact(body).await;
        result.map(|_| body.into_inner())
    }

    async fn write_record(&mut self, record: Vec<u8>) -> io::Result<()> {
        let (result, _) = self.stream.write_all(record).await;
        result.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monoio::net::TcpListener;

    #[test]
    #[ignore = "requires Linux io_uring"]
    fn handshake_sends_client_hello_and_reports_peer_close() {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .with_entries(256)
            .enable_timer()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let handshake = monoio::spawn(async move {
                handshake_upstream(
                    address,
                    &Config {
                        server_name: "example.com".into(),
                        public_key: [9; 32],
                        short_id: [0; 8],
                    },
                )
                .await
            });
            let (socket, _) = listener.accept().await.unwrap();
            let mut transport = RingTransport::new(socket);
            let mut header = [0; 5];
            transport.read_exact(&mut header).await.unwrap();
            assert_eq!(header[..3], [0x16, 0x03, 0x01]);
            let mut body = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            transport.read_exact(&mut body).await.unwrap();
            assert_eq!(body.first(), Some(&1));
            drop(transport);
            let error = handshake.await.err().expect("peer closed during handshake");
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::UnexpectedEof
            );
        });
    }

    #[test]
    #[ignore = "requires Linux io_uring"]
    fn ring_transport_round_trip_and_short_read() {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .with_entries(256)
            .enable_timer()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let client = monoio::spawn(async move {
                let mut transport = RingTransport::new(connect_upstream(address).await.unwrap());
                transport.write_all(b"hel").await.unwrap();
                transport.write_all(b"lo").await.unwrap();
                let mut reply = [0; 5];
                transport.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"world");
            });
            let (socket, _) = listener.accept().await.unwrap();
            let mut transport = RingTransport::new(socket);
            let mut request = [0; 5];
            transport.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            transport.write_all(b"world").await.unwrap();
            drop(transport.into_inner());
            client.await;
        });
    }
}
