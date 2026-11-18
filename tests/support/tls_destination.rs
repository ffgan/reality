use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::CertifiedKey;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

pub fn start() -> [String; 3] {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["example.com".into()])
            .expect("fixture certificate");
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .expect("fixture TLS configuration"),
    );
    let tls = config.clone();
    [
        listen(http),
        listen(move |socket| serve_tls(socket, tls.clone(), |stream| http(stream))),
        listen(move |socket| serve_tls(socket, config.clone(), |stream| duplex(stream))),
    ]
}

fn listen(serve: impl Fn(TcpStream) -> io::Result<()> + Send + Sync + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
    let address = listener.local_addr().unwrap().to_string();
    let serve = Arc::new(serve);
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else { break };
            let serve = serve.clone();
            thread::spawn(move || {
                let timeout = Some(Duration::from_secs(25));
                let _ = socket.set_read_timeout(timeout);
                let _ = socket.set_write_timeout(timeout);
                let _ = serve(socket);
            });
        }
    });
    address
}

fn serve_tls(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    serve: impl FnOnce(&mut StreamOwned<ServerConnection, TcpStream>) -> io::Result<()>,
) -> io::Result<()> {
    let conn = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, socket);
    let result = serve(&mut stream);
    stream.conn.send_close_notify();
    let _ = stream.flush();
    result
}

fn http(stream: impl Read + Write) -> io::Result<()> {
    let mut stream = BufReader::new(stream);
    loop {
        let mut request = String::new();
        if stream.read_line(&mut request)? == 0 {
            return Ok(());
        }
        let mut fields = request.split_whitespace();
        let (Some(method), Some(path), Some(version)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Ok(());
        };
        let mut close = version == "HTTP/1.0";
        let mut length = 0;
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line)? == 0 {
                return Ok(());
            }
            if line.trim().is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().map_err(io::Error::other)?;
                } else if key.eq_ignore_ascii_case("connection") {
                    close = value.trim().eq_ignore_ascii_case("close");
                }
            }
        }
        let body = match (method, path) {
            ("POST", _) => {
                let mut body = vec![0; length];
                stream.read_exact(&mut body)?;
                body
            }
            (_, "/small") => b"small-ok".to_vec(),
            (_, "/big") => vec![b'x'; 300_000],
            _ => b"tls-ok".to_vec(),
        };
        let socket = stream.get_mut();
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n",
            body.len()
        )?;
        if close {
            socket.write_all(b"Connection: close\r\n")?;
        }
        socket.write_all(b"\r\n")?;
        socket.write_all(&body)?;
        socket.flush()?;
        if close {
            return Ok(());
        }
    }
}

fn duplex(mut stream: impl Read + Write) -> io::Result<()> {
    const LEN: usize = 512 * 1024;
    stream.write_all(&vec![0xA1; LEN])?;
    stream.flush()?;
    stream.read_exact(&mut vec![0; LEN])
}
