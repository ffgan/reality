//! Standard VLESS UDP framing over REALITY. UDP has no Vision padding.
use crate::{err, Config, ReadOut, Result, Tunnel};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

pub struct UdpTunnel {
    tunnel: Tunnel,
    pending: Mutex<VecDeque<u8>>,
    sending: Mutex<()>,
}

impl UdpTunnel {
    pub fn dial(server: &str, cfg: &Config, uuid: [u8; 16], host: &str, port: u16) -> Result<Self> {
        let tunnel = Tunnel::dial_udp(server, cfg, uuid, host, port)?;
        tunnel.set_timeout(Some(Duration::from_secs(60)))?;
        Ok(Self {
            tunnel,
            pending: Mutex::new(VecDeque::new()),
            sending: Mutex::new(()),
        })
    }

    pub fn send(&self, packet: &[u8]) -> Result<()> {
        let _guard = self.sending.lock().expect("UDP writer");
        let len = u16::try_from(packet.len()).map_err(|_| err("UDP packet too large"))?;
        let mut frame = Vec::with_capacity(packet.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(packet);
        self.tunnel.write_all_chunks(&frame)
    }

    pub fn recv(&self) -> Result<Vec<u8>> {
        let mut pending = self.pending.lock().expect("UDP reader");
        loop {
            if pending.len() >= 2 {
                let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                if pending.len() >= len + 2 {
                    pending.drain(..2);
                    return Ok(pending.drain(..len).collect());
                }
            }
            let mut buf = [0u8; 16384];
            match self.tunnel.read_some(&mut buf)? {
                ReadOut::Data(n) => pending.extend(&buf[..n]),
                ReadOut::Eof => return Err(err("UDP tunnel EOF")),
                ReadOut::Splice => return Err(err("UDP must not splice")),
            }
        }
    }

    pub fn shutdown(&self) {
        self.tunnel.shutdown();
    }
}
