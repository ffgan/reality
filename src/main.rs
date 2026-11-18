use std::env;
use std::net::TcpListener;
use std::process::ExitCode;

use reality::{parse_key, parse_short_id, parse_uuid, serve_daemon, Config, Endpoint};

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if let Some(path) = flag(&args, "config") {
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) => return fatal(e),
        };
        let config: serde_json::Value = match serde_json::from_slice(&data) {
            Ok(value) => value,
            Err(e) => return fatal(e),
        };
        let Some(config) = config.as_object() else {
            return fatal("config must be an object");
        };
        for (key, value) in config {
            if ![
                "listen", "server", "uuid", "sni", "pbk", "sid", "fp", "redirect", "tproxy",
            ]
            .contains(&key.as_str())
            {
                return fatal(format!("unknown config field: {key}"));
            }
            let value = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => return fatal("invalid config value"),
            };
            args.push(format!("--{key}"));
            args.push(value);
        }
    }
    let listen = flag(&args, "listen").unwrap_or_else(|| "127.0.0.1:10808".to_string());
    let server = flag(&args, "server");
    let uuid = flag(&args, "uuid");
    let sni = flag(&args, "sni");
    let pbk = flag(&args, "pbk");
    let sid = flag(&args, "sid").unwrap_or_default();
    let fp = flag(&args, "fp").unwrap_or_else(|| "chrome".to_string());
    if fp != "chrome" {
        return fatal("only chrome fingerprint is supported");
    }
    let redirect = match flag(&args, "redirect") {
        Some(port) => match port.parse::<u16>() {
            Ok(port) if port != 0 => Some(port),
            _ => return fatal("invalid redirect port"),
        },
        None => None,
    };
    let tproxy = flag(&args, "tproxy")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let (Some(server), Some(uuid), Some(sni), Some(pbk)) = (server, uuid, sni, pbk) else {
        eprintln!("usage: reality -server host:port -uuid UUID -sni name -pbk BASE64 [-sid HEX] [-fp chrome] [-listen 127.0.0.1:10808]");
        return ExitCode::from(2);
    };
    let id = match parse_uuid(&uuid) {
        Ok(id) => id,
        Err(e) => return fatal(e),
    };
    let public_key = match parse_key(&pbk) {
        Ok(key) => key,
        Err(e) => return fatal(e),
    };
    let short_id = match parse_short_id(&sid) {
        Ok(id) => id,
        Err(e) => return fatal(e),
    };
    if args.iter().any(|arg| arg == "--check") {
        return ExitCode::SUCCESS;
    }
    let ln = match TcpListener::bind(&listen) {
        Ok(ln) => ln,
        Err(e) => return fatal(e),
    };
    eprintln!("reality socks5 {listen} -> {server} sni {sni} fp {fp}");
    let endpoint = Endpoint {
        server,
        cfg: Config {
            server_name: sni,
            public_key,
            short_id,
        },
        uuid: id,
    };
    if let Err(error) = serve_daemon(ln, endpoint, redirect.map(|port| (port, tproxy))) {
        return fatal(error);
    }
    ExitCode::SUCCESS
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let dashed = format!("-{name}");
    let dashed2 = format!("--{name}");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == &dashed || arg == &dashed2 {
            return iter.next().cloned();
        }
        for prefix in [&dashed, &dashed2] {
            let with_eq = format!("{prefix}=");
            if let Some(rest) = arg.strip_prefix(&with_eq) {
                return Some(rest.to_string());
            }
        }
    }
    None
}

fn fatal(err: impl std::fmt::Display) -> ExitCode {
    eprintln!("reality: {err}");
    ExitCode::from(1)
}
