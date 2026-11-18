# reality

Linux VLESS REALITY client with Vision TCP forwarding and standard VLESS UDP.
The Rust implementation is in `src/`; the Go files are the earlier client.

## OpenWrt / Passwall

The companion Passwall backend provides a **Reality (Rust)** node type. It
generates a private JSON configuration, runs this binary under procd, and keeps
nftables policy, DNS forwarding, subscriptions and node selection in Passwall.
No Xray process or binary is needed for these nodes.

Supported node: VLESS + REALITY, raw TCP transport, `xtls-rprx-vision`, Chrome
fingerprint, no extra VLESS encryption, ECH, ML-DSA verification, finalmask or
proxy chain. Unsupported settings fail validation instead of being ignored.

The daemon provides:

- A SOCKS5 CONNECT listener for TCP.
- IPv4/IPv6 transparent TCP, using REDIRECT or TProxy.
- IPv4/IPv6 UDP TProxy with original destination recovery and source-preserving
  replies. UDP uses VLESS command 2 over encrypted REALITY, without Vision
  padding. It does not use XUDP multiplexing.
- Upstream bypass marking before connect, and marked transparent replies.
- Bounded UDP queues and at most 64 UDP sessions per address family. Sessions
  expire after 60 seconds without uplink traffic; inactive/downstream-silent
  tunnels also expire. Each session has its own encrypted connection.

UDP policy remains controlled by Passwall; existing port block rules still
apply. SOCKS5 UDP ASSOCIATE and an HTTP proxy listener are not implemented.

Passwall creates the static nftables country sets before starting ChinaDNS,
checks the DNS listener before redirecting queries, and lets procd restart the
native core after an exit.

## Build and run

```sh
cargo build --release --bin reality
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=ld.lld \
  RUSTFLAGS='-C linker-flavor=ld' \
  cargo build --release --target aarch64-unknown-linux-musl --bin reality
```

For the Cortex-A53 OpenWrt router, build with the ARMv8 AES and PMULL backends enabled:

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=ld.lld \
  RUSTFLAGS='-C linker-flavor=ld -C target-cpu=cortex-a53 --cfg aes_armv8 --cfg polyval_armv8' \
  cargo build --locked --release --target aarch64-unknown-linux-musl --bin reality
```

After Vision switches to raw TCP, both relay directions use Linux splice.
When io_uring setup fails, the relay uses poll and nonblocking splice.

Example private configuration (`chmod 600 /path/to/config.json`):

```json
{
  "server": "198.51.100.1:443",
  "uuid": "42000000-0000-0000-0000-000000000000",
  "sni": "example.com",
  "pbk": "REPLACE_WITH_SERVER_PUBLIC_KEY",
  "sid": "",
  "listen": "127.0.0.1:1070",
  "redirect": "1041",
  "tproxy": false
}
```

```sh
reality --config /path/to/config.json --check
REALITY_OUTBOUND_MARK=255 reality --config /path/to/config.json
```

Transparent sockets and socket marking require root or the corresponding Linux
network capabilities. Firewall and policy routing rules must be supplied by
Passwall. The command-line flags `-server`, `-uuid`, `-sni`, `-pbk`, `-sid`,
`-listen`, `-redirect` and `-tproxy true` are also supported.

## Verification

`cargo test` runs parser/framing tests and a local interoperability suite when
the official Xray reference binary is available at `/tmp/xray-bin`. That binary
is a test server only. The suite covers TCP/Vision, concurrent and duplex
transfers, shutdowns, and repeated UDP round trips to a local echo server using
a Vision-configured account.

The optional device probe does not need Xray or a C cross compiler:

```sh
cargo build --release --features device-test --bin reality-udp-probe
reality-udp-probe /path/to/private/config.json
reality-udp-probe --stun
```

The first probe checks repeated UDP DNS replies through REALITY; the second
sends ordinary UDP through the router's firewall and reports the STUN-mapped
exit IP, so transparent UDP can be distinguished from a direct connection.
