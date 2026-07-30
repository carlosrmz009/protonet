# Protonet

Protonet is a Windows desktop demonstration of decentralized, encrypted
peer-to-peer propagation. Selecting an unflagged file computes SHA-256 and
BLAKE3, marks the file malicious, signs the canonical record with the local
Ed25519 identity, persists it to SQLite, and publishes the unchanged signed
record to every reachable peer.

The intelligence policy is deliberately simple: every correctly formed,
non-expired, non-replayed record with a valid origin signature is accepted as
malicious. Signatures authenticate origin and integrity; they do not introduce
voting, reputation, consensus, or verdict review.

## Security and network design

- A unique Ed25519 libp2p identity is generated on first launch. Its private
  key is encrypted with current-user Windows DPAPI in
  `%LOCALAPPDATA%\Protonet\identity.dat`.
- QUIC is preferred. TCP fallback always negotiates Noise and Yamux. Circuit
  Relay v2 carries the same authenticated, encrypted libp2p sessions.
- Gossipsub uses signed authenticity, strict asynchronous validation, the
  `protonet.flagged-files.v1` topic, and record IDs as message IDs.
- Application records use bounded deterministic postcard encoding and an
  Ed25519 origin signature. Forwarders never rewrite the signed record.
- LAN discovery uses mDNS only when all active Windows network profiles are
  Private or DomainAuthenticated. It is off on Public/unknown profiles unless
  explicitly enabled.
- WAN discovery uses a private Protonet Kademlia protocol plus Identify.
  AutoNAT, observed addresses, DCUtR, QUIC hole punching, and encrypted relay
  fallback handle restricted networks.
- Bootstrap nodes only introduce peers. They do not store authoritative
  verdicts or relay ordinary gossip, and existing peer links continue to work
  when bootstrap nodes disappear.
- Offline peers exchange day-bucket inventory digests and request only
  differing IDs and records. Every request, response, concurrent session, and
  duration is bounded.
- SQLite runs in WAL mode. Network writes cross a bounded 10,000-record queue
  and are committed in batches of at most 100 or 25 ms by a dedicated worker.

There is no shared network secret, plaintext production transport, subnet
sweep, hosted-topic integration, message queue, central signature API, or
fabricated peer address.

## Bootstrap and relay configuration

Independent operators start ordinary Protonet nodes, optionally with relay
service enabled. Configure at least three independently operated bootstrap
multiaddresses as a semicolon-separated environment variable:

```powershell
$env:PROTONET_BOOTSTRAP_PEERS="/dns4/bootstrap-a.example/udp/443/quic-v1/p2p/12D3...;/dns4/bootstrap-b.example/tcp/4001/p2p/12D3...;/ip6/2001:db8::10/udp/443/quic-v1/p2p/12D3..."
$env:PROTONET_RELAY_PEERS="/dns4/relay-a.example/tcp/4001/p2p/12D3..."
```

The application accepts DNS, IPv4, IPv6, QUIC, TCP, and circuit addresses.
Entries can be added or removed at runtime through `NetworkCommand`; no entry
has record authority. A relay operator sets `PROTONET_RELAY_SERVER=1`.
`PROTONET_MDNS=1` is an explicit override for mDNS on a profile that cannot be
classified automatically.

Protonet intentionally does not ship fake or project-controlled placeholder
peer IDs: deployments must insert the real `PeerId` advertised by each
independent operator.

## Build and test

```powershell
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo run --release
```

The Windows integration suite starts real local QUIC/Noise nodes, verifies
authenticated peer IDs, partition recovery through bounded direct sync, and
automatic signed Gossipsub propagation without a central service. Property and
load suites cover malformed frames, bounded allocation, replay floods,
duplicate database writes, 2/10/50/100/500-peer simulations, churn/loss, and
P50/P95/P99 reporting.

Nine `cargo-fuzz` targets live in `fuzz/fuzz_targets`:

```powershell
cargo install cargo-fuzz
cargo fuzz run flagged_record_decoder -- -runs=100000
cargo fuzz run signed_record_validator -- -runs=100000
```

Repeat for inventory, sync request/response, multiaddress, identity, database
record, and version targets. The ordinary property tests provide deterministic
CI fuzz coverage on Windows stable.

## Metrics

The network window displays actual `PeerId`s and known multiaddresses,
direct/relayed status, transport, RTT, reachability, DHT state, mesh size,
records and duplicates, invalid messages, database and queue size, byte
counters, and P50/P95/P99 validation/persistence/local-propagation latency.

Wall-clock timestamps in records are used only for expiry with a 15-minute skew
allowance. Local elapsed metrics use monotonic clocks. Cross-machine end-to-end
latency experiments require NTP-synchronized hosts and should be labeled as
clock-dependent.
