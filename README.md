# nomad-p2p-cni

eBPF-based P2P CNI plugin for HashiCorp Nomad with Geneve overlay tunnels, STUN NAT traversal, IPsec encryption, VIP load balancing, firewall ACLs, and seed relay — all in a single unified binary.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    nomad-p2p agent                    │
├──────────┬──────────┬──────────┬──────────┬──────────┤
│  BPF     │  STUN    │  Seed    │  VIP     │ Firewall │
│  (data   │  (NAT    │  (discov │  (load   │  (ACL    │
│   plane) │   type)  │   ery)   │  bal)    │   mgmt)  │
├──────────┴──────────┴──────────┴──────────┴──────────┤
│  Config Hot-Reload  │  Metrics  │  IPsec  │  CNI     │
└──────────────────────────────────────────────────────┘
```

### Data plane (BPF)
- **Geneve overlay**: kernel-level tunnel with `bpf_redirect` via `GENEVE_IFINDEX_MAP`
- **Container route**: `CONTAINER_ROUTE_MAP` (overlay IP → local ifindex)
- **Node discovery**: `NODE_DYNAMIC_MAP` (overlay IP → public endpoint)
- **Route miss**: `ROUTE_MISS_RINGBUF` — kernel notifies userspace of unknown destinations
- **VIP balancer**: `cgroup/connect4` — round-robin load balancing
- **Firewall**: TC ingress with `ACL_MAP`, `PORT_ACL_MAP`, default allow/deny

### Control plane (Go)
| Component | File | Responsibility |
|-----------|------|---------------|
| Agent     | `agent.go` | Struct, lifecycle, NAT type |
| BPF       | `bpf.go` | BPF load/attach/pin, interface detection |
| Protocol  | `protocol.go` | UDP listener, HMAC anti-replay, route miss pipeline, ping/pong, relay |
| Seed      | `seed.go` | Registry, TTL cleanup, heartbeat, peer health, ping loop |
| STUN      | `stun.go` | NAT type detection (symmetric vs easy), public IP discovery, refresh |
| Geneve    | `geneve.go` | Geneve device setup |
| VIP       | `vip.go` | Static & Consul backend merge, BPF map updates |
| Firewall  | `firewall.go` | ACL load/reload |
| Reload    | `reload.go` | Config hot-reload (5s mtime polling) |
| Metrics   | `metrics.go` | Prometheus `/metrics`, JSON `/health` |
| IPsec     | `ipsec.go` | SA management, rotation |
| CNI       | `cni.go` | ADD/DEL with veth TC, container state tracking |
| Consul    | `consul.go` | VIP backend discovery |
| Config    | `config/` | Struct, validation, defaults |

## Features

### NAT traversal
- **STUN**: queries 2 STUN servers from same socket, compares mapped ports — different = symmetric, same = easy NAT
- **NATType propagation**: carried in `PeerInfo`, `NodeRegistration`, `Message` headers
- **Ping/pong direct connectivity check**: periodic (30s) ping all peers, update `PingOK`/`PingLastSuccess`
- **Relay fallback**: symmetric NAT peers query relay-capable (easy NAT) peers via seed

### Lazy route discovery
Prevents storm/flood on large cluster startup:

```
BPF route_miss → ringbuf → consumeRouteMiss (producer)
                                    │ non-blocking write
                            missCh (4096 buffer)
                                    │
                            drainRouteMissBatch (consumers)
                                    │ 100ms window or 256 cap → flush
                            flushRouteMissBatch
                                    │ per-IP 5s cooldown → batch query seed
```

- `lazy_discovery: true` (default): only register at boot, no query-all
- Channel buffer (4096) between ringbuf and query sender absorbs bursts
- `routeMissCooldown` (5s): same IP not re-queried within window
- Channel full = non-blocking drop with `route_miss_drops` counter
- `peerHealthLoop` cleans stale (>10s) pending entries

### HMAC anti-replay
- 16-byte header: 8-byte timestamp + 8-byte random nonce
- HMAC-SHA256 over header+payload
- Receiver validates timestamp within 5min window
- Per-registry nonce dedup with TTL eviction

### VIP load balancing
- **Static backends**: configured via `vip_backends` in config
- **Consul backends**: discovered via consul with `?passing=true` health filter
- **Hot-reload**: file mtime polling (5s), content comparison triggers `updateVIPsFromConfig`

### Firewall ACLs
- **Allowed sources**: source IP whitelist
- **Allowed ports**: protocol+port rules
- **Default policy**: `allow` or `deny`
- **Hot-reload**: iterate+Delete (not Close) to avoid breaking BPF map

### IPsec encryption
- XFRM SA pair: one inbound + one outbound per peer
- SPI + key from config
- Rotation: new SA before old deleted (no encryption gap)

### CNI
- `ADD`: creates veth pair, attaches TC ingress/egress, stores container ID → IP in `/var/run/nomad-p2p/`
- `DEL`: reads container state, deletes route from `CONTAINER_ROUTE_MAP`, cleans up veth

### Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `nomad_p2p_peers_total` | Gauge | Connected peers |
| `nomad_p2p_seed_connections` | Gauge | Active seed connections |
| `nomad_p2p_uptime_seconds` | Counter | Agent uptime |
| `nomad_p2p_nat_type` | Gauge | 0=unknown, 1=easy, 2=symmetric |
| `nomad_p2p_route_misses_total` | Counter | Route miss events |
| `nomad_p2p_route_miss_drops_total` | Counter | Dropped (channel full) |
| `nomad_p2p_hmac_failures_total` | Counter | HMAC verification failed |
| `nomad_p2p_replay_rejected_total` | Counter | Anti-replay rejected |
| `nomad_p2p_stun_refreshes_total` | Counter | STUN refresh cycles |

## Config

See `config/config.example.json` for a full example.

```json
{
  "node_overlay_ip": "10.244.0.1",
  "node_subnet": "10.244.1.0/24",
  "seeds": [{"addr": "seed1.example.com:9528"}],
  "tunnel_vni": 100,
  "tunnel_device": "gnv0",
  "psk": "your-pre-shared-key",
  "stun_servers": ["stun.l.google.com:19302"],
  "listen_port": 9527,
  "stun_refresh_interval": 120,
  "lazy_discovery": true,
  "route_miss_max_pending": 256,
  "ipsec_enabled": false,
  "ipsec_spi": 4096,
  "ipsec_key": "0123456789abcdef0123456789abcdef",
  "cni_bin_path": "/opt/cni/bin/nomad-p2p-cni",
  "mtu": 1420,
  "vip_enabled": false,
  "vip_watch_list": [],
  "vip_backends": [
    {"vip": "10.100.0.50", "backends": ["10.244.0.10", "10.244.1.10"]}
  ],
  "consul_addr": "",
  "consul_token": "",
  "firewall_enabled": false,
  "default_policy": "allow",
  "allowed_sources": [],
  "allowed_ports": [],
  "metrics_port": 9090
}
```

## Build

Requires Linux 5.10+, clang, llvm, libbpf.

```bash
make build-bpf   # compile BPF C → .o
make build-bin   # go build
```

Or all at once: `make`

## Run

```
nomad-p2p agent --config /etc/nomad-p2p/config.json
nomad-p2p seed  --config /etc/nomad-p2p/config.json  # --seed-mode flag
nomad-p2p cni                                          # stdin CNI plugin
nomad-p2p version
```

## Tests

```bash
# CI: build + unit vet + cluster test + multi-node + E2E packet forwarding
# See .github/workflows/build.yml

# Local Docker test
docker build -t nomad-p2p-test -f test/docker/Dockerfile .
test/docker/run-tests.sh
```

## Requirements

- Linux 5.10+ (bpf_redirect, Geneve, ringbuf)
- eBPF filesystem mounted (`/sys/fs/bpf`)
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`
- For Nomad integration: `cni_bin_path` in agent config, Nomad CNI config pointing to the plugin

## License

AGPL-3.0
