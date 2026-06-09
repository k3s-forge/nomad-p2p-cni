# nomad-p2p-cni

eBPF-based P2P CNI plugin for HashiCorp Nomad with zero-veth container networking.

## Architecture

```
Layer 3: Nomad Cluster (runs on gnv0 overlay)
    |
Layer 2: CNI Plugin (bpf_redirect_peer, zero veth)
    |
Layer 1: P2P Backbone (Geneve tunnel, STUN NAT, IPsec)
```

## Features

- **Zero veth**: `bpf_redirect_peer` bypasses virtual ethernet pairs
- **Geneve Overlay**: Kernel-native tunnel encapsulation
- **NAT Traversal**: STUN discovery + UDP hole punching + Seed relay fallback
- **Encryption**: Kernel IPsec (XFRM) transparent encryption
- **VIP Load Balancing**: cgroup/connect4 round-robin backend selection
- **Firewall**: TC ACL with per-source and per-port rules
- **PSK Authentication**: HMAC-SHA256 pre-shared key verification
- **Lazy Route Discovery**: Ringbuf-triggered on-demand route lookup

## Components

| Binary | Description |
|--------|-------------|
| `nomad-p2p-agent` | Per-node control plane daemon |
| `nomad-p2p-seed` | Route registry server (1-3 per cluster) |
| `nomad-p2p-cni` | CNI plugin binary for Nomad |

## Build

```bash
make all
```

Requires: Linux 5.10+, clang, Go 1.22+

## Quick Start

1. Deploy seed node:
```bash
nomad-p2p-seed -addr 0.0.0.0:9528 -psk "your-secret-key"
```

2. Configure agent on each node:
```bash
cp config/config.example.json /etc/nomad-p2p-cni/config.json
# Edit config.json with your node IP, seed addresses, PSK
nomad-p2p-agent -config /etc/nomad-p2p-cni/config.json
```

3. Configure Nomad to use the CNI plugin in job specs.

## License

MIT