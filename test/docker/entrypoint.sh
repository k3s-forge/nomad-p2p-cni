#!/bin/bash
set -e

MODE=${1:-server}
SEED_ADDR=${SEED_ADDR:-"127.0.0.1:9527"}
NODE_OVERLAY_IP=${NODE_OVERLAY_IP:-"10.244.0.1"}

echo "=== nomad-p2p ($MODE) | overlay=$NODE_OVERLAY_IP seed=$SEED_ADDR ==="

cat > /etc/nomad-p2p/config.json <<EOF
{
  "node_overlay_ip": "$NODE_OVERLAY_IP",
  "node_subnet": "10.244.1.0/24",
  "seeds": [{"addr": "$SEED_ADDR"}],
  "tunnel_vni": 100,
  "tunnel_device": "gnv0",
  "psk": "test-psk-key-for-ci-only",
  \"stun_servers\": [],
  \"listen_port\": 9527,
  \"p2p_port\": 0,
  "ipsec_enabled": false,
  "vip_enabled": false,
  "firewall_enabled": false,
  "metrics_port": 0,
  "mtu": 1400,
  "cni_bin_path": "/opt/cni/bin/nomad-p2p-cni"
}
EOF

case "$MODE" in
    seed)
        echo "[seed] Starting P2P seed agent..."
        exec nomad-p2p-agent-rust Seed --config /etc/nomad-p2p/config.json
        ;;

    agent)
        echo "[agent] Starting P2P agent..."
        exec nomad-p2p-agent-rust Agent --config /etc/nomad-p2p/config.json
        ;;

    nomad-seed)
        echo "[1/3] Starting P2P seed agent + Nomad server..."
        nomad-p2p-agent-rust Seed --config /etc/nomad-p2p/config.json &
        AGENT_PID=$!
        sleep 2

        echo "[2/3] Starting Nomad server..."
        nomad agent -server \
          -bind=0.0.0.0 \
          -bootstrap-expect=1 \
          -data-dir=/tmp/nomad-server \
          -config=/etc/nomad/client.hcl \
          > /tmp/nomad-server.log 2>&1 &
        NOMAD_PID=$!
        sleep 5

        echo "[3/3] Verifying Nomad server..."
        for i in $(seq 1 30); do
          if nomad server members 2>/dev/null | grep -q alive; then
            echo "  Nomad server ready!"
            break
          fi
          sleep 1
        done
        nomad server members 2>/dev/null || true

        /opt/test/run-tests.sh
        wait
        ;;

    nomad-client)
        echo "[1/2] Starting P2P agent..."
        nomad-p2p-agent-rust Agent --config /etc/nomad-p2p/config.json &
        AGENT_PID=$!
        sleep 2

        echo "[2/2] Starting Nomad client..."
        nomad agent -client \
          -bind=0.0.0.0 \
          -data-dir=/tmp/nomad-client \
          -servers="${NOMAD_SERVER:-127.0.0.1}:4647" \
          -config=/etc/nomad/client.hcl \
          > /tmp/nomad-client.log 2>&1 &
        NOMAD_PID=$!
        sleep 3

        echo "  Nomad client started (PID: $NOMAD_PID)"
        wait
        ;;

    server)
        # Single-node dev mode (legacy)
        echo "[1/3] Starting P2P agent (seed mode)..."
        nomad-p2p-agent-rust Seed --config /etc/nomad-p2p/config.json &
        AGENT_PID=$!
        sleep 2

        echo "[2/3] Starting Nomad dev..."
        nomad agent -dev \
          -bind=0.0.0.0 \
          -network-interface=eth0 \
          -config=/etc/nomad/client.hcl \
          > /tmp/nomad.log 2>&1 &
        NOMAD_PID=$!
        sleep 5

        echo "[3/3] Waiting for Nomad..."
        for i in $(seq 1 30); do
          if nomad status >/dev/null 2>&1; then
            echo "  Nomad ready!"
            break
          fi
          sleep 1
        done

        /opt/test/run-tests.sh

        wait
        ;;

    test-persistence)
        echo "[1/3] Starting P2P agent + Nomad server..."
        nomad-p2p-agent-rust Seed --config /etc/nomad-p2p/config.json &
        AGENT_PID=$!
        sleep 2

        echo "[2/3] Starting Nomad server..."
        nomad agent -server \
          -bind=0.0.0.0 \
          -bootstrap-expect=1 \
          -data-dir=/tmp/nomad-server \
          -config=/etc/nomad/client.hcl \
          > /tmp/nomad-server.log 2>&1 &
        NOMAD_PID=$!
        sleep 5

        echo "[3/3] Waiting for Nomad..."
        for i in $(seq 1 30); do
          if nomad server members 2>/dev/null | grep -q alive; then break; fi
          sleep 1
        done
        nomad server members 2>/dev/null || true

        /opt/test/test-persistence.sh
        EXIT_CODE=$?
        echo "Persistence test exit: $EXIT_CODE"
        exit $EXIT_CODE
        ;;
    *)
        echo "Usage: entrypoint.sh [seed|agent|nomad-seed|nomad-client|server]"
        exit 1
        ;;
esac
