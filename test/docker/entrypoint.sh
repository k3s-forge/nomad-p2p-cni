#!/bin/bash
set -e

MODE=${1:-server}
SEED_ADDR=${SEED_ADDR:-"127.0.0.1:9527"}
NODE_OVERLAY_IP=${NODE_OVERLAY_IP:-"10.244.0.1"}

echo "=== nomad-p2p test environment ($MODE) ==="

# Generate config based on mode
cat > /tmp/agent.json <<EOF
{
  "node_overlay_ip": "$NODE_OVERLAY_IP",
  "node_subnet": "10.244.1.0/24",
  "seeds": [
    {"addr": "$SEED_ADDR"}
  ],
  "tunnel_vni": 100,
  "tunnel_device": "gnv0",
  "psk": "test-psk-key-for-ci-only",
  "stun_servers": [],
  "listen_port": 9527,
  "ipsec_enabled": false,
  "mtu": 1400,
  "vip_enabled": false
}
EOF

case "$MODE" in
    seed)
        echo "[1/2] Starting nomad-p2p seed agent..."
        nomad-p2p agent --config /tmp/agent.json --seed-mode &
        AGENT_PID=$!
        echo "Seed agent started (PID: $AGENT_PID)"
        wait $AGENT_PID
        ;;
    agent)
        echo "[1/2] Starting nomad-p2p agent..."
        nomad-p2p agent --config /tmp/agent.json &
        AGENT_PID=$!
        echo "Agent started (PID: $AGENT_PID)"
        wait $AGENT_PID
        ;;
    server)
        echo "[1/4] Starting nomad-p2p seed agent..."
        nomad-p2p agent --config /tmp/agent.json --seed-mode &
        AGENT_PID=$!
        sleep 2

        echo "[2/4] Starting Consul..."
        consul agent -dev -bind=127.0.0.1 &
        CONSUL_PID=$!
        sleep 2

        echo "[3/4] Starting Nomad..."
        nomad agent -dev \
          -bind=0.0.0.0 \
          -network-interface=eth0 \
          -consul-address=127.0.0.1:8500 \
          -config=/etc/nomad/ &
        NOMAD_PID=$!
        sleep 3

        echo "[4/4] Waiting for Nomad..."
        for i in $(seq 1 30); do
          if nomad status >/dev/null 2>&1; then
            echo "Nomad ready!"
            break
          fi
          sleep 1
        done

        echo ""
        echo "=== Running tests ==="
        /opt/test/run-tests.sh

        echo ""
        echo "=== All tests passed! ==="
        echo "Keeping services running (PID: agent=$AGENT_PID consul=$CONSUL_PID nomad=$NOMAD_PID)"
        wait
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Usage: entrypoint.sh [seed|agent|server]"
        exit 1
        ;;
esac
