#!/bin/bash
set -e

MODE=${1:-server}

echo "=== nomad-p2p test environment ($MODE) ==="

# Start nomad-p2p agent
echo "[1/4] Starting nomad-p2p agent..."
nomad-p2p agent \
  --config /etc/nomad/agent.json \
  --seed-mode &
AGENT_PID=$!
sleep 2

# Start Consul
echo "[2/4] Starting Consul..."
consul agent -dev -bind=127.0.0.1 &
CONSUL_PID=$!
sleep 2

# Start Nomad
echo "[3/4] Starting Nomad..."
nomad agent -dev \
  -bind=0.0.0.0 \
  -network-interface=eth0 \
  -consul-address=127.0.0.1:8500 \
  -config=/etc/nomad/ &
NOMAD_PID=$!
sleep 3

# Wait for Nomad to be ready
echo "[4/4] Waiting for Nomad..."
for i in $(seq 1 30); do
  if nomad status >/dev/null 2>&1; then
    echo "Nomad ready!"
    break
  fi
  sleep 1
done

# Run tests
echo ""
echo "=== Running tests ==="
/opt/test/run-tests.sh

echo ""
echo "=== All tests passed! ==="
echo "Keeping services running (PID: agent=$AGENT_PID consul=$CONSUL_PID nomad=$NOMAD_PID)"

# Keep alive
wait
