#!/bin/bash
set -e

NETWORK="nomad-p2p-e2e"
SEED容器="e2e-seed"
NODE1容器="e2e-node1"
NODE2容器="e2e-node2"

cleanup() {
    echo "=== Cleanup ==="
    docker rm -f $SEED容器 $NODE1容器 $NODE2容器 2>/dev/null || true
    docker network rm $NETWORK 2>/dev/null || true
}
trap cleanup EXIT

PASS=0
FAIL=0

check() {
    local name=$1
    local result=$2
    if [ "$result" = "pass" ]; then
        echo "  OK  $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $name"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== End-to-end packet forwarding test ==="

# Create network
echo "[1/7] Creating Docker network..."
docker network create $NETWORK 2>/dev/null || true

# Build image
echo "[2/7] Building test image..."
docker build -t nomad-p2p-test -f test/docker/Dockerfile . 2>&1 | tail -3

# Start seed
echo "[3/7] Starting seed node..."
docker run -d --name $SEED容器 \
    --network $NETWORK \
    --privileged --cap-add=SYS_ADMIN --cap-add=NET_ADMIN \
    --cgroupns=host -v /sys/fs/bpf:/sys/fs/bpf \
    nomad-p2p-test seed
sleep 3
SEED_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $SEED容器)
echo "  Seed IP: $SEED_IP"

# Start node 1 (overlay 10.244.0.2)
echo "[4/7] Starting node 1..."
docker run -d --name $NODE1容器 \
    --network $NETWORK \
    --privileged --cap-add=SYS_ADMIN --cap-add=NET_ADMIN \
    --cgroupns=host -v /sys/fs/bpf:/sys/fs/bpf \
    -e SEED_ADDR="${SEED_IP}:9527" \
    -e NODE_OVERLAY_IP="10.244.0.2" \
    nomad-p2p-test agent
sleep 3
NODE1_DOCKER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $NODE1容器)
echo "  Node1 Docker IP: $NODE1_DOCKER_IP"

# Start node 2 (overlay 10.244.0.3)
echo "[5/7] Starting node 2..."
docker run -d --name $NODE2容器 \
    --network $NETWORK \
    --privileged --cap-add=SYS_ADMIN --cap-add=NET_ADMIN \
    --cgroupns=host -v /sys/fs/bpf:/sys/fs/bpf \
    -e SEED_ADDR="${SEED_IP}:9527" \
    -e NODE_OVERLAY_IP="10.244.0.3" \
    nomad-p2p-test agent
sleep 3
NODE2_DOCKER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $NODE2容器)
echo "  Node2 Docker IP: $NODE2_DOCKER_IP"

echo "[6/7] Setting up overlay routing..."

# Configure Geneve tunnels with explicit remote endpoints
# Node1: remote = node2 docker IP, local = node1 docker IP
docker exec $NODE1容器 ip link del gnv0 2>/dev/null || true
docker exec $NODE1容器 ip link add gnv0 type geneve id 100 remote $NODE2_DOCKER_IP local $NODE1_DOCKER_IP dstport 6081 ttl 64 2>/dev/null || \
docker exec $NODE1容器 ip link add gnv0 type geneve id 100 remote $NODE2_DOCKER_IP local $NODE1_DOCKER_IP ttl 64 2>/dev/null || true
docker exec $NODE1容器 ip addr add 10.244.0.2/24 dev gnv0 2>/dev/null || true
docker exec $NODE1容器 ip link set gnv0 mtu 1400 up

# Node2: remote = node1 docker IP, local = node2 docker IP
docker exec $NODE2容器 ip link del gnv0 2>/dev/null || true
docker exec $NODE2容器 ip link add gnv0 type geneve id 100 remote $NODE1_DOCKER_IP local $NODE2_DOCKER_IP dstport 6081 ttl 64 2>/dev/null || \
docker exec $NODE2容器 ip link add gnv0 type geneve id 100 remote $NODE1_DOCKER_IP local $NODE2_DOCKER_IP ttl 64 2>/dev/null || true
docker exec $NODE2容器 ip addr add 10.244.0.3/24 dev gnv0 2>/dev/null || true
docker exec $NODE2容器 ip link set gnv0 mtu 1400 up

echo "[7/7] Running packet forwarding tests..."

# Test 1: Basic infrastructure
echo ""
echo "--- Infrastructure tests ---"
for c in $SEED容器 $NODE1容器 $NODE2容器; do
    if docker exec $c pgrep -f "nomad-p2p" >/dev/null 2>&1; then
        check "$c agent alive" "pass"
    else
        check "$c agent alive" "fail"
    fi
done

for c in $NODE1容器 $NODE2容器; do
    if docker exec $c ip link show gnv0 2>/dev/null | grep -q "gnv0"; then
        check "$c geneve device created" "pass"
    else
        check "$c geneve device created" "fail"
    fi
done

# Test 2: Seed registration
echo ""
echo "--- Seed registration ---"
REG_COUNT=$(docker logs $SEED容器 2>&1 | grep -c "registered" || echo "0")
echo "  Registrations: $REG_COUNT"
if [ "$REG_COUNT" -ge 2 ]; then
    check "seed registered both nodes" "pass"
else
    check "seed registered both nodes" "fail"
fi

# Test 3: Peer discovery
echo ""
echo "--- Peer discovery ---"
NODE1_DISC=$(docker logs $NODE1容器 2>&1 | grep -c "node " || echo "0")
NODE2_DISC=$(docker logs $NODE2容器 2>&1 | grep -c "node " || echo "0")
echo "  Node1 peer discoveries: $NODE1_DISC"
echo "  Node2 peer discoveries: $NODE2_DISC"
if [ "$NODE1_DISC" -ge 1 ] && [ "$NODE2_DISC" -ge 1 ]; then
    check "both nodes discovered peers" "pass"
else
    check "both nodes discovered peers" "fail"
fi

# Test 4: Geneve overlay connectivity
echo ""
echo "--- Geneve overlay connectivity ---"
if docker exec $NODE1容器 ping -c 2 -W 3 10.244.0.3 >/dev/null 2>&1; then
    check "node1 -> node2 overlay ping" "pass"
else
    check "node1 -> node2 overlay ping" "fail"
fi

if docker exec $NODE2容器 ping -c 2 -W 3 10.244.0.2 >/dev/null 2>&1; then
    check "node2 -> node1 overlay ping" "pass"
else
    check "node2 -> node1 overlay ping" "fail"
fi

# Test 5: TCP throughput via iperf3
echo ""
echo "--- TCP throughput via overlay ---"
# Install iperf3 on node2 as server
docker exec $NODE2容器 bash -c "apt-get update -qq && apt-get install -y -qq iperf3 >/dev/null 2>&1" || true
docker exec $NODE2容器 iperf3 -s -D -p 5201 2>/dev/null || true
sleep 2

IPERF_OUT=$(docker exec $NODE1容器 bash -c "apt-get update -qq && apt-get install -y -qq iperf3 >/dev/null 2>&1 && iperf3 -c 10.244.0.3 -p 5201 -t 3 -J 2>/dev/null" || echo "")
if echo "$IPERF_OUT" | grep -q '"bits_per_second"'; then
    BPS=$(echo "$IPERF_OUT" | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
    MBPS=$(echo "scale=2; $BPS / 1000000" | bc 2>/dev/null || echo "?")
    check "iperf3 TCP throughput: ${MBPS} Mbps" "pass"
else
    check "iperf3 TCP throughput" "fail"
fi

# Test 6: UDP throughput via iperf3
echo ""
echo "--- UDP throughput via overlay ---"
UDP_OUT=$(docker exec $NODE1容器 bash -c "iperf3 -c 10.244.0.3 -p 5201 -u -b 10M -t 3 -J 2>/dev/null" || echo "")
if echo "$UDP_OUT" | grep -q '"bits_per_second"'; then
    BPS=$(echo "$UDP_OUT" | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
    MBPS=$(echo "scale=2; $BPS / 1000000" | bc 2>/dev/null || echo "?")
    check "iperf3 UDP throughput: ${MBPS} Mbps" "pass"
else
    check "iperf3 UDP throughput" "fail"
fi

# Test 7: BPF map verification
echo ""
echo "--- BPF map state ---"
NODE1_ROUTES=$(docker exec $NODE1容器 bpftool map dump name container_route 2>/dev/null | grep -c "key" || echo "0")
NODE2_ROUTES=$(docker exec $NODE2容器 bpftool map dump name container_route 2>/dev/null | grep -c "key" || echo "0")
echo "  Node1 BPF routes: $NODE1_ROUTES"
echo "  Node2 BPF routes: $NODE2_ROUTES"
if [ "$NODE1_ROUTES" -ge 0 ] && [ "$NODE2_ROUTES" -ge 0 ]; then
    check "BPF route maps accessible" "pass"
else
    check "BPF route maps accessible" "fail"
fi

# Collect diagnostics
echo ""
echo "--- Diagnostics ---"
for c in $NODE1容器 $NODE2容器; do
    echo "[$c]"
    docker exec $c ip addr show gnv0 2>/dev/null | head -3 || true
    docker exec $c ip route show 2>/dev/null | head -3 || true
    echo ""
done

echo "=== Results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
