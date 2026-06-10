#!/bin/bash
set -e

NETWORK="nomad-p2p-test"
SEED容器="seed-node"
NODE1容器="test-node-1"
NODE2容器="test-node-2"

cleanup() {
    echo "Cleaning up..."
    docker rm -f $SEED容器 $NODE1容器 $NODE2容器 2>/dev/null || true
    docker network rm $NETWORK 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Multi-node P2P cluster test ==="

# Create network
echo "[1/6] Creating Docker network..."
docker network create $NETWORK 2>/dev/null || true

# Build image
echo "[2/6] Building test image..."
docker build -t nomad-p2p-test -f test/docker/Dockerfile . 2>&1 | tail -3

# Start seed node
echo "[3/6] Starting seed node..."
docker run -d --name $SEED容器 \
    --network $NETWORK \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=NET_ADMIN \
    --cgroupns=host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    nomad-p2p-test seed
sleep 3

# Verify seed is running
SEED_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $SEED容器)
echo "  Seed IP: $SEED_IP"

# Start node 1
echo "[4/6] Starting node 1..."
docker run -d --name $NODE1容器 \
    --network $NETWORK \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=NET_ADMIN \
    --cgroupns=host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -e SEED_ADDR="${SEED_IP}:9527" \
    -e NODE_OVERLAY_IP="10.244.0.2" \
    nomad-p2p-test agent
sleep 3

# Start node 2
echo "[5/6] Starting node 2..."
docker run -d --name $NODE2容器 \
    --network $NETWORK \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=NET_ADMIN \
    --cgroupns=host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -e SEED_ADDR="${SEED_IP}:9527" \
    -e NODE_OVERLAY_IP="10.244.0.3" \
    nomad-p2p-test agent
sleep 3

# Verify cluster
echo "[6/6] Verifying cluster..."

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

# Test: seed agent running
if docker exec $SEED容器 pgrep -f "nomad-p2p-agent-rust Seed" >/dev/null 2>&1; then
    check "seed agent running" "pass"
else
    check "seed agent running" "fail"
fi

# Test: node1 agent running
if docker exec $NODE1容器 pgrep -f "nomad-p2p-agent-rust Agent" >/dev/null 2>&1; then
    check "node1 agent running" "pass"
else
    check "node1 agent running" "fail"
fi

# Test: node2 agent running
if docker exec $NODE2容器 pgrep -f "nomad-p2p-agent-rust Agent" >/dev/null 2>&1; then
    check "node2 agent running" "pass"
else
    check "node2 agent running" "fail"
fi

# Test: seed UDP listening
if docker exec $SEED容器 ss -ulnp 2>/dev/null | grep -q ":9527"; then
    check "seed UDP 9527" "pass"
else
    check "seed UDP 9527" "fail"
fi

# Test: node1 UDP listening
if docker exec $NODE1容器 ss -ulnp 2>/dev/null | grep -q ":9527"; then
    check "node1 UDP 9527" "pass"
else
    check "node1 UDP 9527" "fail"
fi

# Test: node2 UDP listening
if docker exec $NODE2容器 ss -ulnp 2>/dev/null | grep -q ":9527"; then
    check "node2 UDP 9527" "pass"
else
    check "node2 UDP 9527" "fail"
fi

# Test: seed geneve device
if docker exec $SEED容器 ip link show gnv0 2>/dev/null | grep -q "gnv0"; then
    check "seed geneve device" "pass"
else
    check "seed geneve device" "fail"
fi

# Test: node1 binary version
VERSION=$(docker exec $NODE1容器 nomad-p2p-agent-rust Version 2>/dev/null || echo "")
if echo "$VERSION" | grep -q "nomad-p2p"; then
    check "node1 version: $VERSION" "pass"
else
    check "node1 version" "fail"
fi

# Test: cross-node connectivity via seed
echo ""
echo "--- Cross-node discovery test ---"
docker logs $SEED容器 2>&1 | grep -c "registered" | xargs -I{} echo "  Seed registrations: {}"
docker logs $NODE1容器 2>&1 | grep -c "node " | xargs -I{} echo "  Node1 peer discoveries: {}"

# Collect logs
echo ""
echo "--- Container logs ---"
for c in $SEED容器 $NODE1容器 $NODE2容器; do
    echo "[$c]"
    docker logs $c 2>&1 | tail -5
    echo ""
done

echo "=== Results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
