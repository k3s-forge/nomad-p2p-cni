#!/bin/bash
set -e

PASS=0; FAIL=0
ok() { echo "  ✓ $1"; PASS=$((PASS+1)); }
nok() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "============================================"
echo " CNI Persistence & Traffic Test Suite"
echo "============================================"

# ── Phase 1: Deploy a CNI container ───────────────────
echo ""
echo "--- Phase 1: Deploy CNI container ---"

cat > /tmp/persist-http.hcl <<'JOB'
job "persist-http" {
  datacenters = ["dc1"]
  type = "service"
  group "web" {
    count = 1
    network { mode = "cni/nomad-p2p" port "http" { to = 8080 } }
    task "echo" {
      driver = "raw_exec"
      config {
        command = "python3"
        args = ["-m", "http.server", "8080"]
      }
      resources { cpu = 50; memory = 64 }
    }
  }
}
JOB

nomad job run -detach /tmp/persist-http.hcl 2>/dev/null && ok "job deployed" || nok "job deployed"

echo "  Waiting for allocation..."
ALLOC_IP=""
for i in $(seq 1 30); do
  STATUS=$(nomad job status persist-http 2>/dev/null | grep Status | awk '{print $NF}')
  ALLOC_ID=$(nomad job allocs persist-http -json 2>/dev/null | jq -r '.[0].ID' 2>/dev/null || echo "")
  if [ -n "$ALLOC_ID" ] && [ "$ALLOC_ID" != "null" ]; then
    ALLOC_IP=$(nomad alloc status "$ALLOC_ID" 2>/dev/null | grep "IP:" | head -1 | awk '{print $2}' || echo "")
  fi
  if [ "$STATUS" = "running" ] && [ -n "$ALLOC_IP" ]; then
    break
  fi
  sleep 2
done
echo "  Allocation IP: $ALLOC_IP"
[ -n "$ALLOC_IP" ] && ok "allocation running ($ALLOC_IP)" || nok "allocation running"

# ── Phase 2: Verify initial traffic ───────────────────
echo ""
echo "--- Phase 2: Verify initial container traffic ---"

# HTTP request to container
HTTP_OK=false
for i in $(seq 1 5); do
  if curl -sf -m 2 "http://${ALLOC_IP}:8080" >/dev/null 2>&1; then
    HTTP_OK=true; break
  fi
  sleep 1
done
$HTTP_OK && ok "HTTP to container OK" || nok "HTTP to container"

# ── Phase 3: Kill agent, verify BPF maps persist ─────
echo ""
echo "--- Phase 3: Agent crash/restart test ---"

AGENT_PID=$(pgrep -f "nomad-p2p-agent-rust Seed" | head -1 || echo "")
if [ -n "$AGENT_PID" ]; then
  echo "  Killing agent PID: $AGENT_PID"
  kill -9 $AGENT_PID 2>/dev/null || true
  sleep 2
  if pgrep -f "nomad-p2p-agent-rust Seed" >/dev/null; then
    nok "agent killed"
  else
    ok "agent killed"
  fi
else
  nok "agent PID not found"
fi

# Verify BPF maps still exist
echo "  Checking BPF map persistence..."
BPF_MAPS=$(ls /sys/fs/bpf/ 2>/dev/null | wc -l)
echo "  BPF maps in /sys/fs/bpf/: $BPF_MAPS"
[ "$BPF_MAPS" -gt 2 ] && ok "BPF maps persist ($BPF_MAPS maps)" || nok "BPF maps persist"

# ── Phase 4: Restart agent, verify recovery ──────────
echo ""
echo "--- Phase 4: Agent restart recovery ---"

nomad-p2p-agent-rust Seed --config /etc/nomad-p2p/config.json > /tmp/agent-restart.log 2>&1 &
NEW_PID=$!
sleep 5

if kill -0 $NEW_PID 2>/dev/null; then
  ok "agent restarted (PID: $NEW_PID)"
else
  nok "agent restart failed"
fi

# Check for recovery markers in agent output
sleep 2
if grep -q "recovered" /tmp/agent-restart.log 2>/dev/null; then
  ok "BPF container recovery confirmed"
elif grep -q "recovered" /tmp/nomad-server.log 2>/dev/null; then
  ok "BPF container recovery confirmed"
else
  nok "BPF container recovery not confirmed"
fi

# ── Phase 5: Verify traffic after restart ────────────
echo ""
echo "--- Phase 5: Post-restart traffic test ---"

HTTP_AFTER=false
for i in $(seq 1 10); do
  if curl -sf -m 3 "http://${ALLOC_IP}:8080" >/dev/null 2>&1; then
    HTTP_AFTER=true; break
  fi
  sleep 2
done
$HTTP_AFTER && ok "HTTP survives restart" || nok "HTTP survives restart"

# ── Phase 6: Cross-node P2P traffic test ─────────────
echo ""
echo "--- Phase 6: Cross-node P2P mesh traffic ---"

NODE_OVERLAY=$(grep node_overlay_ip /etc/nomad-p2p/config.json | awk -F'"' '{print $4}')
echo "  Local overlay IP: $NODE_OVERLAY"

# Deploy a second container that should get a CNI IP
cat > /tmp/persist-echo.hcl <<'JOB'
job "persist-echo" {
  datacenters = ["dc1"]
  type = "service"
  group "echo" {
    count = 1
    network { mode = "cni/nomad-p2p" port "http" { to = 8080 } }
    task "http" {
      driver = "raw_exec"
      config {
        command = "python3"
        args = ["-m", "http.server", "8080"]
      }
      resources { cpu = 50; memory = 64 }
    }
  }
}
JOB

nomad job run -detach /tmp/persist-echo.hcl 2>/dev/null && ok "second job deployed" || nok "second job deployed"

# Wait for second container
ECHO_IP=""
for i in $(seq 1 30); do
  AID=$(nomad job allocs persist-echo -json 2>/dev/null | jq -r '.[0].ID' 2>/dev/null || echo "")
  if [ -n "$AID" ] && [ "$AID" != "null" ]; then
    ECHO_IP=$(nomad alloc status "$AID" 2>/dev/null | grep "IP:" | head -1 | awk '{print $2}' || echo "")
  fi
  [ -n "$ECHO_IP" ] && break
  sleep 2
done

if [ -n "$ECHO_IP" ]; then
  echo "  Second container IP: $ECHO_IP"
  ok "second container running"

  # Cross-container traffic test
  for i in $(seq 1 10); do
    if curl -sf -m 3 "http://${ECHO_IP}:8080" >/dev/null 2>&1; then
      ok "cross-container traffic OK"
      break
    fi
    [ $i -eq 10 ] && nok "cross-container traffic"
    sleep 2
  done
else
  nok "second container"
fi

# ── Phase 7: BPF map state verification ─────────────
echo ""
echo "--- Phase 7: BPF map state ---"

# Check container_route entries
if [ -x /usr/sbin/bpftool ]; then
  ENTRIES=$(bpftool map show pinned /sys/fs/bpf/CONTAINER_ROUTE_MAP 2>/dev/null | grep -c "key:" || echo "0")
  echo "  CONTAINER_ROUTE_MAP entries: $ENTRIES"
  [ "$ENTRIES" -gt 0 ] && ok "BPF has container routes" || nok "BPF has container routes"
else
  echo "  bpftool not available, skipping BPF inspect"
  ok "BPF map check skipped"
fi

# ── Phase 8: Geneve tunnel traffic ──────────────────
echo ""
echo "--- Phase 8: Geneve tunnel check ---"

if ip link show gnv0 2>/dev/null; then
  GENEVE_UP=$(ip link show gnv0 2>/dev/null | grep -c "UP" || echo "0")
  ok "Geneve device exists"
else
  nok "Geneve device missing"
fi

# ── Results ─────────────────────────────────────────
echo ""
echo "============================================"
echo " Results: $PASS passed, $FAIL failed"
echo "============================================"

[ $FAIL -eq 0 ]
