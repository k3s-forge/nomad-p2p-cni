#!/bin/bash
set -e

PASS=0; FAIL=0

ok() { echo "  ok  $1"; PASS=$((PASS+1)); }
nok() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }

echo "=== Test 1: Binary ==="
if nomad-p2p-agent-rust Version 2>/dev/null | grep -q nomad-p2p; then
  ok "agent binary version"
else
  nok "agent binary version"
fi

echo "=== Test 2: Agent process ==="
if pgrep -f "nomad-p2p-agent-rust" >/dev/null; then
  ok "agent process running"
else
  nok "agent process running"
fi

echo "=== Test 3: UDP port ==="
if ss -ulnp 2>/dev/null | grep -q ":9527"; then
  ok "UDP port 9527"
else
  nok "UDP port 9527"
fi

echo "=== Test 4: CNI binary ==="
if [ -x /opt/cni/bin/nomad-p2p-cni ]; then
  ok "cni binary exists"
else
  nok "cni binary exists"
fi

echo "=== Test 5: Nomad server ==="
if nomad server members 2>/dev/null | grep -q alive; then
  ok "nomad server alive"
else
  nok "nomad server alive"
fi

echo "=== Test 6: Deploy CNI job ==="
cat > /tmp/cni-test.hcl <<'JOB'
job "cni-test" {
  datacenters = ["dc1"]
  type = "service"

  group "web" {
    count = 1

    network {
      mode = "cni/nomad-p2p"
      port "http" { to = 8080 }
    }

    task "server" {
      driver = "raw_exec"

      config {
        command = "python3"
        args = ["-m", "http.server", "8080"]
      }

      resources {
        cpu    = 50
        memory = 64
      }
    }
  }
}
JOB

if nomad job run -detach /tmp/cni-test.hcl 2>/dev/null; then
  ok "cni job deployed"
else
  nok "cni job deployed"
fi

echo "=== Test 7: Allocation status ==="
for i in $(seq 1 20); do
  STATUS=$(nomad job status cni-test 2>/dev/null | grep status | awk '{print $NF}')
  if [ "$STATUS" = "running" ]; then ok "allocation running"; break; fi
  sleep 2
done
[ "$STATUS" != "running" ] && nok "allocation running"

echo "=== Test 8: Cross-group CNI network ==="
cat > /tmp/cni-multi.hcl <<'JOB'
job "cni-multi" {
  datacenters = ["dc1"]
  type = "service"

  group "g1" {
    count = 1
    network {
      mode = "cni/nomad-p2p"
      port "http" { to = 8080 }
    }
    task "echo1" {
      driver = "raw_exec"
      config {
        command = "python3"
        args = ["-c", "import http.server; http.server.HTTPServer(('',8080),http.server.SimpleHTTPRequestHandler).serve_forever()"]
      }
      resources { cpu = 50; memory = 64 }
    }
  }

  group "g2" {
    count = 1
    network {
      mode = "cni/nomad-p2p"
      port "http" { to = 8080 }
    }
    task "echo2" {
      driver = "raw_exec"
      config {
        command = "python3"
        args = ["-c", "import http.server; http.server.HTTPServer(('',8080),http.server.SimpleHTTPRequestHandler).serve_forever()"]
      }
      resources { cpu = 50; memory = 64 }
    }
  }
}
JOB

if nomad job run -detach /tmp/cni-multi.hcl 2>/dev/null; then
  ok "multi-group job deployed"
else
  nok "multi-group job deployed"
fi

echo "=== Test 9: Nomad client nodes ==="
CLIENTS=$(nomad node status 2>/dev/null | grep ready | wc -l)
if [ "$CLIENTS" -ge 1 ]; then
  ok "client nodes: $CLIENTS"
else
  nok "client nodes: $CLIENTS"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
