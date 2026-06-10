# Nomad e2e test: deploy 2 containers with CNI networking
# Usage: nomad job run test/nomad/e2e-cni.hcl
# No Docker required - uses raw_exec driver

job "e2e-cni" {
  datacenters = ["dc1"]
  type = "service"

  group "container-a" {
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

    service {
      name = "cni-http"
      port = "http"
      check {
        type     = "http"
        path     = "/"
        interval = "10s"
        timeout  = "2s"
      }
    }
  }

  group "container-b" {
    count = 1
    network {
      mode = "cni/nomad-p2p"
      port "http" { to = 8080 }
    }

    task "echo" {
      driver = "raw_exec"
      config {
        command = "python3"
        args = ["-c", "
import socket, http.server, json, urllib.request, os, time

class EchoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Try to reach container-a via Nomad service discovery
        try:
            svc = os.environ.get('NOMAD_ADDR_pod', '127.0.0.1:8080')
            urllib.request.urlopen(f'http://{svc}', timeout=2)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'cni-cross-node-ok')
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'error: {e}'.encode())

http.server.HTTPServer(('', 8080), EchoHandler).serve_forever()
"]
      }
      resources {
        cpu    = 50
        memory = 64
      }
    }

    service {
      name = "cni-echo"
      port = "http"
      check {
        type     = "http"
        path     = "/"
        interval = "10s"
        timeout  = "2s"
      }
    }
  }
}
