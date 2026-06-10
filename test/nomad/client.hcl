client {
  enabled = true
  cni_path = "/opt/cni/bin"
  cni_config_dir = "/opt/cni/config"
  network_interface = "eth0"

  host_network "private" {
    cidr = "10.244.0.0/16"
    reserved_ports = "1-1024"
  }

  options {
    "driver.raw_exec.enable" = "1"
  }
}

plugin "nomad-p2p-cni" {
  config {
    cni_version = "0.4.0"
    name = "nomad-p2p"
    type = "nomad-p2p-cni"
  }
}
