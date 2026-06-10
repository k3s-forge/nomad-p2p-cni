FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl wget unzip gnupg2 software-properties-common \
    iproute2 iptables jq net-tools \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Nomad
RUN wget -q https://releases.hashicorp.com/nomad/1.7.6/nomad_1.7.6_linux_amd64.zip -O /tmp/nomad.zip \
    && unzip /tmp/nomad.zip -d /usr/local/bin/ \
    && rm /tmp/nomad.zip \
    && nomad version

# Copy binary and BPF artifacts
COPY bin/nomad-p2p /usr/local/bin/nomad-p2p
COPY bin/nomad-p2p-agent-rust /usr/local/bin/nomad-p2p-agent-rust
COPY bin/nomad-p2p-cni-rust /opt/cni/bin/nomad-p2p-cni-rust
COPY bin/*.bpf.o /opt/bpf/
COPY test/nomad/*.json /etc/nomad/
COPY test/docker/*.sh /opt/test/

RUN chmod +x /opt/test/*.sh /usr/local/bin/nomad-p2p /usr/local/bin/nomad-p2p-agent-rust /opt/cni/bin/nomad-p2p-cni-rust

EXPOSE 4646 4647 4648 9527

ENTRYPOINT ["/opt/test/entrypoint.sh"]
