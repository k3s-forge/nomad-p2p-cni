FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl wget gnupg2 software-properties-common \
    iproute2 iptables jq net-tools \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Nomad
RUN wget -qO- https://releases.hashicorp.com/nomad/1.7.6/nomad_1.7.6_linux_amd64.zip | funzip > /usr/local/bin/nomad \
    && chmod +x /usr/local/bin/nomad

# Install Consul (for service discovery)
RUN wget -qO- https://releases.hashicorp.com/consul/1.17.1/consul_1.17.1_linux_amd64.zip | funzip > /usr/local/bin/consul \
    && chmod +x /usr/local/bin/consul

# Copy built artifacts
COPY bin/nomad-p2p /usr/local/bin/nomad-p2p
COPY bin/*.bpf.o /opt/bpf/
COPY test/nomad/*.hcl /etc/nomad/
COPY test/docker/*.sh /opt/test/

RUN chmod +x /opt/test/*.sh

EXPOSE 4646 4647 4648 8500 9527

ENTRYPOINT ["/opt/test/entrypoint.sh"]
