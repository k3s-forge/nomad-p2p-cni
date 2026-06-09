.PHONY: all build-bpf build-agent build-seed build-cni clean

CLANG ?= clang
LLC ?= llc

BPFTOOL ?= bpftool

# Detect libbpf headers location
LIBBPF_HEADERS ?= $(shell dpkg -L libbpf-dev 2>/dev/null | grep include | head -1 || echo "/usr/include")
BPF_CFLAGS := -O2 -g -Wall -target bpf -I$(LIBBPF_HEADERS)

BIN_DIR := bin

all: build-bpf build-agent build-seed build-cni

build-bpf: $(BIN_DIR)
	$(CLANG) $(BPF_CFLAGS) -c bpf/mesh.bpf.c -o $(BIN_DIR)/mesh.bpf.o
	$(CLANG) $(BPF_CFLAGS) -c bpf/vip_balancer.bpf.c -o $(BIN_DIR)/vip_balancer.bpf.o
	$(CLANG) $(BPF_CFLAGS) -c bpf/firewall.bpf.c -o $(BIN_DIR)/firewall.bpf.o

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build-agent: build-bpf
	CGO_ENABLED=0 go build -o $(BIN_DIR)/nomad-p2p-agent ./cmd/agent

build-seed:
	CGO_ENABLED=0 go build -o $(BIN_DIR)/nomad-p2p-seed ./cmd/seed

build-cni:
	CGO_ENABLED=0 go build -o $(BIN_DIR)/nomad-p2p-cni ./cmd/cni

clean:
	rm -rf $(BIN_DIR)
	go clean
