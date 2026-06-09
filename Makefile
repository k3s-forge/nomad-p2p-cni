.PHONY: all build-bpf build-agent build-seed build-cni clean

CLANG ?= clang

BIN_DIR := bin

all: build-bpf build-agent build-seed build-cni

build-bpf: $(BIN_DIR)
	$(CLANG) -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c bpf/mesh.bpf.c -o $(BIN_DIR)/mesh.bpf.o
	$(CLANG) -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c bpf/vip_balancer.bpf.c -o $(BIN_DIR)/vip_balancer.bpf.o
	$(CLANG) -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c bpf/firewall.bpf.c -o $(BIN_DIR)/firewall.bpf.o

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
