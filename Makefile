.PHONY: all build-bpf build-bin clean

CLANG ?= clang
BIN_DIR := bin

all: build-bpf build-bin

build-bpf: $(BIN_DIR)
	$(CLANG) -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c bpf/mesh.bpf.c -o $(BIN_DIR)/mesh.bpf.o
	$(CLANG) -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c bpf/vip_balancer.bpf.c -o $(BIN_DIR)/vip_balancer.bpf.o
	$(CLANG) -O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c bpf/firewall.bpf.c -o $(BIN_DIR)/firewall.bpf.o

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build-bin:
	CGO_ENABLED=0 go build -o $(BIN_DIR)/nomad-p2p ./cmd/nomad-p2p

clean:
	rm -rf $(BIN_DIR)
	go clean
