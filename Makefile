.PHONY: all build-bpf build-bin clean build-ebpf build-agent build-cni

BIN_DIR := bin

all: build-ebpf build-agent

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build-ebpf: $(BIN_DIR)
	cargo xtask build-ebpf 2>&1

build-agent:
	cargo build --release --package nomad-p2p-agent 2>&1

build-cni:
	cargo build --release --package nomad-p2p-cni 2>&1

build-bin: build-agent build-cni
	cp target/release/nomad-p2p-agent $(BIN_DIR)/
	cp target/release/nomad-p2p-cni $(BIN_DIR)/

clean:
	rm -rf $(BIN_DIR) target
