package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nomad-p2p-cni/config"
)

func main() {
	configPath := flag.String("config", "/etc/nomad-p2p-cni/config.json", "config file path")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Create agent
	agent, err := NewAgent(cfg)
	if err != nil {
		log.Fatalf("failed to create agent: %v", err)
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("received shutdown signal")
		agent.Stop()
	}()

	// Run agent
	if err := agent.Run(); err != nil {
		log.Fatalf("agent error: %v", err)
	}
}

func init() {
	// Set log flags
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
