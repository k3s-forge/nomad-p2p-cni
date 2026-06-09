package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nomad-p2p-cni/config"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "agent":
		runAgent(os.Args[2:])
	case "cni":
		runCNI(os.Args[2:])
	case "version":
		fmt.Println("nomad-p2p v0.1.0")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `nomad-p2p - eBPF P2P CNI for Nomad

Usage:
  nomad-p2p agent [flags]    Start control plane daemon
  nomad-p2p cni  [flags]     CNI plugin (called by Nomad)
  nomad-p2p version          Print version

Agent flags:
  -config string     Config file path (default "/etc/nomad-p2p/config.json")
  -seed-mode         Also run as Seed route registry

CNI flags:
  -command string    CNI command: ADD or DEL
  -container-id string  Container ID
  -netns string      Container network namespace path
  -stdin string      CNI config JSON from stdin

Examples:
  # Start agent with seed mode
  nomad-p2p agent --config /etc/nomad-p2p/config.json --seed-mode

  # Start agent only
  nomad-p2p agent --config /etc/nomad-p2p/config.json

  # CNI plugin (called automatically by Nomad)
  nomad-p2p cni --command=ADD --container-id=abc123 --netns=/var/run/netns/test
`)
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	configPath := fs.String("config", "/etc/nomad-p2p/config.json", "config file path")
	seedMode := fs.Bool("seed-mode", false, "also run as Seed route registry")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	agent, err := newAgent(cfg, *seedMode)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		agent.stop()
	}()

	if err := agent.run(); err != nil {
		log.Fatalf("agent error: %v", err)
	}
}

func runCNI(args []string) {
	fs := flag.NewFlagSet("cni", flag.ExitOnError)
	command := fs.String("command", "", "CNI command: ADD or DEL")
	containerID := fs.String("container-id", "", "container ID")
	netns := fs.String("netns", "", "container network namespace path")
	cniStdin := fs.String("stdin", "", "CNI config JSON (or read from stdin)")
	fs.Parse(args)

	var stdinData []byte
	if *cniStdin != "" {
		stdinData = []byte(*cniStdin)
	} else {
		stdinData = readStdin()
	}

	err := handleCNI(*command, *containerID, *netns, stdinData)
	if err != nil {
		log.Fatalf("cni error: %v", err)
	}
}

func readStdin() []byte {
	info, _ := os.Stdin.Stat()
	if (info.Mode() & os.ModeCharDevice) != 0 {
		return nil
	}
	buf := make([]byte, 65536)
	n, _ := os.Stdin.Read(buf)
	return buf[:n]
}
