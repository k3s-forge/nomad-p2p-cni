package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "agent":
		runAgentMain(os.Args[2:])
	case "cni":
		runCNI(os.Args[2:])
	case "version":
		fmt.Println("nomad-p2p v0.3.0")
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
`)
}

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}

func runCNI(args []string) {
	fs := newFlagSet("cni")
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
		fmt.Fprintf(os.Stderr, "cni error: %v\n", err)
		os.Exit(1)
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
