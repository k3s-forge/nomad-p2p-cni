package main

import (
	"flag"
	"log"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:9528", "seed server listen address")
	psk := flag.String("psk", "", "pre-shared key for HMAC authentication")
	flag.Parse()

	if *psk == "" {
		log.Fatal("psk is required")
	}

	server := NewSeedServer(*addr, *psk)
	if err := server.Run(); err != nil {
		log.Fatalf("seed server error: %v", err)
	}
}
