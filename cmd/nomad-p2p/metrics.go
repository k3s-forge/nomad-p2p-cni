package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type metricsCollector struct {
	mu       sync.RWMutex
	counters map[string]float64
	gauges   map[string]float64
}

func newMetricsCollector() *metricsCollector {
	return &metricsCollector{
		counters: make(map[string]float64),
		gauges:   make(map[string]float64),
	}
}

func (m *metricsCollector) inc(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name]++
}

func (m *metricsCollector) setGauge(name string, val float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[name] = val
}

func (m *metricsCollector) snapshot() (map[string]float64, map[string]float64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := make(map[string]float64, len(m.counters))
	for k, v := range m.counters {
		c[k] = v
	}
	g := make(map[string]float64, len(m.gauges))
	for k, v := range m.gauges {
		g[k] = v
	}
	return c, g
}

func (a *Agent) startMetricsServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		counters, gauges := a.metrics.snapshot()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		fmt.Fprintf(w, "# HELP nomad_p2p_uptime_seconds Agent uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE nomad_p2p_uptime_seconds gauge\n")
		fmt.Fprintf(w, "nomad_p2p_uptime_seconds %.0f\n\n", time.Since(a.startTime).Seconds())

		fmt.Fprintf(w, "# HELP nomad_p2p_nat_type NAT type (0=unknown, 1=easy, 2=symmetric)\n")
		fmt.Fprintf(w, "# TYPE nomad_p2p_nat_type gauge\n")
		natVal := 0
		switch a.natType {
		case NATEasy:
			natVal = 1
		case NATSymmetric:
			natVal = 2
		}
		fmt.Fprintf(w, "nomad_p2p_nat_type %d\n\n", natVal)

		fmt.Fprintf(w, "# HELP nomad_p2p_peers_total Current number of known peers\n")
		fmt.Fprintf(w, "# TYPE nomad_p2p_peers_total gauge\n")
		a.mu.RLock()
		peerCount := len(a.peerBook)
		seedCount := len(a.seedConns)
		a.mu.RUnlock()
		fmt.Fprintf(w, "nomad_p2p_peers_total %d\n", peerCount)
		fmt.Fprintf(w, "nomad_p2p_seed_connections %d\n\n", seedCount)

		for name, val := range gauges {
			fmt.Fprintf(w, "# TYPE nomad_p2p_%s gauge\n", name)
			fmt.Fprintf(w, "nomad_p2p_%s %.0f\n", name, val)
		}

		for name, val := range counters {
			fmt.Fprintf(w, "# TYPE nomad_p2p_%s_total counter\n", name)
			fmt.Fprintf(w, "nomad_p2p_%s_total %.0f\n", name, val)
		}
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		a.mu.RLock()
		peerCount := len(a.peerBook)
		a.mu.RUnlock()

status := map[string]interface{}{
		"status":   "ok",
		"version":  "v0.3.0",
		"uptime":   time.Since(a.startTime).String(),
		"peers":    peerCount,
		"overlay":  a.cfg.NodeOverlayIP,
		"public":   fmt.Sprintf("%s:%d", a.publicIP, a.publicPort),
		"nat_type": string(a.natType),
	}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	addr := fmt.Sprintf(":%d", a.cfg.MetricsPort)
	log.Printf("[agent] metrics server on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("[agent] metrics server error: %v", err)
	}
}
