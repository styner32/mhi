//
// Package lifecycle — connection registry and shutdown (checklist T-007,
// spec §9.3, AC-17).
//
// Key constraint: http.Server.Shutdown does NOT wait for or close hijacked
// (CONNECT/MITM) connections. Every accepted inbound conn and everyconn we
// dial upstream is registered here so shutdown can close them explicitly
// after the 3s drain window.
package lifecycle

import (
	"context"
	"net"
	"sync"
	"time"
)

// Registry tracks owned connections for explicit close on shutdown.
type Registry struct {
	mu    sync.Mutex
	conns map[string]net.Conn
	next  uint64
}

func NewRegistry() *Registry {
	return &Registry{conns: make(map[string]net.Conn)}
}

// Add registers a conn and returns its assigned stable connection ID.
func (r *Registry) Add(c net.Conn) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	id := connIDPrefix + itoa(r.next)
	r.conns[id] = c
	return id
}

// Remove forgets a conn by ID (called on connection close).
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, id)
}

// Count returns the number of still-tracked connections.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// CloseAll forcibly closes every tracked conn. Used after the 3s drain
// grace period (§9.3) to guarantee no owned connection outlives shutdown.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.conns {
		_ = c.Close()
		delete(r.conns, id)
	}
}

// connIDPrefix is a run-scoped namespace for connection IDs (§8 — stable,
// readable, no collision across runs because paired with RunID).
const connIDPrefix = "c"

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Drain waits up to grace for tracked connections to fall to zero naturally
// (§9.3 "3초의 정리 시간"), polling since Registry does not expose callbacks.
func (r *Registry) Drain(ctx context.Context, grace time.Duration) {
	deadline := time.Now().Add(grace)
	for r.Count() > 0 {
		if time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}
