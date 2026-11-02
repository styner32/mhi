package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// stdoutWriter / stderrWriter are the process-level output boundaries wired
// by main (§4.8: sanitized events only to stdout; status/warnings to stderr).
var (
	stdoutWriter io.Writer = os.Stdout
	stderrWriter io.Writer = os.Stderr
)

// discardLogger silences goproxy's internal logging (§2.1).
type discardLogger struct{}

func (discardLogger) Printf(format string, args ...any) {}
func (discardLogger) Println(args ...any)               {}

// newRunID generates a per-process observability run identifier.
func newRunID() string {
	return fmt.Sprintf("run-%d", time.Now().UnixNano())
}

// reqRemoteAddr narrows an *http.Request's remote address.
func reqRemoteAddr(req *http.Request) net.Addr {
	if req == nil {
		return nil
	}
	// goproxy populates r.RemoteAddr; pull the IP part.
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return &net.TCPAddr{IP: ip}
}

func reqRemoteAddrString(req *http.Request) string {
	if req == nil {
		return "?"
	}
	return req.RemoteAddr
}

// connectDial is the upstream CONNECT dialer (§6): explicit dial to the
// verified host:port — never via env proxy, never via GoProxy's default.
// Each successful dial is one owned tunnel: registered in the registry with
// its destination metadata so shutdown can close it (§9.3/AC-17) and a
// connection.closed event can carry host/port (§8).
func (s *Server) connectDial(network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return s.trackTunnel(c, addr), nil
}

// trackTunnel wraps an upstream conn for registry + closed-event tracking.
// host/port is parsed from the CONNECT authority form goproxy passes (which
// equals the verified, admitted destination).
func (s *Server) trackTunnel(c net.Conn, addr string) net.Conn {
	host := addr
	port := 0
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host = h
		if v, e := strconv.Atoi(p); e == nil {
			port = v
		}
	}
	// Reuse the admission-time metadata: registration ordered at dial time
	// must not overwrite an existing entry for a repeating dial on the same
	// connection — but one dial == one tunnel in goproxy, so fresh entry.
	w := &watchedConn{Conn: c, srv: s, id: ""} // id assigned by registry.Add below
	id := s.registry.Add(c, w)
	w.id = id // now close paths report the real ID
	meta := &SafeConnectionMeta{
		ID:        id,
		Host:      host,
		Port:      port,
		StartedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	s.connMeta[id] = meta
	s.mu.Unlock()
	return w
}

// SafeConnectionMeta is the per-tunnel registration state needed to emit
// connection.closed with host/port/started_at (§8), independent of goproxy
// internals (confined here).
type SafeConnectionMeta = struct {
	ID        string
	Host      string
	Port      int
	StartedAt time.Time
	ClosedAt  time.Time
}

// watchedConn fires the server's per-tunnel close hook on the FIRST close
// end observed: remote EOF (peer closed tunnel) or our explicit Close
// (shutdown path, §9.3). Never double-reports.
func (s *Server) onTunnelClosed(id string, meta *SafeConnectionMeta) {
	meta.ClosedAt = time.Now().UTC()
	s.registry.Remove(id)
	s.mu.Lock()
	delete(s.connMeta, id)
	s.mu.Unlock()
	s.sink.Send(s.tunnelClosedEvent(meta))
}

// watchedConn wraps the upstream net.Conn with the one-shot close report.
type watchedConn struct {
	net.Conn
	srv  *Server
	id   string
	once sync.Once
}

func (w *watchedConn) Close() error {
	var err error
	w.once.Do(func() {
		err = w.Conn.Close()
	})
	if s := w.srv; s != nil {
		s.mu.Lock()
		meta := s.connMeta[w.id]
		s.mu.Unlock()
		if meta != nil {
			s.onTunnelClosed(w.id, meta)
		}
	}
	return err
}

// note: detecting remote-EOF (client/server closed the tunnel without an
// explicit proxy close) requires read-path observation; M0 wires explicit
// Close-time reporting only. Peer-side close events land with M1 MITM's
// flow tracking where the read loop already observes EOF (T-106).
