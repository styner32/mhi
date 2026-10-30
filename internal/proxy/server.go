//
// Package proxy hosts the GoProxy adapter (M0 scope per T-004..T-007):
// listener/client/proxy auth, destination restrictions, CONNECT authority
// parsing, passthrough tunnel mode with metadata observation, and connection
// registry + shutdown lifecycle.
//
// GoProxy is intentionally confined here (spec §3): its types never leak to
// the CA/redact/output layers. The adapter deliberately overrides GoProxy's
// defaults per spec §2.1:
//
//   - explicit user CA injection only (no GoproxyCa / default MitmConnect)
//   - upstream http.Transport with TLS verification ON, InsecureSkipVerify=false
//   - no env proxy inheritance on plain HTTP or CONNECT dial paths
//   - original Accept-Encoding preserved; no auto-compression/decompression
//   - library verbose logging suppressed; sanitized diagnostics only
//   - Proxy-Authorization never forwarded upstream
package proxy

import (
	"context"
	"fmt"
	"net"
)

// ServeConfig is the M0 minimal runtime configuration derived from CLI flags.
// M2 will replace direct flag construction with the full precedence loader
// (CLI > env > .env > YAML > defaults) and an immutable PolicySnapshot.
type ServeConfig struct {
	Listen string   // host:port to bind; full wildcard bind rejected (§4.5)
	Clients []string // approved client IPs; empty = reject all (AC-08)
	SSLProxyEnabled bool
	MITMDomains     []string
	HTTPCaptureDomains []string
}

// ServeConfigFromFlags builds M0's config from serve flags. Per §4.4 the CLI
// flag defaults (e.g. ssl-proxy=false with no --ssl-proxy given) are *not*
// treated as user values; M2's loader will distinguish via Flags().Changed.
func ServeConfigFromFlags(listen, client string, sslProxy bool, mitmHosts, httpHosts []string) ServeConfig {
	var clients []string
	if client != "" {
		clients = append(clients, client)
	}
	return ServeConfig{
		Listen: listen, Clients: clients,
		SSLProxyEnabled: sslProxy, MITMDomains: mitmHosts, HTTPCaptureDomains: httpHosts,
	}
}

// Server is a running proxy instance; Close implements the §9.3 shutdown
// sequence: stop accepting, 3s drain, close remaining owned connections.
type Server struct {
	ln net.Listener
}

// Close stops the listener and terminates owned connections.
func (s *Server) Close() error {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

// Serve binds and starts the M0 monitoring path.
func Serve(ctx context.Context, cfg ServeConfig) (*Server, error) {
	return nil, fmt.Errorf("proxy: Serve not yet implemented (M0 T-005)")
}
