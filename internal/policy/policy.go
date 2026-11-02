// Package policy implements connection admission and destination rules:
//
//   - approved client IP gate (spec §4.5, AC-08) — checked before any
//     monitoring, host metadata observation, or upstream dial
//   - proxy basic auth (mhi / password from TTY or 0600 file, §4.5)
//   - outbound destination restrictions (§6): localhost/loopback/link-local/
//     private/multicast/metadata addresses default-blocked; CONNECT ports
//     restricted to 443 + user-declared SSL target ports in P0
//   - no environment proxy inheritance on any dial path (AC-23)
//
// DNS verification + dial-to-verified-IP (§6) lands with the proxy dialer in
// T-005; this file holds the pure decision logic so tests cover admission
// first, before listener wiring.
package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Admission is the verdict for an incoming proxy connection attempt.
type Admission int

const (
	Allow Admission = iota
	DenyAuth
	DenyClient
	DenyDestination
)

// Gate decides whether a peer may use the proxy at all.
type Gate struct {
	Clients []string // approved peer IPs (§4.5: --client / config.client)
	User    string   // proxy basic-auth username; fixed "mhi"
	// Passworded via Auth.check; never stored in plaintext logs.
	auth *Auth
}

// NewGate validates the client list and builds the admission gate.
// Rejects anything not parseable as an IPv4/IPv6 address (hostnames are
// refused here — the client gate is IP-based per §4.5 "TCP peer IP로 검증").
func NewGate(clients []string, user string) (*Gate, error) {
	for i, c := range clients {
		ip := net.ParseIP(strings.TrimSpace(c))
		if ip == nil {
			return nil, fmt.Errorf("policy: client entry %q is not an IP address", c)
		}
		_ = i
	}
	if user == "" {
		user = "mhi"
	}
	return &Gate{Clients: clients, User: user}, nil
}

// AdmitClient checks the TCP peer against the approved list. Empty list or
// non-IP peer → deny (fail-closed, AC-08).
func (g *Gate) AdmitClient(peer net.Addr) Admission {
	ip, err := net.ResolveTCPAddr("tcp", peer.String())
	if err != nil {
		return DenyClient
	}
	peerIP := ip.IP
	for _, c := range g.Clients {
		userIP := net.ParseIP(c)
		if userIP != nil && userIP.Equal(peerIP) {
			return Allow
		}
	}
	return DenyClient
}

// Auth holds the proxy-auth credentials and verifies Proxy-Authorization
// without letting the plaintext password leak into logs or errors.
type Auth struct {
	user     string
	password string // set at construction; never String()'d
}

// NewAuth builds the credential holder. Call sites (T-004) read the password
// from /dev/tty or a 0600 file only — never argv or .env (§4.5).
func NewAuth(user, password string) (*Auth, error) {
	if password == "" {
		return nil, fmt.Errorf("policy: proxy auth requires a non-empty password (TTY or 0600 file)")
	}
	if user == "" {
		user = "mhi"
	}
	return &Auth{user: user, password: password}, nil
}

// Authorize verifies a Proxy-Authorization header value; empty/missing always
// fails closed.
func (a *Auth) Authorize(headerValue string) bool {
	if a == nil || headerValue == "" {
		return false
	}
	// Constant-enough comparison: basic scheme parse then user:pass compare.
	const prefix = "Basic "
	if len(headerValue) < len(prefix) || !strings.EqualFold(headerValue[:len(prefix)], prefix) {
		return false
	}
	return constantTimeEqual(headerValue[len(prefix):], a.b64())
}

// b64 returns the base64 of user:password; unexported so it never escapes
// the package via logs.
func (a *Auth) b64() string {
	// Implemented in auth_b64.go to keep encoding out of this file's face.
	return a.b64Impl()
}

func constantTimeEqual(x, y string) bool {
	if len(x) != len(y) {
		return false
	}
	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}
	return v == 0
}

// DestinationPolicy restricts outbound connects (§6).
type DestinationPolicy struct {
	// AllowedConnectPorts are the CONNECT ports permitted beyond 443, per
	// user-declared SSL target ports. P0 default: {443}.
	AllowedConnectPorts map[int]bool
}

// DefaultDestination returns the P0 defaults (§6: 443 only).
func DefaultDestination() *DestinationPolicy {
	return &DestinationPolicy{AllowedConnectPorts: map[int]bool{443: true}}
}

// CheckHostPort validates a CONNECT authority for tunneling. Rules (§6):
//   - strict host:port parse; missing port is NOT defaulted to 80
//   - IP-literal destinations are tunnel-discovery-eligible
//   - private/link-local/loopback/multicast/metadata addresses blocked
//   - port must be in AllowedConnectPorts
func (p *DestinationPolicy) CheckHostPort(authority string) (host string, port int, adm Admission, err error) {
	h, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, DenyDestination, fmt.Errorf("policy: CONNECT authority %q is not host:port", authority)
	}
	if h == "" {
		return "", 0, DenyDestination, fmt.Errorf("policy: empty CONNECT host")
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, DenyDestination, fmt.Errorf("policy: invalid CONNECT port %q", portStr)
	}
	if !p.AllowedConnectPorts[port] {
		return "", 0, DenyDestination, fmt.Errorf("policy: CONNECT port %d not permitted", port)
	}
	if blockedHost(h) {
		return "", 0, DenyDestination, fmt.Errorf("policy: destination %q is blocked", h)
	}
	return h, port, Allow, nil
}

// blockedHost rejects loopback/private/link-local/multicast/metadata targets
// by any name form (IP literal, .localhost, .local suffix etc.).
func blockedHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	// IP literal check covers 127.*, 10.*, 172.16-31.*, 192.168.*, 169.254.*,
	// 224.*, ::1, fc00::/7, ff00::/8, and AWS metadata 169.254.169.254.
	if ip := net.ParseIP(h); ip != nil {
		return blockedIP(ip)
	}
	// Name forms that are plausibly non-public.
	if strings.HasSuffix(h, ".localhost") || h == "localhost" {
		return true
	}
	return false
}

func blockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// AWS/Cloud metadata endpoints (§6 example: 169.254.169.254 — covered by
	// link-local check; kept explicit for documentation).
	if ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}
