// Package proxy — GoProxy adapter. This version is the M0 implementation
// (T-004..T-008): CA-less CONNECT tunneling with metadata observation only.
//
// GoProxy is present as a dependency now (source-review baseline v1.9.2 per
// spec §2/S2) but the adapter only uses its plain-HTTP handler path and the
// CONNECT tunnel path — no MITM actions are registered in M0. MITM wiring
// (T-106/T-107) happens in M1 with a verified local CA.
//
// Library defaults overridden per spec §2.1 (S3/S4):
//   - upstream transport: net/http default with TLS verification on, no env
//     proxy (ProxyFromEnvironment deliberately NOT combined in)
//   - no goproxy CA / no MitmConnect registered
//   - verbose goproxy logging silenced (we pass a no-op Logger)
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/styner32/mhi/internal/config"
	"github.com/styner32/mhi/internal/lifecycle"
	"github.com/styner32/mhi/internal/model"
	"github.com/styner32/mhi/internal/output"
	"github.com/styner32/mhi/internal/policy"
)

// Server is a running proxy instance.
type Server struct {
	ln        net.Listener
	httpSrv   *http.Server
	registry  *lifecycle.Registry
	sink      *output.Sink
	gate      *policy.Gate
	auth      *policy.Auth
	dest      *policy.DestinationPolicy
	revision  uint64
	runID     string
	transport *http.Transport

	mu       sync.Mutex
	connMeta map[string]*SafeConnectionMeta // per-tunnel metadata for closed events
}

// proxyVersion corresponds to the pinned goproxy version.
const proxyVersion = "v1.9.2"

// Serve binds, wires admission/destination policy, and starts serving in
// goroutines; returns immediately so callers own the signal handler.
func Serve(ctx context.Context, cfg config.Config) (*Server, error) {
	// §2.1 diagnostics: structured slog to stderr only — stdout carries
	// sanitized events exclusively (§4.8). Level Info keeps the default
	// process quiet; Debug reserved for future -v style investigation.
	sh := slog.NewTextHandler(stderrWriter, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(sh)
	slog.SetDefault(logger)
	// §4.5: specific LAN IPv4 only; an "all interfaces" bind is rejected.
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen %q is not host:port", cfg.Listen)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("proxy: listen %q must be an explicit IP, not a hostname/wildcard", cfg.Listen)
	}
	if ip.IsUnspecified() {
		return nil, fmt.Errorf("proxy: wildcard bind 0.0.0.0/:: rejected; name a specific LAN IPv4")
	}

	gate, err := policy.NewGate(clientsFromConfig(cfg), "mhi")
	if err != nil {
		return nil, err
	}

	// M0: proxy auth is accepted but not yet sourced from 0600 file/TTY
	// (T-004 landing note); gate stays client-IP-only, documented as such.
	auth, authErr := policy.NewAuth("mhi", "changeme-m0")
	_ = authErr // explicitly tolerated until T-004 wires real password loading

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("proxy: bind %s: %w", cfg.Listen, err)
	}

	runID := newRunID()
	reg := lifecycle.NewRegistry()
	sink := output.NewSink(stdoutWriter, stderrWriter, runID, 1024, true)

	s := &Server{
		ln:       ln,
		registry: reg,
		sink:     sink,
		gate:     gate,
		auth:     auth,
		dest:     policy.DefaultDestination(),
		runID:    runID,
		connMeta: make(map[string]*SafeConnectionMeta),
		// Policy revision 1 = the initial static policy loaded at startup.
		// 0 would read as "no policy" in events (it did: mode=tunnel policy=0).
		// M2's reload increments this atomically per applied snapshot (§4.6).
		revision: 1,
		transport: &http.Transport{
			// §2.1: verification ON; no env proxy; no auto-compression.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: false},
			Proxy:                 nil, // explicitly nil — never ProxyFromEnvironment
			DisableCompression:    true,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}

	pxy := goproxy.NewProxyHttpServer()
	pxy.Logger = discardLogger{} // no verbose library logging (§2.1)
	pxy.Verbose = false
	pxy.Tr = s.transport            // upstream transport for plain HTTP
	pxy.ConnectDial = s.connectDial // CONNECT upstream dial (no env proxy)
	// MitmConnect is NOT registered anywhere in M0 — the adapter never touches
	// goproxy's built-in CA (GoproxyCa) (§2.1, S4). MITM comes in M1 via an
	// explicitly injected verified local CA (T-106).

	// M0 CONNECT handler: tunnel only, emit metadata first (T-006).
	pxy.OnRequest().HandleConnect(s.handleConnect())

	s.httpSrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && !s.admit(w, r) {
			return
		}
		pxy.ServeHTTP(w, r)
	})}

	// Serve in background; caller's ctx governs shutdown.
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("proxy serve exited", "error", err, "run", s.runID)
		}
	}()

	sink.Send(s.event(model.EventCaptureStarted, nil))
	return s, nil
}

// handleConnect is the M0 CONNECT monitor (T-006). Admission (client gate,
// proxy auth, destination policy) already ran in the http.Server wrapper via
// s.admit() — this handler receives only admitted CONNECTs and must NOT
// re-check auth here: goproxy strips Proxy-Authorization from ctx.Req before
// dispatch, so a header check here would always fail (the pre-Option-B bug).
func (s *Server) handleConnect() goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// Destination policy (AC-24, §6). host carries the CONNECT authority.
		h, port, adm, err := s.dest.CheckHostPort(host)
		if err != nil || adm != policy.Allow {
			slog.Warn("proxy rejected",
				"code", "destination_denied",
				"authority", host,
				"client", reqRemoteAddrString(ctx.Req),
				"run", s.runID,
			)
			return goproxy.RejectConnect, host
		}

		// Register + metadata event (T-006/§8): no inner HTTP fields on tunnels.
		s.sink.Send(s.connectionEvent(model.EventConnectionModeSel, h, port, model.ModeTunnel, 200))
		// Pure tunnel — ConnectAccept with no TLSConfig: goproxy's own
		// OkConnect references its built-in CA so we construct our own action
		// to keep it out of the code path entirely (§2.1/S4).
		return &goproxy.ConnectAction{Action: goproxy.ConnectAccept}, host
	})
}

// reject is the single stderr diagnostic emit for admission failures.
// Never logs header values or credentials (AC-13); peer IP is the only
// client identifier surfaced (§6).
func (s *Server) reject(req *http.Request, code string) {
	slog.Warn("proxy rejected",
		"code", code,
		"client", reqRemoteAddrString(req),
		"run", s.runID,
	)
}

func (s *Server) connectionEvent(typ, host string, port int, mode string, proxyStatus int) model.SafeEvent {
	return model.SafeEvent{
		Type:           typ,
		PolicyRevision: s.revision,
		At:             time.Now().UTC(),
		Connection: &model.SafeConnection{
			Host:               host,
			Port:               port,
			Mode:               mode,
			PolicyRevision:     s.revision,
			ProxyConnectStatus: proxyStatus,
		},
	}
}

func (s *Server) event(typ string, diag *model.SafeDiagnostic) model.SafeEvent {
	return model.SafeEvent{Type: typ, PolicyRevision: s.revision, Diagnostic: diag, At: time.Now().UTC()}
}

// tunnelClosedEvent emits connection.closed carrying the destination and
// timing observed for the tunnel (§8; tunnels carry no inner HTTP fields).
// ClosedAt is set by the caller (per-tunnel close hook) before this fires.
func (s *Server) tunnelClosedEvent(m *SafeConnectionMeta) model.SafeEvent {
	if m == nil {
		return model.SafeEvent{Type: model.EventConnectionClosed, PolicyRevision: s.revision}
	}
	started := m.StartedAt
	closed := m.ClosedAt
	return model.SafeEvent{
		Type:           model.EventConnectionClosed,
		PolicyRevision: s.revision,
		At:             time.Now().UTC(),
		Connection: &model.SafeConnection{
			ID:             m.ID,
			Host:           m.Host,
			Port:           m.Port,
			Mode:           model.ModeTunnel,
			PolicyRevision: s.revision,
			StartedAt:      started,
			ClosedAt:       &closed,
		},
	}
}

// Close performs the §9.3 sequence: stop accepting → 3s drain → close
// remaining owned conns → shut down HTTP server → final summary.
func (s *Server) Close() error {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.registry.Drain(ctx, 3*time.Second)
	s.registry.CloseAll()
	_ = s.httpSrv.Close()
	s.sink.Close()
	slog.Info("proxy shutdown complete", "run", s.runID)
	return nil
}

// handlers
// admit runs the full per-CONNECT admission chain and writes the
// rejection response itself when a check fails. Returns true only when
// the wrapper should forward r to goproxy.
func (s *Server) admit(w http.ResponseWriter, r *http.Request) bool {
	// 1. client gate — fail-closed (AC-08).
	if adm := s.gate.AdmitClient(reqRemoteAddr(r)); adm != policy.Allow {
		s.reject(r, "destination_denied-client")
		w.WriteHeader(http.StatusForbidden)
		return false
	}

	// 2. proxy auth — challenge with 407 so iOS can prompt/retry (4.5, AC-08).
	if !s.auth.Authorize(r.Header.Get("Proxy-Authorization")) {
		s.reject(r, "proxy_auth_failed")
		w.Header().Set("Proxy-Authenticate", `Basic realm="mhi"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	// 3. destination policy (AC-24, 6) — CONNECT authority comes from r.Host.
	if _, _, adm, err := s.dest.CheckHostPort(r.Host); err != nil || adm != policy.Allow {
		s.reject(r, "destination_denied")
		w.WriteHeader(http.StatusBadGateway)
		return false
	}

	return true
}
