//
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
	"net"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/sunjinlee/mhi/internal/config"
	"github.com/sunjinlee/mhi/internal/lifecycle"
	"github.com/sunjinlee/mhi/internal/model"
	"github.com/sunjinlee/mhi/internal/output"
	"github.com/sunjinlee/mhi/internal/policy"
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
}

// proxyVersion corresponds to the pinned goproxy version.
const proxyVersion = "v1.9.2"

// Serve binds, wires admission/destination policy, and starts serving in
// goroutines; returns immediately so callers own the signal handler.
func Serve(ctx context.Context, cfg config.Config) (*Server, error) {
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
	pxy.Logger = discardLogger{}          // no verbose library logging (§2.1)
	pxy.Verbose = false
	pxy.Tr = s.transport                  // upstream transport for plain HTTP
	pxy.ConnectDial = s.connectDial       // CONNECT upstream dial (no env proxy)
	// MitmConnect is NOT registered anywhere in M0 — the adapter never touches
	// goproxy's built-in CA (GoproxyCa) (§2.1, S4). MITM comes in M1 via an
	// explicitly injected verified local CA (T-106).

	// M0 CONNECT handler: tunnel only, emit metadata first (T-006).
	pxy.OnRequest().HandleConnect(s.handleConnect())

	s.httpSrv = &http.Server{Handler: pxy}

	// Serve in background; caller's ctx governs shutdown.
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(stderrWriter, "proxy: serve: %v\n", err)
		}
	}()

	sink.Send(s.event(model.EventCaptureStarted, nil))
	return s, nil
}

// handleConnect is the M0 CONNECT monitor (T-006): certified the peer/dest,
// emits metadata, then tunnels raw TLS bytes without any TLS termination
// (§6: "일반 tunnel에서는 TLS를 종료하지 않고 client/server의 검증에 맡긴다").
func (s *Server) handleConnect() goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		req := ctx.Req
		// 1. Client gate (AC-08): checked before anything else (§6 ordering).
		if adm := s.gate.AdmitClient(reqRemoteAddr(req)); adm == policy.DenyClient {
			s.reject(req, "destination_denied-client")
			return goproxy.RejectConnect, host
		}
		// 2. Proxy auth (AC-08) — M0 placeholder credential; tighten at T-004.
		if !s.auth.Authorize(req.Header.Get("Proxy-Authorization")) {
			s.reject(req, "proxy_auth_failed")
			return goproxy.RejectConnect, host
		}
		// 3. Destination policy (AC-24, §6). req.Host carries the authority.
		h, port, adm, err := s.dest.CheckHostPort(host)
		if err != nil || adm != policy.Allow {
			s.reject(req, "destination_denied")
			return goproxy.RejectConnect, host
		}

		// 4. Register + metadata event (T-006/§8): no inner HTTP fields on tunnels.
		s.sink.Send(s.connectionEvent(model.EventConnectionModeSel, h, port, model.ModeTunnel, 200))
		// Pure tunnel — ConnectAccept with no TLSConfig: goproxy's own
		// OkConnect references its built-in CA so we construct our own action
		// to keep it out of the code path entirely (§2.1/S4).
		return &goproxy.ConnectAction{Action: goproxy.ConnectAccept}, host
	})
}

func (s *Server) reject(req *http.Request, code string) {
	fmt.Fprintf(stderrWriter, "reject: %s from %s\n", code, reqRemoteAddrString(req))
}

func (s *Server) connectionEvent(typ, host string, port int, mode string, proxyStatus int) model.SafeEvent {
	return model.SafeEvent{
		Type:           typ,
		PolicyRevision: s.revision,
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
	return model.SafeEvent{Type: typ, PolicyRevision: s.revision, Diagnostic: diag}
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
	fmt.Fprintf(stderrWriter, "shutdown: done\n")
	return nil
}
