package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/elazarl/goproxy"
)

// stdoutWriter / stderrWriter are the process-level output boundaries wired
// by main (§4.8: sanitized events only to stdout; status/warnings to stderr).
var (
	stdoutWriter io.Writer = os.Stdout
	stderrWriter io.Writer      = os.Stderr
)

// discardLogger silences goproxy's internal logging (§2.1).
type discardLogger struct{}

func (discardLogger) Printf(format string, args ...any)             {}
func (discardLogger) Println(args ...any)                           {}

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

// fakeConn is a placeholder registration so the registry compiles under M0's
// metadata-only flow; removed when Hijack-time conn registration (T-007) is
// wired on the real tunnel path.
type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write([]byte) (int, error)       { return 0, io.EOF }
func (fakeConn) Close() error                    { return nil }
func (fakeConn) LocalAddr() net.Addr             { return nil }
func (fakeConn) RemoteAddr() net.Addr            { return nil }
func (fakeConn) SetDeadline(time.Time) error     { return nil }
func (fakeConn) SetReadDeadline(time.Time) error { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

// connectDial is the upstream CONNECT dialer (§6): explicit dial to the
// verified host:port — never via env proxy, never via GoProxy's default.
func (s *Server) connectDial(network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.Dial(network, addr)
}

var _ = goproxy.RejectConnect // kept for wiring visibility
