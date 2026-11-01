//
// Package model defines the sanitized event types of spec v0.3 §8. M0 scope
// is the connection-level subset: SafeConnection metadata for CONNECT
// monitoring (T-006) and the SafeEvent envelope with run/seq bookkeeping.
//
// Constraint (§8): raw http.Request/Response, raw errors, and CA keys must
// never appear in Safe types. Tunnel events carry no inner HTTP path/method/
// body/upstream_status (§8: "터널 이벤트에는 내부 HTTP path/method/body/
// upstream_status를 채우지 않는다").
package model

import "time"

// Event type names per §8 event list.
const (
	EventCaptureStarted      = "capture.started"
	EventConnectionOpened    = "connection.opened"
	EventConnectionModeSel   = "connection.mode_selected"
	EventConnectionTunnel    = "connection.tunnel_ready"
	EventConnectionClosed    = "connection.closed"
	EventConnectionError     = "connection.error"
	EventFlowReqHeaders      = "flow.request_headers"
	EventFlowRespHeaders     = "flow.response_headers"
	EventFlowFinished        = "flow.finished"
	EventConfigApplied       = "config.applied"
	EventConfigRejected      = "config.rejected"
	EventConfigShadowed      = "config.shadowed"
	EventCaptureLoss         = "capture.loss"
	EventCaptureFinished     = "capture.finished"
)

// SchemaVersion for the JSONL event stream (§8: schema_version 2 — independent
// of YAML schema_version 1 and of doc version v0.3).
const SchemaVersion = 2

// SafeEvent is the JSONL envelope (§8). M0 fills SchemaVersion, RunID, Seq,
// Type, At, PolicyRevision, Connection; Flow/Config/Diagnostic are filled in
// later milestones.
type SafeEvent struct {
	SchemaVersion  int             `json:"schema_version"`
	RunID          string          `json:"run_id"`
	Seq            uint64          `json:"seq"`
	Type           string          `json:"type"`
	At             time.Time       `json:"at"`
	PolicyRevision uint64          `json:"policy_revision,omitempty"`
	Connection     *SafeConnection `json:"connection,omitempty"`
	Config         *SafeConfigEvent `json:"config,omitempty"`
	Flow           *SafeFlow       `json:"flow,omitempty"`
	Diagnostic     *SafeDiagnostic `json:"diagnostic,omitempty"`
}

// Connection mode names (§8, §6 decision table).
const (
	ModeTunnel = "tunnel"
	ModeMITM   = "mitm"
)

// SafeConnection carries CONNECT monitoring metadata (§8). M0 emits
// mode_selected(tunnel) + tunnel_ready + closed with these fields only.
type SafeConnection struct {
	ID                  string     `json:"id"`
	Client              string     `json:"client"`
	Host                string     `json:"host"`
	Port                int        `json:"port"`
	Mode                string     `json:"mode"`
	PolicyRevision      uint64     `json:"policy_revision"`
	Phase               string     `json:"phase,omitempty"` // handshake|established|closing
	StartedAt           time.Time  `json:"started_at"`
	ClosedAt            *time.Time `json:"closed_at,omitempty"`
	ProxyConnectStatus  int        `json:"proxy_connect_status,omitempty"` // proxy-generated 200/407/502; NOT the upstream API's status
}

// SafeConfigEvent is the config.applied/config.rejected body (§8): revision,
// changed host list, new-connections-only flag, legacy connection counts —
// never env values, keys, or raw file content.
type SafeConfigEvent struct {
	Revision           uint64   `json:"revision"`
	ChangedHosts       []string `json:"changed_hosts,omitempty"`
	NewConnectionsOnly bool     `json:"new_connections_only"`
	LegacyConnections  int      `json:"active_legacy_connections,omitempty"`
	LegacyMITM         int      `json:"active_legacy_mitm_connections,omitempty"`
	ErrorCode          string   `json:"error_code,omitempty"`
}

// SafeFlow and SafeSide are M3 scope (§8); declared here so future milestones
// extend, not invent, the JSONL contract.
type SafeFlow struct {
	ID               string   `json:"id"`
	ConnectionID     string   `json:"connection_id"`
	PolicyRevision   uint64   `json:"policy_revision"`
	Method           string   `json:"method"`
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	Path             string   `json:"path"`
	UpstreamStatus   *int     `json:"upstream_status"`
	DownstreamStatus *int     `json:"downstream_status"`
	State            string   `json:"state"`
	Request          SafeSide `json:"request"`
	Response         SafeSide `json:"response"`
	DurationMS       *float64 `json:"duration_ms"`
	ErrorCode        string   `json:"error_code,omitempty"`
	Incomplete       bool     `json:"incomplete"`
}

type SafeSide struct {
	HeadersSeen   bool       `json:"headers_seen"`
	EOFObserved   bool       `json:"eof_observed"`
	HTTPVersion   string     `json:"http_version,omitempty"`
	Headers       []SafePair `json:"headers"`
	ObservedBytes int64      `json:"observed_bytes"`
	BodyState     string     `json:"body_state"`
	Omission      string     `json:"omission,omitempty"`
	Preview       string     `json:"preview,omitempty"`
}

type SafePair struct{ Name, Value string }

// SafeDiagnostic is a structured error code (§9.1 taxonomy).
type SafeDiagnostic struct {
	Code         string `json:"code"`
	ConnectionID string `json:"connection_id,omitempty"`
	Count        uint64 `json:"count,omitempty"`
}
