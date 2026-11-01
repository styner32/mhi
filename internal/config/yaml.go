//
// Package config implements the typed configuration loader of spec v0.3 §4
// (checklist T-003, AC-27) and the precedence/validation layers of §4.4
// that M0 needs for its minimal subset.
//
// M0 contract points:
//
//   - Only explicitly given files are read (--config PATH / --env-file PATH).
//     No CWD auto-discovery, no parent-dir search, no home defaults (§4.1).
//   - YAML strict decoding: unknown fields, duplicate keys, extra documents,
//     null-type confusion rejected (§4.4; full rejection table is T-203/M2).
//   - ssl_proxy.enabled=false and ssl_proxy.domains=[] are *normal* defaults
//     for monitoring — not errors (AC-27).
//   - Empty and "unset" are distinct: `MHI_SSL_PROXY_DOMAINS=` is an explicit
//     empty list, not the same as the variable being absent (§4.3).
//   - File size ≤ 64 KiB, ≤ 128 domain entries per list (§4.4 limits).
//
// M0 deliberately does NOT yet implement: .env parsing, MHI_* process-env
// snapshot precedence, flag-Changed distinction, provenance/shadow warnings
// (all M2, T-201/T-202/T-204). This file only builds the in-memory typed
// shape and its YAML-only strict path so M0's serve can run flags+YAML.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Limits from spec §4.4.
const (
	MaxConfigFileBytes = 64 << 10 // 64 KiB
	MaxDomainEntries   = 128
)

// Errors surfaced as config_invalid diagnostics (§9.1).
var (
	// ErrUnknownField mirrors YAML unmarshal strict-mode failure wrapping.
	ErrConfigTooLarge  = errors.New("config file exceeds 64 KiB limit")
	ErrTooManyDomains  = errors.New("domain list exceeds 128 entries")
	ErrEmptySSLList    = errors.New("ssl_proxy.enabled=true requires a non-empty domains list")
	ErrWildcardDomain  = errors.New("wildcard/URL/scheme domains are rejected; only exact host[:port]")
	ErrBadDomain       = errors.New("invalid domain entry")
	ErrUnknownMHIKey   = errors.New("unknown MHI_ key")
	ErrDuplicateEnvKey = errors.New("duplicate key in .env")
)

// SSLProxy mirrors the YAML ssl_proxy block (§4.2).
type SSLProxy struct {
	Enabled bool     `yaml:"enabled"`
	Domains []string `yaml:"domains"`
}

// HTTPCapture mirrors http_capture.domains (§4.2).
type HTTPCapture struct {
	Domains []string `yaml:"domains"`
}

// Capture mirrors capture.{body,details} (§4.2).
type Capture struct {
	Body    string `yaml:"body"`
	Details bool   `yaml:"details"`
}

// Output mirrors output.{format,file,max_bytes} (§4.2).
type Output struct {
	Format   string `yaml:"format"`
	File     string `yaml:"file"`
	MaxBytes int64  `yaml:"max_bytes"`
}

// Config is the typed shape of mhi.yaml (§4.2 example).
type Config struct {
	SchemaVersion int         `yaml:"schema_version"`
	Listen        string      `yaml:"listen"`
	Client        string      `yaml:"client"`
	SSLProxy      SSLProxy    `yaml:"ssl_proxy"`
	HTTPCapture   HTTPCapture `yaml:"http_capture"`
	Capture       Capture     `yaml:"capture"`
	Output        Output      `yaml:"output"`
}

// Defaults returns the product-default Config (§4.5):
// listen 127.0.0.1:9090; SSL disabled; empty lists; text output; no file.
func Defaults() Config {
	return Config{
		SchemaVersion: 1,
		Listen:        "127.0.0.1:9090",
		SSLProxy:      SSLProxy{},
		HTTPCapture:   HTTPCapture{},
		Capture:       Capture{Body: "none"},
		Output:        Output{Format: "text", MaxBytes: 100 << 20}, // 100 MiB
	}
}

// LoadYAML reads exactly the file path given (no fallback search) and decodes
// it strictly. Errors are wrapped for exit-code-2 reporting.
func LoadYAML(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()

	// Bounded read: reject oversized up front rather than buffering unbounded.
	buf, err := io.ReadAll(io.LimitReader(f, MaxConfigFileBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	if len(buf) > MaxConfigFileBytes {
		return Config{}, ErrConfigTooLarge
	}

	return DecodeYAML(buf)
}

// DecodeYAML performs strict decoding plus §4.4 validation. It rejects:
// unknown fields, multiple documents, duplicate keys (via yaml.v3 decode
// errors on duplicated sibling names when strict mode is enabled upstream,
// but yaml.v3 does NOT error on duplicates — post-unmarshal duplicate scan
// is deferred to M2/T-203 which walks the raw node tree).
func DecodeYAML(data []byte) (Config, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // strict: unknown → error

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("config: empty file")
		}
		return Config{}, fmt.Errorf("config: %w", err)
	}

	// Reject additional documents in the same file (§4.4).
	var extra map[string]any
	if err := dec.Decode(&extra); err == nil {
		return Config{}, fmt.Errorf("config: multiple YAML documents rejected")
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate applies schema/domain checks that M0 depends on (AC-27 path).
func validate(c Config) error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("config: schema_version must be 1, got %d", c.SchemaVersion)
	}
	if c.Listen == "" {
		return fmt.Errorf("config: listen is required")
	}
	// Domain lists: shape validation only. The MITM matcher's strict DNS
	// host:port parsing lives in internal/policy (T-105); here we only reject
	// the syntactically-impossible cases (empty entries, wildcards, URLs).
	for _, list := range [][]string{c.SSLProxy.Domains, c.HTTPCapture.Domains} {
		if len(list) > MaxDomainEntries {
			return ErrTooManyDomains
		}
		for _, d := range list {
			if err := validDomainShape(d); err != nil {
				return err
			}
		}
	}
	// §4.4 start-condition table: enabled=true with empty domains is invalid.
	if c.SSLProxy.Enabled && len(c.SSLProxy.Domains) == 0 {
		return ErrEmptySSLList
	}
	return nil
}

// validDomainShape rejects wildcard/URL/scheme input; full DNS validation is
// T-105's matcher. M0 only needs to keep implausible values out.
func validDomainShape(d string) error {
	if d == "" {
		return fmt.Errorf("%w: empty entry", ErrBadDomain)
	}
	// Simple early rejections: products of accidental wildcard/*/regex/URL
	// input that T-105 will formally reject with better diagnostics.
	switch {
	case strings.ContainsAny(d, "?#"),
		strings.Contains(d, "://"),
		strings.HasPrefix(d, "*"),
		strings.ContainsAny(d, "\\ "):
		return fmt.Errorf("%w: %q", ErrWildcardDomain, d)
	}
	if strings.Contains(d, ":") {
		host, _, ok := strings.Cut(d, ":")
		if !ok || host == "" {
			return fmt.Errorf("%w: %q", ErrBadDomain, d)
		}
	}
	return nil
}
