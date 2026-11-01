package policy

import (
	"fmt"
	"os"
	"strings"
)

// ReadPasswordFile reads a proxy-auth password from a 0600 file (spec §4.5).
// Non-0600 files are rejected. No trailing-newline assumptions; strips exactly
// one trailing \n if present.
func ReadPasswordFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("policy: stat password file: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("policy: password file %s must be mode 0600, got %04o", path, info.Mode().Perm())
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("policy: password file %s is not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("policy: read password file: %w", err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return "", fmt.Errorf("policy: password file %s is empty", path)
	}
	return s, nil
}

// ParseProxyAuth extracts the raw base64 credential from a
// "Basic <token>" Proxy-Authorization value for comparison.
func ParseProxyAuth(v string) (token string, ok bool) {
	const prefix = "Basic "
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", false
	}
	return v[len(prefix):], true
}
