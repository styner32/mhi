package proxy

import "github.com/sunjinlee/mhi/internal/config"

// clientsFromConfig extracts approved client IPs. In M0 config.Client holds a
// single approved peer; M2's loader (T-201) generalizes this to the full
// precedence chain (CLI/env/.env/YAML).
func clientsFromConfig(cfg config.Config) []string {
	if cfg.Client != "" {
		return []string{cfg.Client}
	}
	return nil
}
