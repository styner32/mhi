// serve — foreground proxy/monitor command. M0 scope (T-002..T-008):
//
//   - explicit paths only (--config/--env-file, never CWD scanning)
//   - listen on a specific LAN IPv4, restricted client allowlist
//   - no-CA pure CONNECT monitoring: destinations reported as metadata only,
//     tunnel bytes passed through untouched
//   - Ctrl+C/SIGTERM: stop accepting, drain up to 3s, close owned connections,
//     exit 0 (or 130 on SIGINT per §4.8)
//
// Per M0 gate, MITM/black-box decryption is intentionally absent: no CA is
// loaded when ssl_proxy is disabled, and no underground TLS termination
// happens on tunnel-mode connections.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/styner32/mhi/internal/config"
	"github.com/styner32/mhi/internal/proxy"
)

func newServeCmd(stdout, stderr io.Writer) *cobra.Command {
	var flags serveFlags

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the foreground proxy/monitor",
		// Options in §4.5 are accepted as flags but treated as *explicit CLI*
		// values only; cobra flag defaults never become a config source of
		// truth (§4.4 priority: explicit flag > env > .env > YAML > defaults).
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(stdout, stderr, flags)
		},
	}

	addServeFlags(cmd, &flags)
	return cmd
}

// serveFlags mirrors §4.5 option table. Booleans with cobra defaults are only
// meaningful when the user actually supplied them (cmd.Flags().Changed).
type serveFlags struct {
	configPath    string
	listen        string
	client        string
	sslProxy      bool
	mitmHosts     []string
	httpHosts     []string
	body          string
	details       bool
	format        string
	output        string
	maxOutputKB   int64
	redactRules   string
	proxyPassFile string
	watch         bool
}

func addServeFlags(cmd *cobra.Command, f *serveFlags) {
	cmd.Flags().StringVar(&f.configPath, "config", "", "explicit YAML config path (no auto-discovery)")
	// cmd.Flags().StringVar(&f.listen, "listen", "", "listen address (default 127.0.0.1:9090; use a specific LAN IPv4 for iPhone)")
	// cmd.Flags().StringVar(&f.client, "client", "", "approved client IP (required with LAN bind)")
	// cmd.Flags().BoolVar(&f.sslProxy, "ssl-proxy", false, "enable SSL proxying (ssl_proxy.enabled)")
	// cmd.Flags().StringArrayVar(&f.mitmHosts, "mitm-host", nil, "exact host[:port] to MITM; repeatable; replaces domains list")
	// cmd.Flags().StringArrayVar(&f.httpHosts, "http-host", nil, "exact host[:port] for plaintext HTTP observation")
	// cmd.Flags().StringVar(&f.body, "body", "", "body capture mode: none|json (default none)")
	// cmd.Flags().BoolVar(&f.details, "details", false, "emit sanitized detail output")
	// cmd.Flags().StringVar(&f.format, "format", "", "output format: text|jsonl")
	// cmd.Flags().StringVar(&f.output, "output", "", "explicit JSONL output file")
	// cmd.Flags().Int64Var(&f.maxOutputKB, "max-output-bytes", 0, "output file size cap (default 100 MiB)")
	// cmd.Flags().StringVar(&f.redactRules, "redact-rules", "", "redact_rules JSON path")
	// cmd.Flags().StringVar(&f.proxyPassFile, "proxy-password-file", "", "0600 password file (never argv)")
	// cmd.Flags().BoolVar(&f.watch, "watch", false, "watch explicit config/env files for policy reload (serve-only, requires --config and/or --env-file)")
}

func runServe(stdout, stderr io.Writer, f serveFlags) error {
	// M0 v1 behavior: CLI flags fall back through an explicitly-given YAML
	// file only (no auto-discovery, §4.1). M2 adds env/.env/precedence.
	cfg := config.Defaults()
	if f.configPath != "" {
		loaded, err := config.LoadYAML(f.configPath)
		if err != nil {
			fmt.Fprintln(stderr, "serve:", err)
			setExitCode(ExitInvalidConfig)
			return nil
		}

		slog.Info("serve: loaded config",
			"configPath", f.configPath,
			"listen", loaded.Listen,
			"client", loaded.Client,
		)
		cfg = loaded
	}

	// CLI flag overlay (explicit values only; M2 uses Flags().Changed to
	// distinguish user-supplied from cobra defaults, §4.4).
	if f.listen != "" {
		cfg.Listen = f.listen
	}
	if f.client != "" {
		cfg.Client = f.client
	}
	if f.sslProxy {
		cfg.SSLProxy.Enabled = true
	}
	if len(f.mitmHosts) > 0 {
		cfg.SSLProxy.Domains = f.mitmHosts
	}
	if len(f.httpHosts) > 0 {
		cfg.HTTPCapture.Domains = f.httpHosts
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := proxy.Serve(ctx, cfg)
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		setExitCode(ExitStartFailed)
		return nil
	}

	// Block until signal; then srv handles drain/close internally.
	<-ctx.Done()
	srv.Close()
	fmt.Fprintln(stderr, "serve: shutdown complete")
	return nil
}
