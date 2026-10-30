//
// ca sub-commands (spec §4.1, §5) — lobal-only CA lifecycle:
//
//	mhi ca init     — create independent ECDSA P-256 CA key/cert + public DER
//	                  .cer + PEM + metadata.json in state-dir. Never overwrites
//	                  existing files. Prints only the public .cer path (stdout)
//	                  and success/fingerprint/expiry (stderr).
//	mhi ca path     — print absolute path of the public .cer, or exit nonzero
//	                  if absent. Never auto-creates the CA.
//	mhi ca status   — fingerprint/expiry/file ownership/key match/CA flag,
//	                  optional --json. No secret key contents.
//	mhi ca delete   — fingerprint-confirmed delete; refuses while serve holds
//	                  run.lock; --yes --fingerprint <sha256> for non-TTY.
//
// Options explicitly NOT provided (AC-36/37): import, --insecure fallback,
// shared/embedded CA, download server, QR, install wizard, keychain changes.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newCACmd(stdout, stderr io.Writer, registerGlobalFlags globalFlagRegistrar) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Local CA lifecycle (init/path/status/delete)",
	}

	init := &cobra.Command{
		Use:   "init",
		Short: "Create a fresh local CA (key, public DER .cer, PEM, metadata)",
		RunE: func(c *cobra.Command, args []string) error {
			setExitCode(ExitInvalidConfig)
			return fmt.Errorf("ca init: local CA generation lands in M1 (T-101); not yet implemented")
		},
	}

	path := &cobra.Command{
		Use:   "path",
		Short: "Print the public .cer absolute path (one line)",
		RunE: func(c *cobra.Command, args []string) error {
			setExitCode(ExitInvalidConfig)
			return fmt.Errorf("ca path: lands in M1 (T-102); not yet implemented")
		},
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show CA fingerprint/expiry/file state (no secrets)",
		RunE: func(c *cobra.Command, args []string) error {
			setExitCode(ExitInvalidConfig)
			return fmt.Errorf("ca status: lands in M1 (T-103); not yet implemented")
		},
	}

	del := &cobra.Command{
		Use:   "delete",
		Short: "Delete the app-owned CA files after fingerprint confirmation",
		RunE: func(c *cobra.Command, args []string) error {
			setExitCode(ExitInvalidConfig)
			return fmt.Errorf("ca delete: lands in M3 (T-311); not yet implemented")
		},
	}

	for _, sub := range []*cobra.Command{init, path, status, del} {
		registerGlobalFlags(sub)
		// ca-scoped options per spec §5.4.
		if sub == del {
			sub.Flags().Bool("yes", false, "non-interactive delete; requires --fingerprint")
			sub.Flags().String("fingerprint", "", "full SHA-256 fingerprint to confirm deletion")
		}
		if sub == status {
			sub.Flags().Bool("json", false, "emit machine-readable JSON status")
		}
		cmd.AddCommand(sub)
	}
	return cmd
}
