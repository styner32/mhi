// config sub-commands (spec §4.1):
//
//	mhi config check  — validate YAML/env syntax, schema, domains, CA state.
//	                     Read-only: opens no listener, installs no trust.
//	mhi config show   — print sanitized effective config + per-field source.
//	                     NOT a live view of a running process.
//
// M0 wires the command surface; M2 lands full precedence/provenance/shadow
// warnings (T-204). Until then they report their not-yet-implemented status
// honestly rather than pretending success.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newConfigCmd(stdout, stderr io.Writer, registerGlobalFlags globalFlagRegistrar) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Validate or show configuration (no listener, no trust changes)",
	}

	check := &cobra.Command{
		Use:   "check",
		Short: "Validate explicit config/env files; read-only",
		RunE: func(c *cobra.Command, args []string) error {
			cfgPath, _ := c.Flags().GetString("config")
			envPath, _ := c.Flags().GetString("env-file")
			if cfgPath == "" && envPath == "" {
				setExitCode(ExitInvalidConfig)
				return fmt.Errorf("config: --config and/or --env-file is required; CWD auto-discovery is intentionally not supported")
			}
			setExitCode(ExitInvalidConfig)
			return fmt.Errorf("config check: full validation (precedence, provenance, domain schema, CA state) lands in M2 (T-204); not yet implemented")
		},
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "Print sanitized effective config and field sources",
		RunE: func(c *cobra.Command, args []string) error {
			setExitCode(ExitInvalidConfig)
			return fmt.Errorf("config show: sanitized output + field provenance lands in M2 (T-204); not yet implemented")
		},
	}

	registerGlobalFlags(check)
	registerGlobalFlags(show)
	cmd.AddCommand(check, show)
	return cmd
}
