//
// Package cli — shared command-tree plumbing.
package cli

import "github.com/spf13/cobra"

// globalFlagRegistrar installs the shared options of spec §4.1 on a command.
type globalFlagRegistrar func(*cobra.Command)

func registerGlobalFlags(cmd *cobra.Command) {
	cmd.Flags().String("state-dir", "", "override state dir (default os.UserConfigDir()/mhi)")
	cmd.Flags().String("config", "", "explicit YAML config path")
	cmd.Flags().String("env-file", "", "explicit .env path")
	cmd.Flags().Bool("no-color", false, "disable ANSI color in terminal output")
}
