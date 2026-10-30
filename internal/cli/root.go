//
// Package cli wires up the mhi command tree: ca, serve, config, doctor, and
// version. Per spec v0.3 §4.1 these commands only read explicitly given files;
// nothing auto-discovers config in CWD, parent dirs, or HOME.
// Exit codes (spec §4.8):
//	0 normal, 2 invalid config / CA missing, 3 start failure,
//	4 output failure / observation loss, 130 SIGINT.
//
// Commands in M0 are wired but gated on config loading described in §4.4:
// explicit CLI flag > process env MHI_* snapshot > .env file > YAML > defaults.
package cli

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"
)

// Exit codes from spec v0.3 §4.8.
const (
	ExitOK             = 0
	ExitInvalidConfig  = 2 // bad config / required CA missing
	ExitStartFailed    = 3
	ExitOutputFailure  = 4
	ExitSignalInterrupt = 130
)

// Run builds the command tree and executes it against the given args. It
// returns the process exit code. Sub-command wiring for serve/ca/config/doctor
// follows M0–M2 of the checklist; unknown commands fall through to cobra's
// error path with exit code 2.
func Run(stdout, stderr io.Writer, args []string) int {
	root := newRootCmd(stdout, stderr)
	cmd, err := root.ExecuteC()
	if err != nil {
		if cmd != nil {
			fmt.Fprintln(stderr, cmd.ErrPrefix(), err)
		} else {
			fmt.Fprintln(stderr, "Error:", err)
		}
		return ExitInvalidConfig // cobra-level usage/unknown-command errors
	}
	return exitCode
}

// exitCode tracks a sub-command's explicit exit status; sub-packages set it via
// setExitCode rather than calling os.Exit deep in non-main code.
var exitCode = ExitOK

func setExitCode(code int) { exitCode = code }

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "mhi",
		Short:         "Mobile HTTP Inspector: local HTTP observation for approved devices",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)

	for _, sub := range []*cobra.Command{
		newServeCmd(stdout, stderr, registerGlobalFlags),
		newCACmd(stdout, stderr, registerGlobalFlags),
		newConfigCmd(stdout, stderr, registerGlobalFlags),
		newDoctorCmd(stdout, stderr, registerGlobalFlags),
	} {
		root.AddCommand(sub)
	}

	// version — T-002: pure, opens no network, creates no CA, reads no files
	// beyond its own compile-time values.
	root.AddCommand(newVersionCmd(stdout))

	// Hidden completion command removed: not part of the CLI contract (§4.1).
	// cobra generates one by default; spec's command table has no completion
	// entry, so we suppress it to keep `mhi --help` implying exactly the
	// documented surface.
	root.CompletionOptions.DisableDefaultCmd = true
	return root
}

// newVersionCmd implements `mhi version` (spec §4.1): app version, Go runtime
// version, proxy library version, build commit. Values are filled by
// -ldflags at build time; absent injection they report "dev".
func newVersionCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print app, Go, proxy version and build commit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(stdout, "mhi version %s (go %s, goproxy %s, commit %s)\n",
				Version, runtimeGOVersion(), proxyVersion, buildCommit)
		},
	}
}

// Version is the CLI version, overridable via -ldflags "-X main.Version=…".
// Kept here so it is visible on the package boundary without a main-package
// dependency from internal/cli.
var (
	Version     = "0.0.1-dev"
	buildCommit = "unknown"
	proxyVersion = "v1.9.2" // goproxy source-review baseline, pinned in go.mod
)

func runtimeGOVersion() string { return runtime.Version() }
