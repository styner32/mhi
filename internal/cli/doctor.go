//
// doctor — read-only local file/network-candidate inspection (spec §4.1).
// M0 wires the surface; per AC-01 nothing here creates a CA, opens a
// listener, or changes the Mac keychain/system proxy.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newDoctorCmd(stdout, stderr io.Writer, registerGlobalFlags globalFlagRegistrar) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Read-only check of local files and network candidates",
		RunE: func(c *cobra.Command, args []string) error {
			setExitCode(ExitInvalidConfig)
			return fmt.Errorf("doctor: read-only checks land in M3 (T-311 doctor behavior); not yet implemented")
		},
	}
	registerGlobalFlags(cmd)
	return cmd
}
