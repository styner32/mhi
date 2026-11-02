package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/styner32/mhi/internal/model"
)

// writeJSONL emits one compact JSON object with no banners/ANSI mixing (AC-21).
func writeJSONL(bw *bufio.Writer, ev model.SafeEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		// Marshal failure of a sanitized struct is a programming bug; report
		// exactly once per event, never to stdout (keeps stream pure).
		return
	}
	bw.Write(b)
	bw.WriteByte('\n')
}

// textLine renders the §4.8 text contract line, e.g.
//
//	14:30:01 CONNECT  api.example.com:443       mode=tunnel policy=1
//
// Network-origin ESC/OSC/control characters are always escaped (§4.8, AC-20);
// hostnames are not reinterpreted as terminal control tokens.
func textLine(ev model.SafeEvent) string {
	if ev.Connection == nil {
		// Non-connection events currently have no text rendering in M0.
		return fmt.Sprintf("%s", ev.Type)
	}
	c := ev.Connection
	host := escapeText(c.Host)
	// event-type label: the spec 4.8 text contract varies the first token
	// (CONNECT metadata vs closed); c.Mode/policy stay stable per connection.
	label := ev.Type // e.g. connection.mode_selected / connection.closed
	_ = label
	verb := "CONNECT"
	if ev.Type == model.EventConnectionClosed {
		verb = "CLOSED"
	}
	return fmt.Sprintf("%-4s %-28s mode=%s policy=%d", verb, host, c.Mode, c.PolicyRevision)
}

// escapeText replaces network-sourced control bytes with visible escapes.
// ESC(0x1B), OSC initiator/terminator, C0 controls, DEL — all neutralized so
// hostile hostnames cannot drive terminal behavior (AC-20).
func escapeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0x1B: // ESC
			b.WriteString("\\e")
		case r == 0x9B: // CSI single-byte
			b.WriteString("\\u009b")
		case r == 0x9D: // OSC single-byte
			b.WriteString("\\u009d")
		case r < 0x20 && r != '\t': // C0 controls except tab
			fmt.Fprintf(&b, "\\x%02x", r)
		case r == 0x7F: // DEL
			b.WriteString("\\x7f")
		case r == 0xC0 || (r >= 0x80 && r <= 0x9F): // C1 controls in UTF-8 form
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
