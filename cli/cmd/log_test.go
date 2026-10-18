package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newTestCommand(debug bool) *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("debug", debug, "enable debug logging")
	return cmd
}

func TestNewLoggerEmitsStructuredRecord(t *testing.T) {
	var buf bytes.Buffer

	newLoggerTo(&buf, "kamailio", newTestCommand(false)).Printf("hello %s", "world")

	out := buf.String()
	for _, want := range []string{`level=INFO`, `component=kamailio`, `msg="hello world"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log output %q does not contain %q", out, want)
		}
	}
}

func TestNewLoggerDebugLevel(t *testing.T) {
	var buf bytes.Buffer

	newLoggerTo(&buf, "kamailio", newTestCommand(true)).Printf("debugging")

	if out := buf.String(); !strings.Contains(out, `level=DEBUG`) {
		t.Fatalf("expected a DEBUG record, got %q", out)
	}
}
