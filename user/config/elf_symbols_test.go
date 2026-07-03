//go:build !androidgki
// +build !androidgki

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func buildProbeTarget(t *testing.T, dir, out string, source string) string {
	t.Helper()
	bin := filepath.Join(dir, out)
	outBytes, err := exec.Command("gcc", "-o", bin, source).CombinedOutput()
	if err != nil {
		t.Fatalf("build probe target: %v\n%s", err, outBytes)
	}
	return bin
}

func TestRequireElfSymbols(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join("..", "..", "testdata", "probe_target.c")
	bin := buildProbeTarget(t, tmp, "probe-target", src)

	if err := requireElfSymbols(bin, "receive_msg", "udp_send", "tcp_send"); err != nil {
		t.Fatalf("expected symbols in probe target: %v", err)
	}

	if err := requireElfSymbols(bin, "missing_symbol"); err == nil {
		t.Fatal("expected missing symbol error")
	}
}

func TestKamailioConfigCheckValidatesSymbols(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join("..", "..", "testdata", "probe_target.c")
	bin := buildProbeTarget(t, tmp, "kamailio", src)

	cfg := NewKamailioConfig()
	cfg.Kamailiopath = bin
	if err := cfg.Check(); err != nil {
		t.Fatalf("kamailio config check failed: %v", err)
	}
}

func TestOpensipsConfigCheckValidatesSymbols(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join("..", "..", "testdata", "probe_target.c")
	bin := buildProbeTarget(t, tmp, "opensips", src)

	cfg := NewOpensipsConfig()
	cfg.Opensipspath = bin
	if err := cfg.Check(); err != nil {
		t.Fatalf("opensips config check failed: %v", err)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
