package config

import (
	"testing"

	"rtcagent/pkg/util/kernel"
)

func TestEConfigAccessors(t *testing.T) {
	c := &eConfig{}

	c.SetPid(42)
	c.SetUid(1000)
	c.SetDebug(true)
	c.SetHex(true)
	c.SetNoSearch(true)

	if got := c.GetPid(); got != 42 {
		t.Errorf("GetPid: got %d, want 42", got)
	}
	if got := c.GetUid(); got != 1000 {
		t.Errorf("GetUid: got %d, want 1000", got)
	}
	if !c.GetDebug() {
		t.Error("GetDebug: got false, want true")
	}
	if !c.GetHex() {
		t.Error("GetHex: got false, want true")
	}
	if !c.GetNoSearch() {
		t.Error("GetNoSearch: got false, want true")
	}
}

func TestEConfigDefaultsAreZero(t *testing.T) {
	c := &eConfig{}

	if c.GetPid() != 0 || c.GetUid() != 0 || c.GetDebug() || c.GetHex() || c.GetNoSearch() {
		t.Fatalf("unexpected non-zero defaults: %+v", c)
	}
}

func TestEnableGlobalVarTracksKernelVersion(t *testing.T) {
	c := &eConfig{}

	kv, err := kernel.HostVersion()
	want := true
	if err == nil && kv < kernel.VersionCode(5, 2, 0) {
		want = false
	}

	if got := c.EnableGlobalVar(); got != want {
		t.Fatalf("EnableGlobalVar: got %v, want %v (kernel %v, err %v)", got, want, kv, err)
	}
}
