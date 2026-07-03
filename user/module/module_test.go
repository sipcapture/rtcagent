//go:build !androidgki
// +build !androidgki

package module_test

import (
	"testing"

	"rtcagent/user/module"
)

func TestKamailioAndOpensipsModulesRegistered(t *testing.T) {
	if mod := module.GetModuleByName(module.ModuleNameKamailio); mod == nil {
		t.Fatal("kamailio module is not registered")
	}
	if mod := module.GetModuleByName(module.ModuleNameOpensips); mod == nil {
		t.Fatal("opensips module is not registered")
	}
}
