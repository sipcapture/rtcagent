//go:build !androidgki
// +build !androidgki

package config

import (
	"debug/elf"
	"fmt"
)

func hasElfSymbol(elfFile *elf.File, name string) bool {
	for _, lookup := range []func() ([]elf.Symbol, error){
		elfFile.Symbols,
		elfFile.DynamicSymbols,
	} {
		symbols, err := lookup()
		if err != nil {
			continue
		}
		for _, sym := range symbols {
			if sym.Name == name {
				return true
			}
		}
	}
	return false
}

func requireElfSymbols(path string, names ...string) error {
	elfFile, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer elfFile.Close()

	var missing []string
	for _, name := range names {
		if !hasElfSymbol(elfFile, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("binary %s is missing required symbols: %v", path, missing)
	}
	return nil
}
