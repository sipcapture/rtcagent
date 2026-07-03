//go:build !androidgki
// +build !androidgki

package config

import (
	"errors"
	"os"
	"strings"
)

type RtpengineType uint8

const (
	RtpengineTypeUnknown RtpengineType = iota
	RtpengineTypeCurrent
)

type RtpengineConfig struct {
	eConfig
	Rtpenginepath string        `json:"rtpenginePath"`
	ElfType       uint8         //
	Version       RtpengineType //
	VersionInfo   string        //
}

func NewRtpengineConfig() *RtpengineConfig {
	return &RtpengineConfig{}
}

func (this *RtpengineConfig) Check() error {
	if this.Rtpenginepath == "" || len(strings.TrimSpace(this.Rtpenginepath)) <= 0 {
		return errors.New("RTPEngine path cant be null.")
	}

	if this.GetNoSearch() {
		return nil
	}

	if _, err := os.Stat(this.Rtpenginepath); err != nil {
		return err
	}

	this.ElfType = ElfTypeBin
	this.Version = RtpengineTypeCurrent
	this.VersionInfo = "rtpengine"
	return nil
}
