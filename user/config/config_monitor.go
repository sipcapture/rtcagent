//go:build !androidgki
// +build !androidgki

/*

LINK - http://github.com/sipcapture/rtcagent

Copyright (C) 2023 QXIP B.V.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

package config

import (
	"errors"
	"log"
	"os"
	"rtcagent/model"
	"strings"
)

type MonitorType uint8

const (
	MonitorTypeUnknow MonitorType = iota
	MonitorType5
	MonitorType4
	MonitorType3
	MonitorType2
)

// tcprtt
type MonitorConfig struct {
	eConfig
	Monitorpath    string      `json:"monitPath"`
	SysCall        bool        //
	UserCall       bool        //
	NetworkCall    bool        //
	NetworkLatency bool        //
	ElfType        uint8       //
	Version        MonitorType //
	VersionInfo    string      // info
	UserFunctions  []string    // user functions
	PromCh         chan model.AggregatedMetricValue
	UiCh           chan model.AggregatedTimeMetricValue
}

func NewMonitorConfig() *MonitorConfig {
	config := &MonitorConfig{}
	config.PromCh = make(chan model.AggregatedMetricValue, 500)
	config.UiCh = make(chan model.AggregatedTimeMetricValue, 500)

	return config
}

func (this *MonitorConfig) Check() error {

	if this.Monitorpath == "" || len(strings.TrimSpace(this.Monitorpath)) <= 0 {
		return errors.New("binary path cant be null.")
	}

	if this.GetNoSearch() {
		log.Printf("RTCAGENT :: binary. No search")
		return nil
	}

	_, e := os.Stat(this.Monitorpath)
	if e != nil {
		return e
	}
	this.ElfType = ElfTypeBin

	return nil
}
