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
	Monitorpath string      `json:"tcprttPath"`
	SysCall     bool        //
	UserCall    bool        //
	ElfType     uint8       //
	Version     MonitorType //
	VersionInfo string      // info
}

func NewMonitorConfig() *MonitorConfig {
	config := &MonitorConfig{}
	return config
}

func (this *MonitorConfig) Check() error {

	//if funcName == "" {
	//	return errors.New(fmt.Sprintf("cant match tcprtt 'receive_msg'function to hook with tcprtt file::%s", this.Monitorpath))
	//}

	return nil
}
