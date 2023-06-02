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

type TcpdropType uint8

const (
	TcpdropTypeUnknow TcpdropType = iota
	TcpdropType5
	TcpdropType4
	TcpdropType3
	TcpdropType2
)

// tcpdrop
type TcpdropConfig struct {
	eConfig
	Tcpdroppath string      `json:"tcpdropPath"`
	ElfType     uint8       //
	Version     TcpdropType //
	VersionInfo string      // info
}

func NewTcpdropConfig() *TcpdropConfig {
	config := &TcpdropConfig{}
	return config
}

func (this *TcpdropConfig) Check() error {

	//if funcName == "" {
	//	return errors.New(fmt.Sprintf("cant match tcpdrop 'receive_msg'function to hook with tcpdrop file::%s", this.Tcpdroppath))
	//}

	return nil
}
