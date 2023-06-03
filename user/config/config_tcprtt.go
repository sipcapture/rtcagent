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

type TcprttType uint8

const (
	TcprttTypeUnknow TcprttType = iota
	TcprttType5
	TcprttType4
	TcprttType3
	TcprttType2
)

// tcprtt
type TcprttConfig struct {
	eConfig
	Tcprttpath  string     `json:"tcprttPath"`
	ElfType     uint8      //
	Version     TcprttType //
	VersionInfo string     // info
}

func NewTcprttConfig() *TcprttConfig {
	config := &TcprttConfig{}
	return config
}

func (this *TcprttConfig) Check() error {

	//if funcName == "" {
	//	return errors.New(fmt.Sprintf("cant match tcprtt 'receive_msg'function to hook with tcprtt file::%s", this.Tcprttpath))
	//}

	return nil
}
