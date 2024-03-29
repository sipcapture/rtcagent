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
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"strings"
)

type FreeSwitchType uint8

const (
	FreeSwitchTypeUnknow FreeSwitchType = iota
	FreeSwitchType5
	FreeSwitchType4
	FreeSwitchType3
	FreeSwitchType2
)

// freeswitch
type FreeSwitchConfig struct {
	eConfig
	FreeSwitchpath string         `json:"freeswitchPath"`
	ElfType        uint8          //
	Version        FreeSwitchType //
	VersionInfo    string         // info
}

func NewFreeSwitchConfig() *FreeSwitchConfig {
	config := &FreeSwitchConfig{}
	return config
}

func (this *FreeSwitchConfig) Check() error {

	if this.FreeSwitchpath == "" || len(strings.TrimSpace(this.FreeSwitchpath)) <= 0 {
		return errors.New("FreeSwitch path cant be null.")
	}

	_, e := os.Stat(this.FreeSwitchpath)
	if e != nil {
		return e
	}
	this.ElfType = ElfTypeBin

	_elf, e := elf.Open(this.FreeSwitchpath)
	if e != nil {
		return e
	}

	//if funcName == "" {
	//	return errors.New(fmt.Sprintf("cant match freeswitch 'receive_msg'function to hook with freeswitch file::%s", this.FreeSwitchpath))
	//}

	this.Version = FreeSwitchType5
	this.VersionInfo = "freeswitch"

	found := strings.Contains("receive_msg", "COM_DATA")
	if found {
		roSection := _elf.Section(".rodata")
		var buf []byte
		buf, e = roSection.Data()
		var ver FreeSwitchType
		var verInfo string
		if e == nil {
			ver, verInfo = getFreeSwitchVer(buf)
		}
		this.Version = ver
		this.VersionInfo = verInfo
	}

	return nil
}

func getFreeSwitchVer(buf []byte) (FreeSwitchType, string) {

	var slice [][]byte

	if slice = bytes.Split(buf, []byte("\x00")); slice == nil {
		return FreeSwitchTypeUnknow, ""
	}

	length := len(slice)
	var offset int

	for i := 0; i < length; i++ {
		if len(slice[i]) == 0 {
			continue
		}

		l := len(slice[i])
		if l > 15 || l < 8 {
			continue
		}

		freeswitchVer := string(slice[i])
		if strings.Contains(freeswitchVer, "freeswitch 5.") {
			//fmt.Println(fmt.Sprintf("offset:%d, body:%s", offset, slice[i]))
			return FreeSwitchType5, freeswitchVer
		} else if strings.Contains(freeswitchVer, "freeswitch 4.") {
			return FreeSwitchType4, freeswitchVer
		} else if strings.Contains(freeswitchVer, "freeswitch 3.") {
			return FreeSwitchType3, freeswitchVer
		}
		offset += len(slice[i]) + 1
	}
	return FreeSwitchTypeUnknow, ""
}
