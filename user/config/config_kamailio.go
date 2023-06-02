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

type KamailioType uint8

const (
	KamailioTypeUnknow KamailioType = iota
	KamailioType5
	KamailioType4
	KamailioType3
	KamailioType2
)

// kamailio
type KamailioConfig struct {
	eConfig
	Kamailiopath string       `json:"kamailioPath"`
	ElfType      uint8        //
	Version      KamailioType //
	VersionInfo  string       // info
}

func NewKamailioConfig() *KamailioConfig {
	config := &KamailioConfig{}
	return config
}

func (this *KamailioConfig) Check() error {

	if this.Kamailiopath == "" || len(strings.TrimSpace(this.Kamailiopath)) <= 0 {
		return errors.New("Kamailio path cant be null.")
	}

	_, e := os.Stat(this.Kamailiopath)
	if e != nil {
		return e
	}
	this.ElfType = ElfTypeBin

	_elf, e := elf.Open(this.Kamailiopath)
	if e != nil {
		return e
	}

	//if funcName == "" {
	//	return errors.New(fmt.Sprintf("cant match kamailio 'receive_msg'function to hook with kamailio file::%s", this.Kamailiopath))
	//}

	this.Version = KamailioType5
	this.VersionInfo = "kamailio"

	found := strings.Contains("receive_msg", "COM_DATA")
	if found {
		roSection := _elf.Section(".rodata")
		var buf []byte
		buf, e = roSection.Data()
		var ver KamailioType
		var verInfo string
		if e == nil {
			ver, verInfo = getKamailioVer(buf)
		}
		this.Version = ver
		this.VersionInfo = verInfo
	}

	return nil
}

func getKamailioVer(buf []byte) (KamailioType, string) {

	var slice [][]byte

	if slice = bytes.Split(buf, []byte("\x00")); slice == nil {
		return KamailioTypeUnknow, ""
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

		kamailioVer := string(slice[i])
		if strings.Contains(kamailioVer, "kamailio 5.") {
			//fmt.Println(fmt.Sprintf("offset:%d, body:%s", offset, slice[i]))
			return KamailioType5, kamailioVer
		} else if strings.Contains(kamailioVer, "kamailio 4.") {
			return KamailioType4, kamailioVer
		} else if strings.Contains(kamailioVer, "kamailio 3.") {
			return KamailioType3, kamailioVer
		}
		offset += len(slice[i]) + 1
	}
	return KamailioTypeUnknow, ""
}
