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
	"log"
	"os"
	"strings"
)

type OpensipsType uint8

const (
	OpensipsTypeUnknow OpensipsType = iota
	OpensipsType3
	OpensipsType2
	OpensipsType1
)

// opensips
type OpensipsConfig struct {
	eConfig
	Opensipspath string       `json:"opensipsPath"`
	ElfType      uint8        //
	Version      OpensipsType //
	VersionInfo  string       // info
}

func NewOpensipsConfig() *OpensipsConfig {
	config := &OpensipsConfig{}
	return config
}

func (this *OpensipsConfig) Check() error {

	if this.Opensipspath == "" || len(strings.TrimSpace(this.Opensipspath)) <= 0 {
		return errors.New("Opensips path cant be null.")
	}

	if this.GetNoSearch() {
		log.Printf("RTCAGENT :: opensips. No search")
		return nil
	}

	_, e := os.Stat(this.Opensipspath)
	if e != nil {
		return e
	}
	this.ElfType = ElfTypeBin

	_elf, e := elf.Open(this.Opensipspath)
	if e != nil {
		return e
	}

	//if funcName == "" {
	//	return errors.New(fmt.Sprintf("cant match opensips 'receive_msg'function to hook with opensips file::%s", this.Opensipspath))
	//}

	this.Version = OpensipsType3
	this.VersionInfo = "opensips"

	found := strings.Contains("receive_msg", "COM_DATA")
	if found {
		roSection := _elf.Section(".rodata")
		var buf []byte
		buf, e = roSection.Data()
		var ver OpensipsType
		var verInfo string
		if e == nil {
			ver, verInfo = getOpensipsVer(buf)
		}
		this.Version = ver
		this.VersionInfo = verInfo
	}

	return nil
}

func getOpensipsVer(buf []byte) (OpensipsType, string) {

	var slice [][]byte

	if slice = bytes.Split(buf, []byte("\x00")); slice == nil {
		return OpensipsTypeUnknow, ""
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

		opensipsVer := string(slice[i])
		if strings.Contains(opensipsVer, "opensips 3.") {
			//fmt.Println(fmt.Sprintf("offset:%d, body:%s", offset, slice[i]))
			return OpensipsType3, opensipsVer
		} else if strings.Contains(opensipsVer, "opensips 2.") {
			return OpensipsType2, opensipsVer
		} else if strings.Contains(opensipsVer, "opensips 1.") {
			return OpensipsType1, opensipsVer
		}
		offset += len(slice[i]) + 1
	}
	return OpensipsTypeUnknow, ""
}
