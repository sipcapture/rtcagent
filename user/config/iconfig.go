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

import "rtcagent/pkg/util/kernel"

type IConfig interface {
	Check() error //
	GetPid() uint64
	GetUid() uint64
	GetHex() bool
	GetDebug() bool
	GetNoSearch() bool
	SetPid(uint64)
	SetUid(uint64)
	SetHex(bool)
	SetDebug(bool)
	SetNoSearch(bool)
	EnableGlobalVar() bool //
}

type eConfig struct {
	Pid      uint64
	Uid      uint64
	IsHex    bool
	Debug    bool
	NoSearch bool
}

func (this *eConfig) GetPid() uint64 {
	return this.Pid
}

func (this *eConfig) GetUid() uint64 {
	return this.Uid
}

func (this *eConfig) GetDebug() bool {
	return this.Debug
}

func (this *eConfig) GetHex() bool {
	return this.IsHex
}

func (this *eConfig) GetNoSearch() bool {
	return this.NoSearch
}

func (this *eConfig) SetPid(pid uint64) {
	this.Pid = pid
}

func (this *eConfig) SetUid(uid uint64) {
	this.Uid = uid
}

func (this *eConfig) SetDebug(b bool) {
	this.Debug = b
}

func (this *eConfig) SetHex(isHex bool) {
	this.IsHex = isHex
}

func (this *eConfig) SetNoSearch(noSearch bool) {
	this.NoSearch = noSearch
}

func (this *eConfig) EnableGlobalVar() bool {
	kv, err := kernel.HostVersion()
	if err != nil {
		//log.Fatal(err)
		return true
	}
	if kv < kernel.VersionCode(5, 2, 0) {
		return false
	}
	return true
}
