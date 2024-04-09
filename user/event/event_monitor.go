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

package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type MonitorSysCallEvent struct {
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`
	Saddr uint32 `json:"saddr"`
	Daddr uint32 `json:"daddr"`
	SRTT  uint32 `json:"srtt"`
}

type MonitorEvent struct {
	event_type EventType
	DataType   int64    `json:"dataType"`
	Timestamp  uint64   `json:"timestamp"`
	Pid        uint32   `json:"pid"`
	Tid        uint32   `json:"tid"`
	SysCallId  uint64   `json:"syscall_id"`
	Comm       [16]byte `json:"Comm"`
}

func (tcpev *MonitorEvent) Decode(payload []byte) (err error) {

	buf := bytes.NewBuffer(payload)

	if err = binary.Read(buf, binary.LittleEndian, &tcpev.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysCallId); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Comm); err != nil {
		return
	}

	return nil
}

func (tcpev *MonitorEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d", tcpev.Pid, tcpev.Tid)
}

func (tcpev *MonitorEvent) Payload() []byte {
	da := []byte{}
	return da
}

func (tcpev *MonitorEvent) PayloadLen() int {
	return 0
}

func (tcpev *MonitorEvent) StringHex() string {
	//var connInfo string
	//perfix = COLORGREEN
	//s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Mask: %d, Payload:\n%s", tcpev.Pid, CToGoString(tcpev.Comm[:]),
	//	tcpev.Tid, connInfo, v, 1, b.String())
	//s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, SrcPort: %d, DstPort:%d, SrcIPv6: %d, DstIPv6: %d, Payload:\n%s", tcpev.Pid, CToGoString(tcpev.Comm[:]),
	//	tcpev.Tid, connInfo, v.String(), tcpev.RcInfo.SrcPort, tcpev.RcInfo.DstPort, 1, 1, b.String())
	return "a"
}

// intToIP converts IPv4 number to net.IP

func (tcpev *MonitorEvent) String() string {
	//addr := tcpev.module.(*module.MOpenSSLProbe).GetConn(tcpev.Pid, tcpev.Fd)
	prefix := COLORGREEN

	funcName := "unknown"
	if tcpev.SysCallId == 1 {
		funcName = "write"
	} else if tcpev.SysCallId == 2 {
		funcName = "open"
	} else if tcpev.SysCallId == 3 {
		funcName = "read"
	} else if tcpev.SysCallId == 15 {
		funcName = "chown"
	} else if tcpev.SysCallId == 21 {
		funcName = "access"
	} else if tcpev.SysCallId == 23 {
		funcName = "truncate"
	} else if tcpev.SysCallId == 62 {
		funcName = "sys_kill"
	} else if tcpev.SysCallId == 34 {
		funcName = "pause"
	} else if tcpev.SysCallId == 128 {
		funcName = "rt_sigtimedwait"
	} else if tcpev.SysCallId == 232 {
		funcName = "epoll_wait"
	} else if tcpev.SysCallId == 281 {
		funcName = "futex"
	}

	s := fmt.Sprintf("%s %d %d %d %s %d %s %d ns %s", prefix, tcpev.DataType, tcpev.Pid, tcpev.Tid, string(tcpev.Comm[:]), tcpev.SysCallId, funcName, 0, COLORRESET)
	return s
}

func (tcpev *MonitorEvent) SendHep() bool {
	//Lets allow to send HEP
	return false
}

func (tcpev *MonitorEvent) GenerateHEP() ([]byte, error) {

	return nil, fmt.Errorf("no data")

}

func (tcpev *MonitorEvent) Clone() IEventStruct {
	event := new(MonitorEvent)
	return event
}

func (tcpev *MonitorEvent) EventType() EventType {
	return 0
}
