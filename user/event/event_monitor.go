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
	Type         uint8        `json:"type"`
	SysEvent     SysEvent     `json:"sys_event"`
	NetworkEvent NetworkEvent `json:"network_event"`
}

type SysEvent struct {
	Timestamp     uint64   `json:"timestamp"`
	Pid           uint32   `json:"pid"`
	Tid           uint32   `json:"tid"`
	SysCallId     uint32   `json:"syscall_id"`
	Latency       uint32   `json:"latency"`
	Comm          [16]byte `json:"Comm"`
	NrCpusAllowed uint32   `json:"nr_cpus_allowed"`
	RecentUsedCpu uint32   `json:"recent_used_cpu"`
	ExitCode      uint32   `json:"exit_code"`
	Cookie        uint64   `json:"cookie"`
	funcName      string   `json:"func_name"`
}

type NetworkEvent struct {
	Timestamp     uint64   `json:"timestamp"`
	Pid           uint32   `json:"pid"`
	Tid           uint32   `json:"tid"`
	SysCallId     uint32   `json:"syscall_id"`
	Latency       uint32   `json:"latency"`
	Comm          [16]byte `json:"Comm"`
	NrCpusAllowed uint32   `json:"nr_cpus_allowed"`
	RecentUsedCpu uint32   `json:"recent_used_cpu"`
	ExitCode      uint32   `json:"exit_code"`
	Cookie        uint64   `json:"cookie"`
	funcName      string   `json:"func_name"`
}

func (tcpev *MonitorEvent) Decode(payload []byte) (err error) {

	buf := bytes.NewBuffer(payload)

	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Type); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.SysCallId); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.Latency); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.NrCpusAllowed); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.RecentUsedCpu); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.ExitCode); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SysEvent.Cookie); err != nil {
		return
	}

	return nil
}

func (tcpev *MonitorEvent) DoCorrelation(userFunctionArray []string) bool {

	tcpev.SysEvent.funcName = "unknown"

	if tcpev.SysEvent.SysCallId == 1 {
		tcpev.SysEvent.funcName = "write"
	} else if tcpev.SysEvent.SysCallId == 2 {
		tcpev.SysEvent.funcName = "open"
	} else if tcpev.SysEvent.SysCallId == 3 {
		tcpev.SysEvent.funcName = "read"
	} else if tcpev.SysEvent.SysCallId == 15 {
		tcpev.SysEvent.funcName = "chown"
	} else if tcpev.SysEvent.SysCallId == 21 {
		tcpev.SysEvent.funcName = "access"
	} else if tcpev.SysEvent.SysCallId == 23 {
		tcpev.SysEvent.funcName = "truncate"
	} else if tcpev.SysEvent.SysCallId == 62 {
		tcpev.SysEvent.funcName = "sys_kill"
	} else if tcpev.SysEvent.SysCallId == 34 {
		tcpev.SysEvent.funcName = "pause"
	} else if tcpev.SysEvent.SysCallId == 128 {
		tcpev.SysEvent.funcName = "rt_sigtimedwait"
	} else if tcpev.SysEvent.SysCallId == 232 {
		tcpev.SysEvent.funcName = "epoll_wait"
	} else if tcpev.SysEvent.SysCallId == 281 {
		tcpev.SysEvent.funcName = "futex"
	}

	if int(tcpev.SysEvent.Cookie) > 0 && int(tcpev.SysEvent.Cookie) <= len(userFunctionArray) {
		tcpev.SysEvent.funcName = userFunctionArray[tcpev.SysEvent.Cookie-1]
	}

	return false
}

func (tcpev *MonitorEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d", tcpev.SysEvent.Pid, tcpev.SysEvent.Tid)
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

	s := fmt.Sprintf("%s Time: %d Pid: %d Tid: %d Comm: [%s] SysID: %d Func:%s Time Latency: %d ns, Max Cpu: %d, Recent CPU: %d, Exit Code: %d, Cookie: %d %s", prefix,
		tcpev.SysEvent.Timestamp, tcpev.SysEvent.Pid, tcpev.SysEvent.Tid, string(tcpev.SysEvent.Comm[:]), tcpev.SysEvent.SysCallId, tcpev.SysEvent.funcName, tcpev.SysEvent.Latency, tcpev.SysEvent.NrCpusAllowed, tcpev.SysEvent.RecentUsedCpu, tcpev.SysEvent.ExitCode, tcpev.SysEvent.Cookie,
		COLORRESET)
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
