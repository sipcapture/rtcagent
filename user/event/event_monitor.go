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
	"net"
	"rtcagent/model"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

type uint128 struct {
	hi uint64
	lo uint64
}

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
	funcName     string       `json:"func_name"`
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
}

type NetworkEvent struct {
	Timestamp uint64   `json:"timestamp"`
	IPType    uint32   `json:"iptype"`
	SrcIPv4   uint32   `json:"src_ipv4"`
	DstIPv4   uint32   `json:"dst_ipv4"`
	SrcIPv6   uint128  `json:"src_ipv6"`
	DstIPv6   uint128  `json:"dst_ipv6"`
	SrcPort   uint16   `json:"src_port"`
	DstPort   uint16   `json:"dst_port"`
	DeltaUS   uint64   `json:"delta_us"`
	TsUS      uint64   `json:"ts_us"`
	Pid       uint32   `json:"pid"`
	Tid       uint32   `json:"tid"`
	Comm      [16]byte `json:"Comm"`
}

func (tcpev *MonitorEvent) Decode(payload []byte) (err error) {

	buf := bytes.NewBuffer(payload)

	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Type); err != nil {
		return
	}

	fmt.Printf("MonitorEvent Decode type: %d\n", tcpev.Type)

	if tcpev.Type == 1 {

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
	} else if tcpev.Type == 2 {

		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.Timestamp); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.SrcIPv4); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.DstIPv4); err != nil {
			return

		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.SrcIPv6.hi); err != nil {
			return
		}

		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.SrcIPv6.lo); err != nil {
			return
		}

		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.DstIPv6.hi); err != nil {
			return
		}

		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.DstIPv6.lo); err != nil {
			return
		}

		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.SrcPort); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.DstPort); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.Tid); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.IPType); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.DeltaUS); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.TsUS); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.Pid); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &tcpev.NetworkEvent.Comm); err != nil {
			return
		}
	}

	return nil
}

func (tcpev *MonitorEvent) DoCorrelation(userFunctionArray []string) bool {

	tcpev.funcName = "unknown"

	if tcpev.SysEvent.SysCallId == 1 {
		tcpev.funcName = "write"
	} else if tcpev.SysEvent.SysCallId == 2 {
		tcpev.funcName = "open"
	} else if tcpev.SysEvent.SysCallId == 3 {
		tcpev.funcName = "read"
	} else if tcpev.SysEvent.SysCallId == 15 {
		tcpev.funcName = "chown"
	} else if tcpev.SysEvent.SysCallId == 21 {
		tcpev.funcName = "access"
	} else if tcpev.SysEvent.SysCallId == 23 {
		tcpev.funcName = "truncate"
	} else if tcpev.SysEvent.SysCallId == 62 {
		tcpev.funcName = "sys_kill"
	} else if tcpev.SysEvent.SysCallId == 34 {
		tcpev.funcName = "pause"
	} else if tcpev.SysEvent.SysCallId == 128 {
		tcpev.funcName = "rt_sigtimedwait"
	} else if tcpev.SysEvent.SysCallId == 232 {
		tcpev.funcName = "epoll_wait"
	} else if tcpev.SysEvent.SysCallId == 281 {
		tcpev.funcName = "futex"
	}

	if int(tcpev.SysEvent.Cookie) > 0 && int(tcpev.SysEvent.Cookie) <= len(userFunctionArray) {
		tcpev.funcName = userFunctionArray[tcpev.SysEvent.Cookie-1]
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

	fmt.Printf("MonitorEvent type: %d\n", tcpev.Type)
	s := ""

	if tcpev.Type == 1 {
		s = fmt.Sprintf("%s Time: %d Pid: %d Tid: %d Comm: [%s] SysID: %d Func:%s Time Latency: %d ns, Max Cpu: %d, Recent CPU: %d, Exit Code: %d, Cookie: %d %s", prefix,
			tcpev.SysEvent.Timestamp, tcpev.SysEvent.Pid, tcpev.SysEvent.Tid, string(tcpev.SysEvent.Comm[:]), tcpev.SysEvent.SysCallId, tcpev.funcName, tcpev.SysEvent.Latency, tcpev.SysEvent.NrCpusAllowed, tcpev.SysEvent.RecentUsedCpu, tcpev.SysEvent.ExitCode, tcpev.SysEvent.Cookie,
			COLORRESET)
	} else if tcpev.Type == 2 {

		s = fmt.Sprintf("%s Time: %d Pid: %d Tid: %d Comm: [%s], IPType: %d, Src_Port: %d, Dst_Port: %d, Src IP: %d, Dst IP: %d %s", prefix,
			tcpev.NetworkEvent.Timestamp, tcpev.NetworkEvent.Pid, tcpev.NetworkEvent.Tid, string(tcpev.NetworkEvent.Comm[:]), tcpev.NetworkEvent.IPType,
			tcpev.NetworkEvent.SrcPort, tcpev.NetworkEvent.DstPort,
			tcpev.NetworkEvent.SrcIPv4, tcpev.NetworkEvent.DstIPv4,
			COLORRESET)
	}

	return s
}

func (tcpev *MonitorEvent) SendHep() bool {
	//Lets allow to send HEP
	return false
}

func (tcpev *MonitorEvent) GenerateMetric() model.AggregatedMetricValue {
	//Lets allow to send HEP

	labelNames := []string{}
	//src_ip
	src_ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(src_ip, tcpev.NetworkEvent.SrcIPv4)
	dst_ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(dst_ip, tcpev.NetworkEvent.DstIPv4)
	labelNames = append(labelNames, "alex-kamailio")
	labelNames = append(labelNames, src_ip.String())
	labelNames = append(labelNames, dst_ip.String())
	labelNames = append(labelNames, strconv.Itoa(int(tcpev.NetworkEvent.SrcPort))) // Convert SrcPort to string
	labelNames = append(labelNames, strconv.Itoa(int(tcpev.NetworkEvent.DstPort))) // Convert SrcPort to string

	newAM := model.AggregatedMetricValue{
		Labels: labelNames,
		Value:  float64(tcpev.NetworkEvent.DeltaUS),
		Name:   "tcp_receive_state",
		Type:   prometheus.GaugeValue,
	}
	return newAM
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
