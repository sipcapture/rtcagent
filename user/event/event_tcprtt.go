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
)

type TcprttEvent struct {
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`
	Saddr uint32 `json:"saddr"`
	Daddr uint32 `json:"daddr"`
	SRTT  uint32 `json:"srtt"`
}

func (tcpev *TcprttEvent) Decode(payload []byte) (err error) {

	buf := bytes.NewBuffer(payload)

	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Sport); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Dport); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Saddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.Daddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &tcpev.SRTT); err != nil {
		return
	}

	return nil
}

func (tcpev *TcprttEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d", tcpev.Sport, tcpev.Dport)
}

func (tcpev *TcprttEvent) Payload() []byte {
	da := []byte{}
	return da
}

func (tcpev *TcprttEvent) PayloadLen() int {
	return 0
}

func (tcpev *TcprttEvent) StringHex() string {
	//var connInfo string
	//perfix = COLORGREEN
	//s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Mask: %d, Payload:\n%s", tcpev.Pid, CToGoString(tcpev.Comm[:]),
	//	tcpev.Tid, connInfo, v, 1, b.String())
	//s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, SrcPort: %d, DstPort:%d, SrcIPv6: %d, DstIPv6: %d, Payload:\n%s", tcpev.Pid, CToGoString(tcpev.Comm[:]),
	//	tcpev.Tid, connInfo, v.String(), tcpev.RcInfo.SrcPort, tcpev.RcInfo.DstPort, 1, 1, b.String())
	return "a"
}

// intToIP converts IPv4 number to net.IP

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

func (tcpev *TcprttEvent) String() string {
	//addr := tcpev.module.(*module.MOpenSSLProbe).GetConn(tcpev.Pid, tcpev.Fd)

	srcIP := intToIP(tcpev.Saddr)
	dstIP := intToIP(tcpev.Daddr)

	prefix := COLORGREEN

	s := fmt.Sprintf("%s%-15s %-6d -> %-15s %-6d %-6d%s", prefix, srcIP, tcpev.Sport, dstIP, tcpev.Dport, tcpev.SRTT, COLORRESET)
	return s
}

func (tcpev *TcprttEvent) SendHep() bool {
	//Lets allow to send HEP
	return false
}

func (tcpev *TcprttEvent) GenerateHEP() ([]byte, error) {

	return nil, fmt.Errorf("no data")

}

func (tcpev *TcprttEvent) Clone() IEventStruct {
	event := new(TcprttEvent)
	return event
}

func (tcpev *TcprttEvent) EventType() EventType {
	return 0
}

func (tcpev *TcprttEvent) DoCorrelation(userFunctionArray []string) bool {

	return false
}

func (tcpev *TcprttEvent) GenerateMetric() model.AggregatedMetricValue {
	//Lets allow to send HEP

	return model.AggregatedMetricValue{}
}

func (tcpev *TcprttEvent) GenerateTimeMetric() model.AggregatedTimeMetricValue {

	return model.AggregatedTimeMetricValue{}
}
