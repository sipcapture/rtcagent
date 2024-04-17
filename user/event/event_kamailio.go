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
	"rtcagent/outdata/hep"
	monotonic "rtcagent/user/time"
)

const MaxDataSize = 1024 * 4

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const (
	//dispatch_command_return
	DispatchCommandV5Failed        = -2
	DispatchCommandNotCaptured     = -1
	DispatchCommandSuccess         = 0
	DispatchCommandCloseConnection = 1
	DispatchCommandWouldblock      = 2
)

type dispatch_command_return int8

func (dcr dispatch_command_return) String() string {
	var retStr string
	switch dcr {
	case DispatchCommandCloseConnection:
		retStr = "DISPATCH_COMMAND_CLOSE_CONNECTION"
	case DispatchCommandSuccess:
		retStr = "DISPATCH_COMMAND_SUCCESS"
	case DispatchCommandWouldblock:
		retStr = "DISPATCH_COMMAND_WOULDBLOCK"
	case DispatchCommandNotCaptured:
		retStr = "DISPATCH_COMMAND_NOT_CAPTURED"
	case DispatchCommandV5Failed:
		retStr = "DISPATCH_COMMAND_V5_FAILED"
	}
	return retStr
}

type IpAddr struct {
	//4
	Af uint32
	////4
	Len uint32
	//16
	Addr [16]byte
}

type ReceiveInfo struct {
	SrcIP   IpAddr
	DstIP   IpAddr
	SrcPort uint16 `json:"srcPort"`
	DstPort uint16 `json:"dstPort"`
}

type KamailioEvent struct {
	event_type EventType
	DataType   int64    `json:"dataType"`
	Timestamp  uint64   `json:"timestamp"`
	Pid        uint32   `json:"pid"`
	Tid        uint32   `json:"tid"`
	RcInfo     [56]byte `json:"rcinfo"`
	//RcInfo  ReceiveInfo       `json:"rcinfo"`
	Data    [MaxDataSize]byte `json:"data"`
	DataLen int32             `json:"dataLen"`
	Comm    [16]byte          `json:"Comm"`
	Fd      uint32            `json:"fd"`
	Version int32             `json:"version"`
}

func (kem *KamailioEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)

	if err = binary.Read(buf, binary.LittleEndian, &kem.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.RcInfo); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.DataLen); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &kem.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.Version); err != nil {
		return
	}

	return nil
}

func (kem *KamailioEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", kem.Pid, kem.Tid, CToGoString(kem.Comm[:]), kem.Fd, kem.DataType)
}

func (kem *KamailioEvent) Payload() []byte {
	return kem.Data[:kem.DataLen]
}

func (kem *KamailioEvent) PayloadLen() int {
	return int(kem.DataLen)
}

func (kem *KamailioEvent) StringHex() string {
	//addr := kem.module.(*module.MOpenSSLProbe).GetConn(kem.Pid, kem.Fd)
	addr := "[TODO]"
	var perfix, connInfo string
	switch AttachType(kem.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sReceived %d%s bytes from %s%s%s", COLORGREEN, kem.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, kem.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", kem.DataType)
	}

	b := dumpByteSlice(kem.Data[:kem.DataLen], perfix)
	b.WriteString(COLORRESET)
	v := "V"
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Mask: %d, Payload:\n%s", kem.Pid, CToGoString(kem.Comm[:]),
		kem.Tid, connInfo, v, 1, b.String())
	//s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, SrcPort: %d, DstPort:%d, SrcIPv6: %d, DstIPv6: %d, Payload:\n%s", kem.Pid, CToGoString(kem.Comm[:]),
	//	kem.Tid, connInfo, v.String(), kem.RcInfo.SrcPort, kem.RcInfo.DstPort, 1, 1, b.String())
	return s
}

func (kem *KamailioEvent) String() string {
	//addr := kem.module.(*module.MOpenSSLProbe).GetConn(kem.Pid, kem.Fd)

	buf := bytes.NewBuffer(kem.RcInfo[:])
	t := ReceiveInfo{}
	err := binary.Read(buf, binary.LittleEndian, &t)
	if err != nil {
		panic(err)
	}

	srcIP := net.IP(t.SrcIP.Addr[:4])
	dstIP := net.IP(t.DstIP.Addr[:4])
	addr := fmt.Sprintf("%s:%d", srcIP.String(), t.SrcPort)

	date := monotonic.GetRealTime(kem.Timestamp)

	var perfix, connInfo string
	switch AttachType(kem.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sReceived %d%s bytes from %s%s%s", COLORGREEN, kem.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, kem.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORPURPLE
	default:
		connInfo = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, kem.DataType, COLORRESET)
	}

	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, TimeML: %d, RealTime: %s, SrcIP: %s, SrcPort: %d, DstIP: %s, DstPort: %d, Payload:\n%s%s%s", kem.Pid, bytes.TrimSpace(kem.Comm[:]), kem.Tid, connInfo,
		kem.Timestamp, date.String(),
		srcIP.String(), t.SrcPort, dstIP.String(), t.DstPort, perfix, string(kem.Data[:kem.DataLen]), COLORRESET)

	//s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, SrcPort: %d, DstPort:%d, SrcIPv6: %d, Mask: %d, Payload:\n%s%s%s", kem.Pid, bytes.TrimSpace(kem.Comm[:]), kem.Tid, connInfo,
	//	this.RcInfo.SrcPort, this.RcInfo.DstPort, 1, this.Mask, perfix, string(this.Data[:this.DataLen]), COLORRESET)
	return s
}

func (kem *KamailioEvent) SendHep() bool {
	//Lets allow to send HEP
	return true
}

func (kem *KamailioEvent) GenerateHEP() ([]byte, error) {

	buf := bytes.NewBuffer(kem.RcInfo[:])
	t := ReceiveInfo{}
	err := binary.Read(buf, binary.LittleEndian, &t)
	if err != nil {
		panic(err)
	}

	srcIP := net.IP(t.SrcIP.Addr[:4])
	dstIP := net.IP(t.DstIP.Addr[:4])

	date := monotonic.GetRealTime(kem.Timestamp)

	hepPacket := hep.Packet{
		Version:   0x02,
		Protocol:  22,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   t.SrcPort,
		DstPort:   t.DstPort,
		Tsec:      uint32(date.Unix()),
		Tmsec:     uint32(date.UnixMilli() - (date.Unix() * 1000)),
		ProtoType: 1,
		Payload:   kem.Data[:kem.DataLen],
	}

	return hep.EncodeHEP(&hepPacket)

}

func (kem *KamailioEvent) Clone() IEventStruct {
	event := new(KamailioEvent)
	event.event_type = EventTypeEventProcessor
	return event
}

func (kem *KamailioEvent) EventType() EventType {
	return kem.event_type
}

func (kem *KamailioEvent) DoCorrelation(userFunctionArray []string) bool {
	return false
}

func (kem *KamailioEvent) GenerateMetric() model.AggregatedMetricValue {
	//Lets allow to send HEP

	return model.AggregatedMetricValue{}
}

func (kem *KamailioEvent) GenerateTimeMetric() model.AggregatedTimeMetricValue {

	return model.AggregatedTimeMetricValue{}
}
