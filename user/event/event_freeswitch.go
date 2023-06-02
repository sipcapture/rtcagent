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
	"rtcagent/outdata/hep"
	"time"
)

type IpAddrFS struct {
	Addr [16]byte
}

type ReceiveFreewSwitchInfo struct {
	Port uint16
	IP   IpAddrFS
}

type FreeSwitchEvent struct {
	event_type EventType
	DataType   int64             `json:"dataType"`
	Timestamp  uint64            `json:"timestamp"`
	Pid        uint32            `json:"pid"`
	Tid        uint32            `json:"tid"`
	DstInfo    [20]byte          `json:"dstinfo"`
	SrcInfo    [20]byte          `json:"srcinfo"`
	Data       [MaxDataSize]byte `json:"data"`
	DataLen    int32             `json:"dataLen"`
	Comm       [16]byte          `json:"Comm"`
	Fd         uint32            `json:"fd"`
	Version    int32             `json:"version"`
}

func (kem *FreeSwitchEvent) Decode(payload []byte) (err error) {
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
	if err = binary.Read(buf, binary.LittleEndian, &kem.DstInfo); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &kem.SrcInfo); err != nil {
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

func (kem *FreeSwitchEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", kem.Pid, kem.Tid, CToGoString(kem.Comm[:]), kem.Fd, kem.DataType)
}

func (kem *FreeSwitchEvent) Payload() []byte {
	return kem.Data[:kem.DataLen]
}

func (kem *FreeSwitchEvent) PayloadLen() int {
	return int(kem.DataLen)
}

func (kem *FreeSwitchEvent) StringHex() string {
	//addr := kem.module.(*module.MOpenSSLProbe).GetConn(kem.Pid, kem.Fd)
	addr := "[TODO]"
	var perfix, connInfo string
	switch AttachType(kem.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sRecived %d%s bytes from %s%s%s", COLORGREEN, kem.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
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
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Mask: %d, Payload:\n%s \n Byte: %v", kem.Pid, CToGoString(kem.Comm[:]),
		kem.Tid, connInfo, v, 1, b.String(), b)
	return s
}

func (kem *FreeSwitchEvent) String() string {
	//addr := kem.module.(*module.MOpenSSLProbe).GetConn(kem.Pid, kem.Fd)

	buf := bytes.NewBuffer(kem.DstInfo[:])
	dst := ReceiveFreewSwitchInfo{}
	err := binary.Read(buf, binary.BigEndian, &dst)
	if err != nil {
		panic(err)
	}

	srcIP := net.IP(dst.IP.Addr[:4]).String()
	dstIP := net.IP(dst.IP.Addr[:4]).String()
	dstPort := dst.Port
	srcPort := 5060
	if dstPort == 0 {
		dstPort = uint16(srcPort)
		srcIP = "192.168.178.68"
		dstIP = "192.168.178.68"
	}
	addr := fmt.Sprintf("%s:%d", srcIP, srcPort)
	var perfix, connInfo string
	switch AttachType(kem.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sRecived %d%s bytes from %s%s%s", COLORGREEN, kem.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, kem.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORPURPLE
	default:
		connInfo = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, kem.DataType, COLORRESET)
	}

	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Time:%d, SrcIP: %s, SrcPort: %d, DstIP: %s, DstPort: %d, Payload:\n%s%s, \n%s", kem.Pid, bytes.TrimSpace(kem.Comm[:]), kem.Tid, connInfo,
		kem.Timestamp, srcIP, srcPort, dstIP, dstPort, perfix, string(kem.Data[:kem.DataLen]), COLORRESET)

	return s
}

func (kem *FreeSwitchEvent) SendHep() bool {
	//Lets allow to send HEP
	return true
}

func (kem *FreeSwitchEvent) GenerateHEP() ([]byte, error) {

	buf := bytes.NewBuffer(kem.DstInfo[:])
	dst := ReceiveFreewSwitchInfo{}
	err := binary.Read(buf, binary.BigEndian, &dst)
	if err != nil {
		panic(err)
	}

	srcIP := net.IP(dst.IP.Addr[:4])
	dstIP := net.IP(dst.IP.Addr[:4])

	var date time.Time

	hepPacket := hep.Packet{
		Version:   0x02,
		Protocol:  17,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   dst.Port,
		DstPort:   dst.Port,
		Tsec:      uint32(date.Unix()),
		Tmsec:     uint32(date.UnixMilli() - (date.Unix() * 1000)),
		ProtoType: 1,
		Payload:   kem.Data[:kem.DataLen],
	}

	return hep.EncodeHEP(&hepPacket)

}

func (kem *FreeSwitchEvent) Clone() IEventStruct {
	event := new(FreeSwitchEvent)
	event.event_type = EventTypeEventProcessor
	return event
}

func (kem *FreeSwitchEvent) EventType() EventType {
	return kem.event_type
}
