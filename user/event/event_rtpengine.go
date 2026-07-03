//go:build !androidgki
// +build !androidgki

package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"rtcagent/model"
	"rtcagent/outdata/hep"
	monotonic "rtcagent/user/time"
)

const (
	hepProtoRTP  byte = 34
	hepProtoRTCP byte = 36

	maxMediaDataSize = 1500
)

type RtpengineEvent struct {
	event_type EventType
	DataType   int64    `json:"dataType"`
	Timestamp  uint64   `json:"timestamp"`
	Pid        uint32   `json:"pid"`
	Tid        uint32   `json:"tid"`
	SrcIP      IpAddr
	DstIP      IpAddr
	SrcPort    uint16 `json:"srcPort"`
	DstPort    uint16 `json:"dstPort"`
	Data       [maxMediaDataSize]byte `json:"data"`
	DataLen    int32             `json:"dataLen"`
	Comm       [16]byte          `json:"Comm"`
}

func (ev *RtpengineEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)

	if err = binary.Read(buf, binary.LittleEndian, &ev.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.SrcIP); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.DstIP); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.SrcPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.DstPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ev.Comm); err != nil {
		return
	}

	return nil
}

func (ev *RtpengineEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d", ev.Pid, ev.Tid, CToGoString(ev.Comm[:]), ev.DataType)
}

func (ev *RtpengineEvent) Payload() []byte {
	if ev.DataLen <= 0 {
		return nil
	}
	return ev.Data[:ev.DataLen]
}

func (ev *RtpengineEvent) PayloadLen() int {
	return int(ev.DataLen)
}

func (ev *RtpengineEvent) StringHex() string {
	return ev.String()
}

func (ev *RtpengineEvent) String() string {
	srcIP := netIPFromAddr(ev.SrcIP)
	dstIP := netIPFromAddr(ev.DstIP)
	date := monotonic.GetRealTime(ev.Timestamp)

	var connInfo, prefix string
	switch AttachType(ev.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sReceived %d%s bytes from %s:%d%s", COLORGREEN, ev.DataLen, COLORRESET, srcIP, ev.SrcPort, COLORRESET)
		prefix = COLORGREEN
	case ProbeRet:
		connInfo = fmt.Sprintf("%sSent %d%s bytes to %s:%d%s", COLORPURPLE, ev.DataLen, COLORRESET, dstIP, ev.DstPort, COLORRESET)
		prefix = COLORPURPLE
	default:
		connInfo = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, ev.DataType, COLORRESET)
		prefix = COLORRED
	}

	return fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, TimeML: %d, RealTime: %s, SrcIP: %s, SrcPort: %d, DstIP: %s, DstPort: %d, Proto: %d, Payload:\n%s%s%s",
		ev.Pid, bytes.TrimSpace(ev.Comm[:]), ev.Tid, connInfo, ev.Timestamp, date.String(),
		srcIP, ev.SrcPort, dstIP, ev.DstPort, detectMediaProto(ev.Payload()), prefix, string(ev.Payload()), COLORRESET)
}

func (ev *RtpengineEvent) SendHep() bool {
	return true
}

func (ev *RtpengineEvent) GenerateHEP() ([]byte, error) {
	srcIP := netIPFromAddr(ev.SrcIP)
	dstIP := netIPFromAddr(ev.DstIP)
	ipVersion := hepIPVersion(ev.SrcIP)
	if srcIP == nil || len(srcIP) == 0 {
		ipVersion = hepIPVersion(ev.DstIP)
	}

	date := monotonic.GetRealTime(ev.Timestamp)
	tsec, tmsec := hepTimestampFields(date)

	hepPacket := hep.Packet{
		Version:   ipVersion,
		Protocol:  17,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   ev.SrcPort,
		DstPort:   ev.DstPort,
		Tsec:      tsec,
		Tmsec:     tmsec,
		ProtoType: detectMediaProto(ev.Payload()),
		Payload:   ev.Payload(),
	}

	return hep.EncodeHEP(&hepPacket)
}

func detectMediaProto(payload []byte) byte {
	if len(payload) < 2 {
		return hepProtoRTP
	}
	if payload[0]&0xC0 != 0x80 {
		return hepProtoRTP
	}
	pt := payload[1]
	if pt >= 192 && pt <= 211 {
		return hepProtoRTCP
	}
	return hepProtoRTP
}

func (ev *RtpengineEvent) Clone() IEventStruct {
	event := new(RtpengineEvent)
	event.event_type = EventTypeEventProcessor
	return event
}

func (ev *RtpengineEvent) EventType() EventType {
	return ev.event_type
}

func (ev *RtpengineEvent) DoCorrelation(userFunctionArray []string) bool {
	return false
}

func (ev *RtpengineEvent) GenerateMetric() model.AggregatedMetricValue {
	return model.AggregatedMetricValue{}
}

func (ev *RtpengineEvent) GenerateTimeMetric() model.AggregatedTimeMetricValue {
	return model.AggregatedTimeMetricValue{}
}
