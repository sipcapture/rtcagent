//go:build !androidgki
// +build !androidgki

package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"rtcagent/model"
)

type TcprttEvent struct {
	Sport  uint16
	Dport  uint16
	Family uint8
	Pad    [3]byte
	SRTT   uint32
	Saddr  uint32
	Daddr  uint32
	Saddr6 [16]byte
	Daddr6 [16]byte
}

func (tcpev *TcprttEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	return binary.Read(buf, binary.LittleEndian, tcpev)
}

func (tcpev *TcprttEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d", tcpev.Sport, tcpev.Dport)
}

func (tcpev *TcprttEvent) Payload() []byte {
	return nil
}

func (tcpev *TcprttEvent) PayloadLen() int {
	return 0
}

func (tcpev *TcprttEvent) StringHex() string {
	return tcpev.String()
}

func be32ToIPv4(ipNum uint32) net.IP {
	if ipNum == 0 {
		return nil
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func (tcpev *TcprttEvent) srcIP() net.IP {
	if tcpev.Family == afINET6 {
		return net.IP(tcpev.Saddr6[:])
	}
	return be32ToIPv4(tcpev.Saddr)
}

func (tcpev *TcprttEvent) dstIP() net.IP {
	if tcpev.Family == afINET6 {
		return net.IP(tcpev.Daddr6[:])
	}
	return be32ToIPv4(tcpev.Daddr)
}

func (tcpev *TcprttEvent) String() string {
	srcIP := tcpev.srcIP()
	dstIP := tcpev.dstIP()
	prefix := COLORGREEN

	return fmt.Sprintf("%s%-39s %-6d -> %-39s %-6d %-6dms%s",
		prefix, srcIP, tcpev.Sport, dstIP, tcpev.Dport, tcpev.SRTT, COLORRESET)
}

func (tcpev *TcprttEvent) SendHep() bool {
	return false
}

func (tcpev *TcprttEvent) GenerateHEP() ([]byte, error) {
	return nil, fmt.Errorf("no data")
}

func (tcpev *TcprttEvent) Clone() IEventStruct {
	return new(TcprttEvent)
}

func (tcpev *TcprttEvent) EventType() EventType {
	return EventTypeOutput
}

func (tcpev *TcprttEvent) DoCorrelation(userFunctionArray []string) bool {
	return false
}

func (tcpev *TcprttEvent) GenerateMetric() model.AggregatedMetricValue {
	return model.AggregatedMetricValue{}
}

func (tcpev *TcprttEvent) GenerateTimeMetric() model.AggregatedTimeMetricValue {
	return model.AggregatedTimeMetricValue{}
}
