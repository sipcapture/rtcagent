package event

import (
	"net"
	"time"

	"rtcagent/outdata/hep"
)

const (
	afINET  = 2
	afINET6 = 10

	hepFamilyIPv4 = 0x02
	hepFamilyIPv6 = 0x0a
)

func netIPFromAddr(addr IpAddr) net.IP {
	if addr.Len == 16 || addr.Af == afINET6 {
		return net.IP(addr.Addr[:16])
	}
	return net.IP(addr.Addr[:4])
}

func hepIPVersion(addr IpAddr) byte {
	if addr.Len == 16 || addr.Af == afINET6 {
		return hepFamilyIPv6
	}
	return hepFamilyIPv4
}

func hepTimestampFields(t time.Time) (uint32, uint32) {
	return uint32(t.Unix()), uint32(t.Nanosecond() / 1000)
}

func buildSipHepPacket(ipVersion byte, protocol byte, src, dst net.IP, srcPort, dstPort uint16, t time.Time, payload []byte) hep.Packet {
	tsec, tmsec := hepTimestampFields(t)
	return hep.Packet{
		Version:   ipVersion,
		Protocol:  protocol,
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Tsec:      tsec,
		Tmsec:     tmsec,
		ProtoType: 1,
		Payload:   payload,
	}
}
