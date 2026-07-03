//go:build !androidgki
// +build !androidgki

package event

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestTcprttEventDecodeIPv4(t *testing.T) {
	ev := &TcprttEvent{}
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint16(5060))
	binary.Write(buf, binary.LittleEndian, uint16(5070))
	binary.Write(buf, binary.LittleEndian, uint8(afINET))
	buf.Write([]byte{0, 0, 0})
	binary.Write(buf, binary.LittleEndian, uint32(12))
	binary.Write(buf, binary.LittleEndian, uint32(0x0A000001))
	binary.Write(buf, binary.LittleEndian, uint32(0x0A000002))
	buf.Write(make([]byte, 32))

	if err := ev.Decode(buf.Bytes()); err != nil {
		t.Fatalf("decode tcprtt event: %v", err)
	}
	if got, want := ev.srcIP().String(), "10.0.0.1"; got != want {
		t.Fatalf("unexpected src ip: got %s want %s", got, want)
	}
	if got, want := ev.dstIP().String(), "10.0.0.2"; got != want {
		t.Fatalf("unexpected dst ip: got %s want %s", got, want)
	}
	if ev.SRTT != 12 {
		t.Fatalf("unexpected srtt: %d", ev.SRTT)
	}
}

func TestTcprttEventDecodeIPv6(t *testing.T) {
	want := net.ParseIP("2001:db8::1")
	ev := &TcprttEvent{}
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint16(5060))
	binary.Write(buf, binary.LittleEndian, uint16(5070))
	binary.Write(buf, binary.LittleEndian, uint8(afINET6))
	buf.Write([]byte{0, 0, 0})
	binary.Write(buf, binary.LittleEndian, uint32(25))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	var addr [16]byte
	copy(addr[:], want.To16())
	buf.Write(addr[:])
	buf.Write(make([]byte, 16))

	if err := ev.Decode(buf.Bytes()); err != nil {
		t.Fatalf("decode tcprtt ipv6 event: %v", err)
	}
	if !ev.srcIP().Equal(want) {
		t.Fatalf("unexpected src ip: got %s want %s", ev.srcIP(), want)
	}
}

func TestDetectMediaProto(t *testing.T) {
	rtp := []byte{0x80, 0x00}
	if detectMediaProto(rtp) != hepProtoRTP {
		t.Fatalf("expected RTP proto")
	}
	rtcp := []byte{0x80, 0xC8}
	if detectMediaProto(rtcp) != hepProtoRTCP {
		t.Fatalf("expected RTCP proto")
	}
}
