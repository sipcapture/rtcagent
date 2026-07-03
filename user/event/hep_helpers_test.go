//go:build !androidgki
// +build !androidgki

package event

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestHepTimestampFieldsUsesMicroseconds(t *testing.T) {
	ts := time.Date(2024, 8, 19, 6, 50, 4, 199206453, time.UTC)
	tsec, tmsec := hepTimestampFields(ts)

	if tsec != uint32(ts.Unix()) {
		t.Fatalf("unexpected tsec: got %d want %d", tsec, ts.Unix())
	}
	if tmsec != 199206 {
		t.Fatalf("unexpected tmsec: got %d want 199206", tmsec)
	}
}

func TestNetIPFromAddrIPv6(t *testing.T) {
	want := net.ParseIP("2001:db8::1")
	addr := IpAddr{
		Af:  afINET6,
		Len: 16,
	}
	copy(addr.Addr[:], want)

	got := netIPFromAddr(addr)
	if !got.Equal(want) {
		t.Fatalf("unexpected IPv6: got %s want %s", got, want)
	}
	if hepIPVersion(addr) != hepFamilyIPv6 {
		t.Fatalf("unexpected hep version: got %#x want %#x", hepIPVersion(addr), hepFamilyIPv6)
	}
}

func TestKamailioGenerateHEPIPv6(t *testing.T) {
	ev := &KamailioEvent{
		DataLen: int32(len("SIP/2.0 200 OK")),
	}
	copy(ev.Data[:], "SIP/2.0 200 OK")

	src := net.ParseIP("2001:db8:944::44e6:a8fd:0:453c")
	dst := net.ParseIP("2001:db8:4a43:d692:287f:e154::318f")

	var rcinfo ReceiveInfo
	rcinfo.SrcIP.Af = afINET6
	rcinfo.SrcIP.Len = 16
	copy(rcinfo.SrcIP.Addr[:], src.To16())
	rcinfo.DstIP.Af = afINET6
	rcinfo.DstIP.Len = 16
	copy(rcinfo.DstIP.Addr[:], dst.To16())
	rcinfo.SrcPort = 6060
	rcinfo.DstPort = 49512

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.LittleEndian, &rcinfo); err != nil {
		t.Fatalf("write rcinfo: %v", err)
	}
	copy(ev.RcInfo[:], buf.Bytes())

	ev.Timestamp = 1445124394701952

	raw, err := ev.GenerateHEP()
	if err != nil {
		t.Fatalf("generate hep: %v", err)
	}

	if len(raw) < 6 || string(raw[:4]) != "HEP3" {
		t.Fatalf("unexpected hep header: %q", raw[:6])
	}

	// First chunk after the HEP3 header is the IP family (0x0001).
	if raw[12] != hepFamilyIPv6 {
		t.Fatalf("expected IPv6 hep family %#x, got %#x", hepFamilyIPv6, raw[12])
	}

	chunk5 := []byte{0x00, 0x00, 0x00, 0x05}
	if !bytes.Contains(raw, chunk5) {
		t.Fatalf("expected IPv6 source chunk 0x0005 in hep packet")
	}
}
