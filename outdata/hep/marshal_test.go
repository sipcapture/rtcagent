package hep

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// hepChunk is one decoded HEP chunk.
type hepChunk struct {
	vendor uint16
	typ    uint16
	value  []byte
}

// parseHEP decodes a HEP message into its chunks, validating the framing.
func parseHEP(t *testing.T, msg []byte) map[uint16]hepChunk {
	t.Helper()

	if len(msg) < 6 {
		t.Fatalf("message too short: %d bytes", len(msg))
	}
	if string(msg[:4]) != "HEP3" {
		t.Fatalf("bad magic: %q", msg[:4])
	}
	if got := int(binary.BigEndian.Uint16(msg[4:6])); got != len(msg) {
		t.Fatalf("length field %d does not match message size %d", got, len(msg))
	}

	chunks := make(map[uint16]hepChunk)
	offset := 6
	for offset < len(msg) {
		if offset+6 > len(msg) {
			t.Fatalf("truncated chunk header at offset %d", offset)
		}
		vendor := binary.BigEndian.Uint16(msg[offset:])
		typ := binary.BigEndian.Uint16(msg[offset+2:])
		length := int(binary.BigEndian.Uint16(msg[offset+4:]))
		if length < 6 || offset+length > len(msg) {
			t.Fatalf("invalid chunk length %d at offset %d", length, offset)
		}
		chunks[typ] = hepChunk{vendor: vendor, typ: typ, value: msg[offset+6 : offset+length]}
		offset += length
	}
	if offset != len(msg) {
		t.Fatalf("chunks do not fill the message: offset=%d len=%d", offset, len(msg))
	}
	return chunks
}

func TestEncodeHEPIPv4(t *testing.T) {
	pkt := &Packet{
		Version:   0x02,
		Protocol:  0x11, // UDP
		SrcIP:     net.ParseIP("10.0.0.1").To4(),
		DstIP:     net.ParseIP("10.0.0.2").To4(),
		SrcPort:   5060,
		DstPort:   5061,
		Tsec:      1700000000,
		Tmsec:     123456,
		ProtoType: 1, // SIP
		Payload:   []byte("INVITE sip:x SIP/2.0"),
		CID:       []byte("correlation-id"),
		Vlan:      100,
	}

	msg, err := EncodeHEP(pkt)
	if err != nil {
		t.Fatalf("EncodeHEP: %v", err)
	}

	chunks := parseHEP(t, msg)

	want := map[uint16][]byte{
		Version:   {0x02},
		Protocol:  {0x11},
		IP4SrcIP:  net.ParseIP("10.0.0.1").To4(),
		IP4DstIP:  net.ParseIP("10.0.0.2").To4(),
		SrcPort:   {0x13, 0xc4}, // 5060
		DstPort:   {0x13, 0xc5}, // 5061
		ProtoType: {0x01},       // SIP
		Payload:   []byte("INVITE sip:x SIP/2.0"),
		CID:       []byte("correlation-id"),
		Vlan:      {0x00, 0x64}, // 100
	}

	for typ, value := range want {
		got, ok := chunks[typ]
		if !ok {
			t.Errorf("missing chunk 0x%04x", typ)
			continue
		}
		if got.vendor != 0 {
			t.Errorf("chunk 0x%04x: unexpected vendor %d", typ, got.vendor)
		}
		if !bytes.Equal(got.value, value) {
			t.Errorf("chunk 0x%04x: got %x, want %x", typ, got.value, value)
		}
	}

	// Timestamps.
	if got := binary.BigEndian.Uint32(chunks[Tsec].value); got != pkt.Tsec {
		t.Errorf("Tsec: got %d, want %d", got, pkt.Tsec)
	}
	if got := binary.BigEndian.Uint32(chunks[Tmsec].value); got != pkt.Tmsec {
		t.Errorf("Tmsec: got %d, want %d", got, pkt.Tmsec)
	}
	// EncodeHEP always stamps its node id and password.
	if got := binary.BigEndian.Uint32(chunks[NodeID].value); got != 999 {
		t.Errorf("NodeID: got %d, want 999", got)
	}
	if got := string(chunks[NodePW].value); got != "empty" {
		t.Errorf("NodePW: got %q, want %q", got, "empty")
	}
	if _, ok := chunks[NodeName]; ok {
		t.Error("empty NodeName must not be encoded")
	}
}

func TestEncodeHEPIPv6UsesIPv6Chunks(t *testing.T) {
	pkt := &Packet{
		Version:  0x0a, // IPv6
		Protocol: 0x11,
		SrcIP:    net.ParseIP("2001:db8::1"),
		DstIP:    net.ParseIP("2001:db8::2"),
		Payload:  []byte("x"),
	}

	msg, err := EncodeHEP(pkt)
	if err != nil {
		t.Fatalf("EncodeHEP: %v", err)
	}
	chunks := parseHEP(t, msg)

	if _, ok := chunks[IP6SrcIP]; !ok {
		t.Error("missing IPv6 source chunk")
	}
	if _, ok := chunks[IP6DstIP]; !ok {
		t.Error("missing IPv6 destination chunk")
	}
	if _, ok := chunks[IP4SrcIP]; ok {
		t.Error("IPv4 source chunk must not be present for an IPv6 packet")
	}
	if _, ok := chunks[IP4DstIP]; ok {
		t.Error("IPv4 destination chunk must not be present for an IPv6 packet")
	}
}

func TestEncodeHEPOmitsEmptyOptionalChunks(t *testing.T) {
	pkt := &Packet{Version: 0x02, Protocol: 0x11}

	msg, err := EncodeHEP(pkt)
	if err != nil {
		t.Fatalf("EncodeHEP: %v", err)
	}
	chunks := parseHEP(t, msg)

	for _, typ := range []uint16{IP4SrcIP, IP4DstIP, Payload, CID} {
		if _, ok := chunks[typ]; ok {
			t.Errorf("chunk 0x%04x must be omitted when its value is empty", typ)
		}
	}
}
