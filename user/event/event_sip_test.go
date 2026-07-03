//go:build !androidgki
// +build !androidgki

package event

import (
	"encoding/binary"
	"testing"
)

const sipEventPayloadSize = 4192

func buildSipEventPayload(t *testing.T, dataType int32, payload string) []byte {
	t.Helper()

	buf := make([]byte, sipEventPayloadSize)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(dataType))
	binary.LittleEndian.PutUint64(buf[8:16], 123456789)
	binary.LittleEndian.PutUint32(buf[16:20], 42)
	binary.LittleEndian.PutUint32(buf[20:24], 43)
	binary.LittleEndian.PutUint16(buf[48:50], 5060)
	binary.LittleEndian.PutUint16(buf[50:52], 5070)

	dataOffset := 76
	copy(buf[dataOffset:], payload)
	binary.LittleEndian.PutUint32(buf[4172:4176], uint32(len(payload)))
	copy(buf[4176:4192], []byte("kamailio\x00\x00\x00\x00\x00\x00\x00"))
	return buf
}

func TestKamailioEventDecodeMatchesKernelLayout(t *testing.T) {
	ev := &KamailioEvent{}
	payload := "INVITE sip:test@example.com SIP/2.0"
	if err := ev.Decode(buildSipEventPayload(t, 0, payload)); err != nil {
		t.Fatalf("decode kamailio event: %v", err)
	}
	if ev.Pid != 42 || ev.Tid != 43 {
		t.Fatalf("unexpected pid/tid: %d/%d", ev.Pid, ev.Tid)
	}
	if ev.DataLen != int32(len(payload)) {
		t.Fatalf("unexpected data len: %d", ev.DataLen)
	}
	if string(ev.Payload()) != payload {
		t.Fatalf("unexpected payload: %q", string(ev.Payload()))
	}
}

func TestOpensipsEventDecodeMatchesKernelLayout(t *testing.T) {
	ev := &OpensipsEvent{}
	if err := ev.Decode(buildSipEventPayload(t, 1, "REGISTER sip:example.com SIP/2.0")); err != nil {
		t.Fatalf("decode opensips event: %v", err)
	}
	if ev.DataType != 1 {
		t.Fatalf("unexpected data type: %d", ev.DataType)
	}
	if string(ev.Payload()) != "REGISTER sip:example.com SIP/2.0" {
		t.Fatalf("unexpected payload: %q", string(ev.Payload()))
	}
}

func TestSipEventPayloadSize(t *testing.T) {
	if sipEventPayloadSize != 4192 {
		t.Fatalf("expected sip event payload size 4192, got %d", sipEventPayloadSize)
	}
}
