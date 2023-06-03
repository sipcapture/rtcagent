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

package event_processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"rtcagent/user/event"
)

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const ChunkSize = 16
const ChunkSizeHalf = ChunkSize / 2

const MaxDataSize = 1024 * 4
const SaDataLen = 14

const (
	Ssl2Version   = 0x0002
	Ssl3Version   = 0x0300
	Tls1Version   = 0x0301
	Tls11Version  = 0x0302
	Tls12Version  = 0x0303
	Tls13Version  = 0x0304
	Dtls1Version  = 0xFEFF
	Dtls12Version = 0xFEFD
)

type tls_version struct {
	version int32
}

func (t tls_version) String() string {
	switch t.version {
	case Ssl2Version:
		return "SSL2_VERSION"
	case Ssl3Version:
		return "SSL3_VERSION"
	case Tls1Version:
		return "TLS1_VERSION"
	case Tls11Version:
		return "TLS1_1_VERSION"
	case Tls12Version:
		return "TLS1_2_VERSION"
	case Tls13Version:
		return "TLS1_3_VERSION"
	case Dtls1Version:
		return "DTLS1_VERSION"
	case Dtls12Version:
		return "DTLS1_2_VERSION"
	}
	return fmt.Sprintf("TLS_VERSION_UNKNOW_%d", t.version)
}

type BaseEvent struct {
	event_type event.EventType
	DataType   int64
	Timestamp  uint64
	Pid        uint32
	Tid        uint32
	Data       [MaxDataSize]byte
	Data_len   int32
	Comm       [16]byte
	Fd         uint32
	Version    int32
}

func (be *BaseEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &be.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Data_len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Version); err != nil {
		return
	}

	return nil
}

func (be *BaseEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", be.Pid, be.Tid, CToGoString(be.Comm[:]), be.Fd, be.DataType)
}

func (be *BaseEvent) Payload() []byte {
	return be.Data[:be.Data_len]
}

func (be *BaseEvent) PayloadLen() int {
	return int(be.Data_len)
}

func (be *BaseEvent) StringHex() string {

	var perfix, connInfo string
	switch AttachType(be.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("Received %d bytes", be.Data_len)
	case ProbeRet:
		connInfo = fmt.Sprintf("Send %d bytes", be.Data_len)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", be.DataType)
	}

	b := dumpByteSlice(be.Data[:be.Data_len], perfix)

	v := tls_version{version: be.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Payload:\n%s", be.Pid, CToGoString(be.Comm[:]), be.Tid, connInfo, v.String(), b.String())
	return s
}

func (be *BaseEvent) SendHep() bool {

	return false
}

func (be *BaseEvent) String() string {

	var connInfo string
	switch AttachType(be.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("Received %dbytes", be.Data_len)
	case ProbeRet:
		connInfo = fmt.Sprintf("Send %d bytes", be.Data_len)
	default:
		connInfo = fmt.Sprintf("UNKNOW_%d", be.DataType)
	}
	v := tls_version{version: be.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, Version:%s, %s, Payload:\n%s", be.Pid, bytes.TrimSpace(be.Comm[:]), be.Tid, v.String(), connInfo, string(be.Data[:be.Data_len]))
	return s
}

func (be *BaseEvent) Clone() event.IEventStruct {
	e := new(BaseEvent)
	e.event_type = event.EventTypeOutput
	return e
}

func (be *BaseEvent) GenerateHEP() ([]byte, error) {

	return nil, fmt.Errorf("not implemented")
}

func (be *BaseEvent) EventType() event.EventType {
	return be.event_type
}

func CToGoString(c []byte) string {
	n := -1
	for i, b := range c {
		if b == 0 {
			break
		}
		n = i
	}
	return string(c[:n+1])
}

func dumpByteSlice(b []byte, perfix string) *bytes.Buffer {
	var a [ChunkSize]byte
	bb := new(bytes.Buffer)
	n := (len(b) + (ChunkSize - 1)) &^ (ChunkSize - 1)

	for i := 0; i < n; i++ {

		if i%ChunkSize == 0 {
			bb.WriteString(perfix)
			bb.WriteString(fmt.Sprintf("%04d", i))
		}

		if i%ChunkSizeHalf == 0 {
			bb.WriteString("    ")
		} else if i%(ChunkSizeHalf/2) == 0 {
			bb.WriteString("  ")
		}

		if i < len(b) {
			bb.WriteString(fmt.Sprintf(" %02X", b[i]))
		} else {
			bb.WriteString("  ")
		}

		if i >= len(b) {
			a[i%ChunkSize] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%ChunkSize] = '.'
		} else {
			a[i%ChunkSize] = b[i]
		}

		if i%ChunkSize == (ChunkSize - 1) {
			bb.WriteString(fmt.Sprintf("    %s\n", string(a[:])))
		}
	}
	return bb
}
