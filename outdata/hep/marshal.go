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

package hep

import (
	"encoding/binary"
	"fmt"
	"net"
	strings "strings"
	"unsafe"
)

// HEP chuncks
const (
	Version   = 1  // Chunk 0x0001 IP protocol family (0x02=IPv4, 0x0a=IPv6)
	Protocol  = 2  // Chunk 0x0002 IP protocol ID (0x06=TCP, 0x11=UDP)
	IP4SrcIP  = 3  // Chunk 0x0003 IPv4 source address
	IP4DstIP  = 4  // Chunk 0x0004 IPv4 destination address
	IP6SrcIP  = 5  // Chunk 0x0005 IPv6 source address
	IP6DstIP  = 6  // Chunk 0x0006 IPv6 destination address
	SrcPort   = 7  // Chunk 0x0007 Protocol source port
	DstPort   = 8  // Chunk 0x0008 Protocol destination port
	Tsec      = 9  // Chunk 0x0009 Unix timestamp, seconds
	Tmsec     = 10 // Chunk 0x000a Unix timestamp, microseconds
	ProtoType = 11 // Chunk 0x000b Protocol type (DNS, LOG, RTCP, SIP)
	NodeID    = 12 // Chunk 0x000c Capture client ID
	NodePW    = 14 // Chunk 0x000e Authentication key (plain text / TLS connection)
	Payload   = 15 // Chunk 0x000f Captured packet payload
	CID       = 17 // Chunk 0x0011 Correlation ID
	Vlan      = 18 // Chunk 0x0012 VLAN
	NodeName  = 19 // Chunk 0x0013 NodeName
)

// HepMsg represents a parsed HEP packet
type HepMsg struct {
	Version   byte
	Protocol  byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Tsec      uint32
	Tmsec     uint32
	ProtoType byte
	NodeID    uint32
	NodePW    string
	Payload   []byte
	CID       []byte
	Vlan      uint16
	NodeName  string
}

type Packet struct {
	Version   byte
	Protocol  byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Tsec      uint32
	Tmsec     uint32
	ProtoType byte
	Payload   []byte
	CID       []byte
	Vlan      uint16
	// date
	dateString string
}

// EncodeHEP creates the HEP Packet which
// will be send to wire
func EncodeHEP(h *Packet) (hepMsg []byte, err error) {

	hep := &HepMsg{
		Version:   h.Version,
		Protocol:  h.Protocol,
		SrcIP:     h.SrcIP,
		DstIP:     h.DstIP,
		SrcPort:   h.SrcPort,
		DstPort:   h.DstPort,
		Tsec:      h.Tsec,
		Tmsec:     h.Tmsec,
		ProtoType: h.ProtoType,
		NodeID:    uint32(999),
		NodePW:    "empty",
		Payload:   h.Payload,
		CID:       h.CID,
		Vlan:      h.Vlan,
	}

	hepMsg, err = hep.Marshal()
	return hepMsg, err
}

func (h *HepMsg) Marshal() (dAtA []byte, err error) {
	size := h.Size()
	dAtA = make([]byte, size)
	n, err := h.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (h *HepMsg) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i

	i += copy(dAtA[i:], []byte{0x48, 0x45, 0x50, 0x33})
	binary.BigEndian.PutUint16(dAtA[i:], uint16(len(dAtA)))
	i += 2

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x07})
	dAtA[i] = h.Version
	i++

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x07})
	dAtA[i] = h.Protocol
	i++

	if h.Version == 0x02 {
		if h.SrcIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x03})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.SrcIP)))
			i += 2
			i += copy(dAtA[i:], h.SrcIP)
		}

		if h.DstIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x04})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.DstIP)))
			i += 2
			i += copy(dAtA[i:], h.DstIP)
		}
	} else {
		if h.SrcIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x05})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.SrcIP)))
			i += 2
			i += copy(dAtA[i:], h.SrcIP)
		}

		if h.DstIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x06})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.DstIP)))
			i += 2
			i += copy(dAtA[i:], h.DstIP)
		}
	}

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x07, 0x00, 0x08})
	binary.BigEndian.PutUint16(dAtA[i:], h.SrcPort)
	i += 2

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x08})
	binary.BigEndian.PutUint16(dAtA[i:], h.DstPort)
	i += 2

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x09, 0x00, 0x0a})
	binary.BigEndian.PutUint32(dAtA[i:], h.Tsec)
	i += 4

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a})
	binary.BigEndian.PutUint32(dAtA[i:], h.Tmsec)
	i += 4

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0b, 0x00, 0x07})
	dAtA[i] = h.ProtoType
	i++

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a})
	binary.BigEndian.PutUint32(dAtA[i:], h.NodeID)
	i += 4

	if h.NodePW != "" {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0e})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.NodePW)))
		i += 2
		i += copy(dAtA[i:], h.NodePW)
	}

	if h.Payload != nil {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0f})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.Payload)))
		i += 2
		i += copy(dAtA[i:], h.Payload)
	}

	if h.CID != nil {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x11})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.CID)))
		i += 2
		i += copy(dAtA[i:], h.CID)
	}

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x12, 0x00, 0x08})
	binary.BigEndian.PutUint16(dAtA[i:], h.Vlan)
	i += 2

	if h.NodeName != "" {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x13})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.NodeName)))
		i += 2
		i += copy(dAtA[i:], h.NodeName)
	}

	return i, nil
}

func (h *HepMsg) Size() (n int) {
	n += 4 + 2     // len("HEP3") + 2
	n += 4 + 2 + 1 // len(vendor) + len(chunk) + len(Version)
	n += 4 + 2 + 1 // len(vendor) + len(chunk) + len(Protocol)
	if h.SrcIP != nil {
		n += 4 + 2 + len(h.SrcIP) // len(vendor) + len(chunk) + len(SrcIP)
	}
	if h.DstIP != nil {
		n += 4 + 2 + len(h.DstIP) // len(vendor) + len(chunk) + len(DstIP)
	}
	n += 4 + 2 + 2 // len(vendor) + len(chunk) + len(SrcPort)
	n += 4 + 2 + 2 // len(vendor) + len(chunk) + len(DstPort)
	n += 4 + 2 + 4 // len(vendor) + len(chunk) + len(Tsec)
	n += 4 + 2 + 4 // len(vendor) + len(chunk) + len(Tmsec)
	n += 4 + 2 + 1 // len(vendor) + len(chunk) + len(ProtoType)
	n += 4 + 2 + 4 // len(vendor) + len(chunk) + len(NodeID)
	if h.NodePW != "" {
		n += 4 + 2 + len(h.NodePW) // len(vendor) + len(chunk) + len(NodePW)
	}
	if h.Payload != nil {
		n += 4 + 2 + len(h.Payload) // len(vendor) + len(chunk) + len(Payload)
	}
	if h.CID != nil {
		n += 4 + 2 + len(h.CID) // len(vendor) + len(chunk) + len(CID)
	}
	n += 4 + 2 + 2 // len(vendor) + len(chunk) + len(Vlan)
	if h.NodeName != "" {
		n += 4 + 2 + len(h.NodeName) // len(vendor) + len(chunk) + len(NodeName)
	}
	return n
}

func (h *HepMsg) String() string {
	if h == nil {
		return "nil"
	}
	s := strings.Join([]string{`HEP packet:{`,
		`Version:` + fmt.Sprintf("%v", h.Version) + `,`,
		`Protocol:` + fmt.Sprintf("%v", h.Protocol) + `,`,
		`SrcIP:` + fmt.Sprintf("%v", h.SrcIP) + `,`,
		`DstIP:` + fmt.Sprintf("%v", h.DstIP) + `,`,
		`SrcPort:` + fmt.Sprintf("%v", h.SrcPort) + `,`,
		`DstPort:` + fmt.Sprintf("%v", h.DstPort) + `,`,
		`Tsec:` + fmt.Sprintf("%v", h.Tsec) + `,`,
		`Tmsec:` + fmt.Sprintf("%v", h.Tmsec) + `,`,
		`ProtoType:` + fmt.Sprintf("%v", h.ProtoType) + `,`,
		`NodeID:` + fmt.Sprintf("%v", h.NodeID) + `,`,
		`NodePW:` + fmt.Sprintf("%s", h.NodePW) + `,`,
		`CID:` + fmt.Sprintf("%s", h.CID) + `,`,
		`Vlan:` + fmt.Sprintf("%v", h.Vlan),
		`}`,
	}, "")
	return s + " with Payload:\n" + fmt.Sprintf("%s", string(h.Payload))
}

func unsafeBytesToStr(z []byte) string {
	return *(*string)(unsafe.Pointer(&z))
}
