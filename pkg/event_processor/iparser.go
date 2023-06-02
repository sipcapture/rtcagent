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
	"encoding/hex"
	"fmt"
)

type ProcessStatus uint8
type PacketType uint8
type ParserType uint8

const (
	ProcessStateInit ProcessStatus = iota
	ProcessStateProcessing
	ProcessStateDone
)

const (
	PacketTypeNull PacketType = iota
	PacketTypeUnknow
	PacketTypeGzip
	PacketTypeWebSocket
)

const (
	ParserTypeNull ParserType = iota
	ParserTypeHttpRequest
	ParserTypeHttp2Request
	ParserTypeHttpResponse
	ParserTypeHttp2Response
	ParserTypeWebSocket
)

type IParser interface {
	detect(b []byte) error
	Write(b []byte) (int, error)
	ParserType() ParserType
	PacketType() PacketType
	//Body() []byte
	Name() string
	IsDone() bool
	Init()
	Display() []byte
	Reset()
}

var parsers = make(map[string]IParser)

func Register(p IParser) {
	if p == nil {
		panic("Register Parser is nil")
	}
	name := p.Name()
	if _, dup := parsers[name]; dup {
		panic(fmt.Sprintf("Register called twice for Parser %s", name))
	}
	parsers[name] = p
}

func GetAllModules() map[string]IParser {
	return parsers
}

func GetModuleByName(name string) IParser {
	return parsers[name]
}

func NewParser(payload []byte) IParser {
	if len(payload) > 0 {
		var newParser IParser
		for _, parser := range GetAllModules() {
			err := parser.detect(payload)
			if err == nil {
				break
			}
		}
		if newParser == nil {
			newParser = new(DefaultParser)
		}
		newParser.Init()
		return newParser
	}
	var np = &DefaultParser{}
	np.Init()
	return np
}

type DefaultParser struct {
	reader *bytes.Buffer
	isdone bool
}

func (dp *DefaultParser) ParserType() ParserType {
	return ParserTypeNull
}

func (dp *DefaultParser) PacketType() PacketType {
	return PacketTypeNull
}

func (dp *DefaultParser) Write(b []byte) (int, error) {
	dp.isdone = true
	return dp.reader.Write(b)
}

func (dp *DefaultParser) detect(b []byte) error {
	return nil
}

func (dp *DefaultParser) Name() string {
	return "DefaultParser"
}

func (dp *DefaultParser) IsDone() bool {
	return dp.isdone
}

func (dp *DefaultParser) Init() {
	dp.reader = bytes.NewBuffer(nil)
}

func (dp *DefaultParser) Display() []byte {
	b := dp.reader.Bytes()
	if len(b) <= 0 {
		return []byte{}
	}
	if b[0] < 32 || b[0] > 126 {
		return []byte(hex.Dump(b))
	}
	return []byte(CToGoString(dp.reader.Bytes()))
}

func (dp *DefaultParser) Reset() {
	dp.isdone = false
	dp.reader.Reset()
}
