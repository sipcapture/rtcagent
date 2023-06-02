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
	"encoding/hex"
	"rtcagent/user/event"
	"time"
)

type IWorker interface {
	Write(event.IEventStruct) error
	GetUUID() string
}

const (
	MaxTickerCount = 10 // 1 Sencond/(eventWorker.ticker.C) = 10
	MaxChanLen     = 16
)

type eventWorker struct {
	incoming chan event.IEventStruct
	//events      []user.IEventStruct
	status      ProcessStatus
	packetType  PacketType
	ticker      *time.Ticker
	tickerCount uint8
	UUID        string
	processor   *EventProcessor
	parser      IParser
}

func NewEventWorker(uuid string, processor *EventProcessor) IWorker {
	eWorker := &eventWorker{}
	eWorker.init(uuid, processor)
	go func() {
		eWorker.Run()
	}()
	return eWorker
}

func (ew *eventWorker) init(uuid string, processor *EventProcessor) {
	ew.ticker = time.NewTicker(time.Millisecond * 100)
	ew.incoming = make(chan event.IEventStruct, MaxChanLen)
	ew.status = ProcessStateInit
	ew.UUID = uuid
	ew.processor = processor
}

func (ew *eventWorker) GetUUID() string {
	return ew.UUID
}

func (ew *eventWorker) Write(e event.IEventStruct) error {
	ew.incoming <- e
	return nil
}

func (ew *eventWorker) Display() {

	//if ew.parser.ParserType() != ParserTypeHttpResponse {
	//	return
	//}

	b := ew.parser.Display()

	if len(b) <= 0 {
		return
	}

	if ew.processor.isHex {
		b = []byte(hex.Dump(b))
	}

	//ew.processor.GetLogger().Printf("UUID:%s, Name:%s, Type:%d, Length:%d", ew.UUID, ew.parser.Name(), ew.parser.ParserType(), len(b))
	ew.processor.GetLogger().Println("\n===================================================" + string(b))
	ew.parser.Reset()
	ew.status = ProcessStateDone
	ew.packetType = PacketTypeNull
}

func (ew *eventWorker) parserEvent(e event.IEventStruct) {

	if ew.status == ProcessStateInit {
		parser := NewParser(e.Payload())
		ew.parser = parser
	}

	ew.status = ProcessStateProcessing

	_, err := ew.parser.Write(e.Payload()[:e.PayloadLen()])
	if err != nil {
		ew.processor.GetLogger().Fatalf("eventWorker: detect packet type error, UUID:%s, error:%v", ew.UUID, err)
	}

	if ew.parser.IsDone() {

		ew.Display()
	}

}

func (ew *eventWorker) Run() {
	for {
		select {
		case _ = <-ew.ticker.C:
			//
			if ew.tickerCount > MaxTickerCount {
				ew.processor.GetLogger().Printf("eventWorker TickerCount > %d, event closed.", MaxTickerCount)
				ew.Close()
				return
			}
			ew.tickerCount++
		case e := <-ew.incoming:
			// reset tickerCount
			ew.tickerCount = 0
			ew.parserEvent(e)
		}
	}

}

func (ew *eventWorker) Close() {
	ew.ticker.Stop()
	ew.Display()
	ew.tickerCount = 0
	ew.processor.delWorkerByUUID(ew)
}
