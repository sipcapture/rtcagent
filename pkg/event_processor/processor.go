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
	"fmt"
	"log"
	"rtcagent/hepclient/hepsender"
	"rtcagent/user/event"
	"sync"
)

const (
	MaxIncomingChanLen = 1024
	MaxParserQueueLen  = 1024
)

type EventProcessor struct {
	sync.Mutex
	incoming chan event.IEventStruct

	workerQueue map[string]IWorker

	logger *log.Logger

	// output model
	isHex bool
}

func (ep *EventProcessor) GetLogger() *log.Logger {
	return ep.logger
}

func (ep *EventProcessor) init() {
	ep.incoming = make(chan event.IEventStruct, MaxIncomingChanLen)
	ep.workerQueue = make(map[string]IWorker, MaxParserQueueLen)
}

// Write event
func (ep *EventProcessor) Serve() {
	for {
		select {
		case e := <-ep.incoming:
			ep.dispatch(e)
		}
	}
}

func (ep *EventProcessor) dispatch(e event.IEventStruct) {
	ep.logger.Printf("event ==== ID:%s", e.String())

	//fmt.Printf("event ==== ID:%s\n", e.String())

	if e.SendHep() {
		ep.logger.Printf("LETS SEND HEP\n")
		data, err := e.GenerateHEP()
		if err == nil {
			if hepsender.Hepsender != nil {
				hepsender.Hepsender.Output(data)
			}

		}
	}

	//ep.
	//Worker will be reimplement later!
	/*
		var uuid string = e.GetUUID()
		found, eWorker := ep.getWorkerByUUID(uuid)
		if !found {
			// ADD a new eventWorker into queue
			eWorker = NewEventWorker(e.GetUUID(), ep)
			ep.addWorkerByUUID(eWorker)
		}

		err := eWorker.Write(e)
		if err != nil {
			//...
			ep.GetLogger().Fatalf("write event failed , error:%v", err)
		}
	*/
}

//func (ep *EventProcessor) Incoming() chan user.IEventStruct {
//	return ep.incoming
//}

func (ep *EventProcessor) getWorkerByUUID(uuid string) (bool, IWorker) {
	ep.Lock()
	defer ep.Unlock()
	var eWorker IWorker
	var found bool
	eWorker, found = ep.workerQueue[uuid]
	if !found {
		return false, eWorker
	}
	return true, eWorker
}

func (ep *EventProcessor) addWorkerByUUID(worker IWorker) {
	ep.Lock()
	defer ep.Unlock()
	ep.workerQueue[worker.GetUUID()] = worker
}

func (ep *EventProcessor) delWorkerByUUID(worker IWorker) {
	ep.Lock()
	defer ep.Unlock()
	delete(ep.workerQueue, worker.GetUUID())
}

// Write event
func (ep *EventProcessor) Write(e event.IEventStruct) {
	select {
	case ep.incoming <- e:
		return
	}
}

func (ep *EventProcessor) Close() error {
	if len(ep.workerQueue) > 0 {
		return fmt.Errorf("EventProcessor.Close(): workerQueue is not empty:%d", len(ep.workerQueue))
	}
	return nil
}

func NewEventProcessor(logger *log.Logger, isHex bool) *EventProcessor {
	var ep *EventProcessor
	ep = &EventProcessor{}
	ep.logger = logger
	ep.isHex = isHex
	ep.init()
	return ep
}
