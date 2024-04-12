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

package module

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"rtcagent/pkg/event_processor"
	"rtcagent/pkg/util/kernel"
	"rtcagent/user/config"
	"rtcagent/user/event"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

type IModule interface {
	// Init
	Init(context.Context, *log.Logger, config.IConfig) error

	Name() string

	// Run
	Run() error

	// Start
	Start() error

	// Stop
	Stop() error

	// Close
	Close() error

	SetChild(module IModule)

	Decode(*ebpf.Map, []byte) (event.IEventStruct, error)

	Events() []*ebpf.Map

	DecodeFun(p *ebpf.Map) (event.IEventStruct, bool)

	Dispatcher(event.IEventStruct)
}

const KernelLess52Prefix = "_less52.o"

type Module struct {
	opts   *ebpf.CollectionOptions
	reader []IClose
	ctx    context.Context
	logger *log.Logger
	child  IModule
	name   string

	mType string

	conf config.IConfig

	processor       *event_processor.EventProcessor
	isKernelLess5_2 bool //is  kernel version less 5.2
}

// Init
func (this *Module) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) {
	this.ctx = ctx
	this.logger = logger
	this.processor = event_processor.NewEventProcessor(logger, conf.GetHex())
	this.isKernelLess5_2 = false //set false default
	kv, err := kernel.HostVersion()
	if err != nil {
		// nothing to do.
	}
	if kv < kernel.VersionCode(5, 2, 0) {
		this.isKernelLess5_2 = true
	}
}

func (this *Module) geteBPFName(filename string) string {
	if this.isKernelLess5_2 {
		return strings.Replace(filename, ".o", KernelLess52Prefix, 1)
	}
	return filename
}

func (this *Module) SetChild(module IModule) {
	this.child = module
}

func (this *Module) Start() error {
	panic("Module.Start() not implemented yet")
}

func (this *Module) Events() []*ebpf.Map {
	panic("Module.Events() not implemented yet")
}

func (this *Module) DecodeFun(p *ebpf.Map) (event.IEventStruct, bool) {
	panic("Module.DecodeFun() not implemented yet")
}

func (this *Module) Name() string {
	return this.name
}

func (this *Module) Run() error {
	this.logger.Printf("RTCAGENT ::\tModule.Run()")
	//  start
	err := this.child.Start()
	if err != nil {
		return err
	}

	go func() {
		this.run()
	}()

	go func() {
		this.processor.Serve()
	}()

	err = this.readEvents()
	if err != nil {
		return err
	}

	return nil
}
func (this *Module) Stop() error {
	return nil
}

// Stop shuts down Module
func (this *Module) run() {
	for {
		select {
		case _ = <-this.ctx.Done():
			err := this.child.Stop()
			if err != nil {
				this.logger.Fatalf("%s\t stop Module error:%v.", this.child.Name(), err)
			}
			return
		}
	}
}

func (this *Module) readEvents() error {
	var errChan = make(chan error, 8)
	go func() {
		for {
			select {
			case err := <-errChan:
				this.logger.Printf("%s\treadEvents error:%v", this.child.Name(), err)
			}
		}
	}()

	for _, e := range this.child.Events() {
		switch {
		case e.Type() == ebpf.RingBuf:
			this.ringbufEventReader(errChan, e)
		case e.Type() == ebpf.PerfEventArray:
			this.perfEventReader(errChan, e)
		default:
			return fmt.Errorf("%s\tunsupported mapType:%s , mapinfo:%s",
				this.child.Name(), e.Type().String(), e.String())
		}
	}

	return nil
}

func (this *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := perf.NewReader(em, os.Getpagesize()*BufferSizeOfEbpfMap)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}

	this.reader = append(this.reader, rd)
	go func() {
		for {
			select {
			case _ = <-this.ctx.Done():
				this.logger.Printf("%s\tperfEventReader received close signal from context.Done().", this.child.Name())
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				errChan <- fmt.Errorf("%s\treading from perf event reader: %s", this.child.Name(), err)
				return
			}

			if record.LostSamples != 0 {
				this.logger.Printf("%s\tperf event ring buffer full, dropped %d samples", this.child.Name(), record.LostSamples)
				continue
			}

			var e event.IEventStruct
			e, err = this.child.Decode(em, record.RawSample)
			if err != nil {
				this.logger.Printf("%s\tthis.child.decode error:%v", this.child.Name(), err)
				continue
			}

			//
			this.child.Dispatcher(e)
		}
	}()
}

func (this *Module) ringbufEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := ringbuf.NewReader(em)
	if err != nil {
		errChan <- fmt.Errorf("%s\tcreating %s reader dns: %s", this.child.Name(), em.String(), err)
		return
	}

	this.reader = append(this.reader, rd)
	go func() {
		for {
			//
			select {
			case _ = <-this.ctx.Done():
				this.logger.Printf("%s\tringbufEventReader received close signal from context.Done().", this.child.Name())
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					this.logger.Printf("%s\tReceived signal, exiting..", this.child.Name())
					return
				}
				errChan <- fmt.Errorf("%s\treading from ringbuf reader: %s", this.child.Name(), err)
				return
			}

			var e event.IEventStruct
			e, err = this.child.Decode(em, record.RawSample)
			if err != nil {
				this.logger.Printf("%s\tthis.child.decode error:%v", this.child.Name(), err)
				continue
			}

			//
			this.Dispatcher(e)
		}
	}()
}

func (this *Module) Decode(em *ebpf.Map, b []byte) (event event.IEventStruct, err error) {
	es, found := this.child.DecodeFun(em)
	if !found {
		err = fmt.Errorf("%s\tcan't found decode function :%s, address:%p", this.child.Name(), em.String(), em)
		return
	}

	te := es.Clone()
	err = te.Decode(b)
	if err != nil {
		return nil, err
	}
	return te, nil
}

func (this *Module) Dispatcher(e event.IEventStruct) {

	switch e.EventType() {
	case event.EventTypeOutput:

		if this.conf.GetHex() {
			this.logger.Println(e.StringHex())
		} else {
			this.logger.Println(e.String())
		}
	case event.EventTypeEventProcessor:
		this.processor.Write(e)
	case event.EventTypeModuleData:
		// Save to cache
		this.child.Dispatcher(e)
	}
}

func (this *Module) Close() error {
	this.logger.Printf("%s\tclose", this.child.Name())
	for _, iClose := range this.reader {
		if err := iClose.Close(); err != nil {
			return err
		}
	}
	err := this.processor.Close()
	return err
}
