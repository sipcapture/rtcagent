//go:build !androidgki
// +build !androidgki

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
	"bytes"
	"context"
	"fmt"
	"log"
	"math"
	"rtcagent/assets"
	"rtcagent/user/config"
	"rtcagent/user/event"

	manager "github.com/adubovikov/ebpfmanager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type MTcprttProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
	linkData          link.Link
}

func (this *MTcprttProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MTcprttProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

type bpfPrograms struct {
	TcpClose *ebpf.Program `ebpf:"tcp_close"`
}

type bpfMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (this *MTcprttProbe) start() error {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var bpfFileName = this.geteBPFName("user/bytecode/tcprtt_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename: [%s]\n", this.Name(), bpfFileName)

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	objs := bpfObjects{}

	reader := bytes.NewReader(byteBuf)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return fmt.Errorf("can't load bpf: %w", err)
	}

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	this.linkData, err = link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpClose,
	})
	if err != nil {
		this.logger.Printf("%s\tBPF bytecode filename FATAL: [%s]\n", this.Name(), bpfFileName)
		log.Fatal(err)
	}

	this.eventMaps = append(this.eventMaps, objs.bpfMaps.Events)
	this.eventFuncMaps[objs.bpfMaps.Events] = &event.TcprttEvent{}

	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MTcprttProbe) Close() error {

	this.linkData.Close()
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return this.Module.Close()
}

func (this *MTcprttProbe) setupManagers() error {
	var binaryPath string

	version := this.conf.(*config.TcprttConfig).Version
	versionInfo := this.conf.(*config.TcprttConfig).VersionInfo

	var probes = []*manager.Probe{
		{
			Section:          "fentry/tcp_close",
			EbpfFuncName:     `ebpf:"tcp_close"`,
			AttachToFuncName: `ebpf:"tcp_close"`,
		},
	}

	this.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	this.logger.Printf("%s\tTcprtt: %d, Version:%s, binrayPath:%s\n", this.Name(), version, versionInfo, binaryPath)

	this.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
	return nil
}

func (this *MTcprttProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MTcprttProbe) initDecodeFun() error {

	prefix := event.COLORCYAN

	this.logger.Printf("%s%-15s %-6s -> %-15s %-6s %-6s%s", prefix, "Src addr", "Port", "Dest addr", "Port", "RTT", event.COLORRESET)

	return nil
}

func (this *MTcprttProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MTcprttProbe{}
	mod.name = ModuleNameTcprtt
	mod.mType = ProbeTypeFentry
	Register(mod)
}
