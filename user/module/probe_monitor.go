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
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"rtcagent/assets"
	"rtcagent/user/config"
	"rtcagent/user/event"

	manager "github.com/adubovikov/ebpfmanager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type MMonitorProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
	linkData          link.Link
}

func (this *MMonitorProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MMonitorProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

/*
type monitorBpfPrograms struct {
	MonitorEnter *ebpf.Program `ebpf:"raw_tracepoint_sys_enter"`
	MonitorClose *ebpf.Program `ebpf:"raw_tracepoint_sys_exit"`
}

type monitorBpfMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}
type monitorBpfObjects struct {
	monitorBpfPrograms
	monitorBpfMaps
}
*/

func (this *MMonitorProbe) start() error {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var bpfFileName = this.geteBPFName("user/bytecode/monitor_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename: [%s]\n", this.Name(), bpfFileName)

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	// setup the managers
	err = this.setupManagers()
	if err != nil {
		return fmt.Errorf("kamailio module couldn't find binPath %v.", err)
	}

	// initialize the bootstrap manager
	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	/*
		objs := monitorBpfObjects{}

		reader := bytes.NewReader(byteBuf)
		spec, err := ebpf.LoadCollectionSpecFromReader(reader)
		if err != nil {
			return fmt.Errorf("can't load bpf: %w", err)
		}

		err = spec.LoadAndAssign(&objs, nil)
		if err != nil {
			return fmt.Errorf("couldn't find asset %v.", err)
		}

		this.linkData, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: objs.monitorBpfPrograms.MonitorClose,
		})
		if err != nil {
			this.logger.Printf("%s\tBPF bytecode filename FATAL: [%s]\n", this.Name(), bpfFileName)
			log.Fatal(err)
		}

		this.eventMaps = append(this.eventMaps, objs.monitorBpfMaps.Events)
		this.eventFuncMaps[objs.monitorBpfMaps.Events] = &event.MonitorEvent{}
	*/

	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MMonitorProbe) Close() error {

	this.linkData.Close()
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return this.Module.Close()
}

func (this *MMonitorProbe) setupManagers() error {
	var binaryPath string

	version := this.conf.(*config.MonitorConfig).Version
	versionInfo := this.conf.(*config.MonitorConfig).VersionInfo
	syscall := this.conf.(*config.MonitorConfig).SysCall
	usercall := this.conf.(*config.MonitorConfig).UserCall

	switch this.conf.(*config.MonitorConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = this.conf.(*config.MonitorConfig).Monitorpath
	default:
		binaryPath = "/usr/sbin/kamailio"
	}

	//objdump -T /usr/sbin/kamailio |grep receive_msg
	//0000000000174c30 g    DF .text	000000000000541f  Base        receive_msg

	if !this.conf.(*config.MonitorConfig).GetNoSearch() {
		_, err := os.Stat(binaryPath)
		if err != nil {
			return err
		}
	}

	var probes = []*manager.Probe{}

	if syscall {
		probes = append(probes, &manager.Probe{
			Section:      "raw_tracepoint/sys_enter",
			EbpfFuncName: "raw_tracepoint_sys_enter",
		})

		probes = append(probes, &manager.Probe{
			Section:      "raw_tracepoint/sys_exit",
			EbpfFuncName: "raw_tracepoint_sys_exit",
		})
	} else if usercall {

		probes = append(probes, &manager.Probe{
			Section:          "uprobe/user_function",
			EbpfFuncName:     "user_function",
			AttachToFuncName: "receive_msg",
			BinaryPath:       binaryPath,
			Cookie:           0x1,
		})

		probes = append(probes, &manager.Probe{
			Section:          "uretprobe/user_function",
			EbpfFuncName:     "user_ret_function",
			AttachToFuncName: "receive_msg",
			BinaryPath:       binaryPath,
			Cookie:           0x2,
		})

	}

	this.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	this.logger.Printf("%s\tMonitor: %d, Version:%s, binrayPath:%s\n", this.Name(), version, versionInfo, binaryPath)

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

func (this *MMonitorProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MMonitorProbe) initDecodeFun() error {

	monitorEventsMap, found, err := this.bpfManager.GetMap("events")

	this.logger.Printf("====> BPF bytecode filename: [%v]\n", found)

	if err != nil {
		this.logger.Printf("====> ERRROR BPF bytecode filename: [%]\n", err.Error())
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, monitorEventsMap)
	this.eventFuncMaps[monitorEventsMap] = &event.MonitorEvent{}

	prefix := event.COLORCYAN

	this.logger.Printf("%s%-15s %-6s -> %-15s %-6s %-6s%s", prefix, "Src addr", "Port", "Dest addr", "Port", "RTT", event.COLORRESET)

	return nil
}

func (this *MMonitorProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MMonitorProbe{}
	mod.name = ModuleNameMonitor
	mod.mType = ProbeTypeFentry
	Register(mod)
}
