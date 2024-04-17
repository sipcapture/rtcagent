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
	"golang.org/x/sys/unix"
)

type MFreeSwitchProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

func (this *MFreeSwitchProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MFreeSwitchProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MFreeSwitchProbe) MakeUI() error {

	return nil
}

func (this *MFreeSwitchProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = this.geteBPFName("user/bytecode/freeswitch_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename: [%s]\n", this.Name(), bpfFileName)

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	// setup the managers
	err = this.setupManagers()
	if err != nil {
		return fmt.Errorf("freeswitch module couldn't find binPath %v.", err)
	}

	// initialize the bootstrap manager
	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MFreeSwitchProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return this.Module.Close()
}

func (this *MFreeSwitchProbe) setupManagers() error {
	var binaryPath string
	switch this.conf.(*config.FreeSwitchConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = this.conf.(*config.FreeSwitchConfig).FreeSwitchpath
	default:
		binaryPath = "/usr/local/lib/libsofia-sip-ua.so.0"
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	version := this.conf.(*config.FreeSwitchConfig).Version
	versionInfo := this.conf.(*config.FreeSwitchConfig).VersionInfo

	//objdump -T /usr/local/lib/libsofia-sip-ua.so.0 |grep receive_msg
	//0000000000174c30 g    DF .text	000000000000541f  Base        receive_msg

	var probes = []*manager.Probe{
		{
			Section:          "uprobe/receive_msg",
			EbpfFuncName:     "freeswitch_receive_msg",
			AttachToFuncName: "su_vrecv",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uretprobe/receive_msg",
			EbpfFuncName:     "freeswitch_ret_receive_msg",
			AttachToFuncName: "su_vrecv",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uprobe/msg_send",
			EbpfFuncName:     "msg_send",
			AttachToFuncName: "tport_vsend",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uretprobe/msg_send",
			EbpfFuncName:     "msg_ret_send",
			AttachToFuncName: "tport_vsend",
			BinaryPath:       binaryPath,
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

	this.logger.Printf("%s\tFreeSwitch: %d, Version:%s, binrayPath:%s\n", this.Name(), version, versionInfo, binaryPath)

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

func (this *MFreeSwitchProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MFreeSwitchProbe) initDecodeFun() error {
	// freeswitchEventsMap
	freeswitchEventsMap, found, err := this.bpfManager.GetMap("events")

	this.logger.Printf("====> BPF bytecode filename: [%v]\n", found)

	if err != nil {
		this.logger.Printf("====> ERRROR BPF bytecode filename: [%]\n", err.Error())
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, freeswitchEventsMap)
	this.eventFuncMaps[freeswitchEventsMap] = &event.FreeSwitchEvent{}

	///Packet{payload: payload[:len(hep)], length: len(hep)}

	return nil
}

func (this *MFreeSwitchProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MFreeSwitchProbe{}
	mod.name = ModuleNameFreeSwitch
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
