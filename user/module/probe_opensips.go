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

type MOpensipsProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

func (this *MOpensipsProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MOpensipsProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MOpensipsProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = this.geteBPFName("user/bytecode/opensips_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename: [%s]\n", this.Name(), bpfFileName)

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	// setup the managers
	err = this.setupManagers()
	if err != nil {
		return fmt.Errorf("opensips module couldn't find binPath %v.", err)
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

func (this *MOpensipsProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return this.Module.Close()
}

func (this *MOpensipsProbe) setupManagers() error {
	var binaryPath string
	switch this.conf.(*config.OpensipsConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = this.conf.(*config.OpensipsConfig).Opensipspath
	default:
		binaryPath = "/usr/sbin/opensips"
	}

	if !this.conf.(*config.OpensipsConfig).GetNoSearch() {
		_, err := os.Stat(binaryPath)
		if err != nil {
			return err
		}
	}

	version := this.conf.(*config.OpensipsConfig).Version
	versionInfo := this.conf.(*config.OpensipsConfig).VersionInfo

	//objdump -T /usr/sbin/opensips |grep receive_msg
	//0000000000174c30 g    DF .text	000000000000541f  Base        receive_msg

	var probes = []*manager.Probe{
		{
			Section:          "uprobe/receive_msg",
			EbpfFuncName:     "opensips_receive_msg",
			AttachToFuncName: "receive_msg",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uretprobe/receive_msg",
			EbpfFuncName:     "opensips_ret_receive_msg",
			AttachToFuncName: "receive_msg",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uprobe/msg_send_udp",
			EbpfFuncName:     "msg_send_udp",
			AttachToFuncName: "proto_udp_send",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uretprobe/msg_send_udp",
			EbpfFuncName:     "msg_ret_send_udp",
			AttachToFuncName: "proto_udp_send",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uprobe/msg_send_tcp",
			EbpfFuncName:     "msg_send_tcp",
			AttachToFuncName: "proto_tcp_send",
			BinaryPath:       binaryPath,
		},
		{
			Section:          "uretprobe/msg_send_tcp",
			EbpfFuncName:     "msg_ret_send_tcp",
			AttachToFuncName: "proto_tcp_send",
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

	this.logger.Printf("%s\tOpensips: %d, Version:%s, binrayPath:%s\n", this.Name(), version, versionInfo, binaryPath)

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

func (this *MOpensipsProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MOpensipsProbe) initDecodeFun() error {
	// opensipsEventsMap
	opensipsEventsMap, found, err := this.bpfManager.GetMap("events")

	this.logger.Printf("====> BPF bytecode filename: [%v]\n", found)

	if err != nil {
		this.logger.Printf("====> ERRROR BPF bytecode filename: [%]\n", err.Error())
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, opensipsEventsMap)
	this.eventFuncMaps[opensipsEventsMap] = &event.OpensipsEvent{}

	///Packet{payload: payload[:len(hep)], length: len(hep)}

	return nil
}

func (this *MOpensipsProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MOpensipsProbe{}
	mod.name = ModuleNameOpensips
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
