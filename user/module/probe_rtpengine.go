//go:build !androidgki
// +build !androidgki

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

type MRtpengineProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

func (this *MRtpengineProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MRtpengineProbe) Start() error {
	return this.start()
}

func (this *MRtpengineProbe) start() error {
	bpfFileName := this.geteBPFName("user/bytecode/rtpengine_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename: [%s]\n", this.Name(), bpfFileName)

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	if err = this.setupManagers(); err != nil {
		return err
	}

	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	return this.initDecodeFun()
}

func (this *MRtpengineProbe) MakeUI() error {
	return nil
}

func (this *MRtpengineProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return this.Module.Close()
}

func (this *MRtpengineProbe) setupManagers() error {
	cfg := this.conf.(*config.RtpengineConfig)
	binaryPath := cfg.Rtpenginepath
	if !cfg.GetNoSearch() {
		if _, err := os.Stat(binaryPath); err != nil {
			return err
		}
	}

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:      "tracepoint/syscalls/sys_enter",
				EbpfFuncName: "tracepoint_sys_enter",
			},
			{
				Section:      "tracepoint/syscalls/sys_exit",
				EbpfFuncName: "tracepoint_sys_exit",
			},
		},
		Maps: []*manager.Map{
			{Name: "events"},
		},
	}

	this.logger.Printf("%s\tRTPEngine: %s, binaryPath:%s\n", this.Name(), cfg.VersionInfo, binaryPath)

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

func (this *MRtpengineProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MRtpengineProbe) initDecodeFun() error {
	eventsMap, found, err := this.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}

	this.eventMaps = append(this.eventMaps, eventsMap)
	this.eventFuncMaps[eventsMap] = &event.RtpengineEvent{}
	return nil
}

func (this *MRtpengineProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MRtpengineProbe{}
	mod.name = ModuleNameRtpengine
	mod.mType = ProbeTypeTP
	Register(mod)
}
