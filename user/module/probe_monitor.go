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
	"sort"
	"time"

	"rtcagent/model"

	manager "github.com/adubovikov/ebpfmanager"
	tm "github.com/buger/goterm"
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
	userFunctionArray []string
	promCh            chan model.AggregatedMetricValue
	uiCh              chan model.AggregatedTimeMetricValue
	uiSorted          []model.AggregatedTimeMetricValue
}

func (this *MMonitorProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {

	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	this.userFunctionArray = make([]string, 0, 100)
	return nil
}

func (this *MMonitorProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}

	//UI channel
	go this.MakeUI()

	return nil
}

func (this *MMonitorProbe) MakeUI() error {

	networkLatency := this.conf.(*config.MonitorConfig).NetworkLatency

	go func() {
		for {
			expireNow := time.Now().Unix()
			//fmt.Print("\033[H\033[2J")
			tm.Clear() // Clear current screen
			tm.MoveCursor(1, 1)

			if networkLatency {

				fmt.Printf("\r\n %s Kamailio TCP Latency. Refresh 1 sec.%s\r\n\r\n", event.COLORCYAN, event.COLORRESET)
				fmt.Printf("%s %-15s %-15s %-15s %-4s %-4s %-15s %-4s %-15s %-4s %-18s %-18s %-6s %-6s %s\r\n\r\n", event.COLORRED, "Node", "Timestamp", "App", "Pid", "Tid", "Src IP", "Src Port", "Dst IP", "Dst Port", "Old State", "New State", "Delta (ns)", "Latency (ns) ", event.COLORRESET)
			} else {

				fmt.Printf("\r\n %s Kamailio Syscall/Usercall. Refresh 1 sec.%s\r\n\r\n", event.COLORCYAN, event.COLORRESET)
				fmt.Printf("%s %-15s %-15s %-8s %-8s %-8s %-15s %-15s %-15s %-15s %-15s %-15s %s\r\n\r\n", event.COLORRED, "Node", "Timestamp", "App", "PID", "TID", "Syscallid", "Function", "Exit Code", "MaxCPU", "RecentCPU", "Latency (ns) ", event.COLORRESET)
			}

			temp := this.uiSorted[:0]

			for index, val := range this.uiSorted {
				if val.Time >= expireNow {
					temp = append(temp, val)
				}

				if index < 50 {
					if networkLatency {
						fmt.Printf("%s %-15s %-15d  %-25s %-4d %-4d %-15s:%-6d -> %-15s:%-6d %-18s %-18s %-6d %-6f%s\r\n", event.COLORGREEN,
							val.MapLabelsString["node"], val.Time, val.MapLabelsString["comm"], val.MapLabelsInt["pid"], val.MapLabelsInt["tid"], val.MapLabelsString["src_ip"], val.MapLabelsInt["src_port"], val.MapLabelsString["dst_ip"],
							val.MapLabelsInt["dst_port"], val.MapLabelsString["oldstate"], val.MapLabelsString["newstate"], val.MapLabelsInt["delta"], val.Value, event.COLORRESET)
					} else {
						fmt.Printf("%s %-15s %-15d %-15s %-8d %-8d %-15d %-15s %-15d %-15d %-15d %-5d %s\r\n", event.COLORGREEN,
							val.MapLabelsString["node"], val.Time, val.MapLabelsString["comm"], val.MapLabelsInt["pid"], val.MapLabelsInt["tid"], val.MapLabelsInt["syscallid"], val.MapLabelsString["funcname"],
							val.MapLabelsInt["exit_code"], val.MapLabelsInt["nrcpu"], val.MapLabelsInt["recentcpu"],
							val.MapLabelsInt["latency"], event.COLORRESET)
					}

				}
			}

			//tm.Flush() // Call it every time at the end of rendering
			this.uiSorted = temp
			time.Sleep(time.Duration(1) * time.Second)
		}

	}()

	for pkt := range this.uiCh {

		this.uiSorted = append(this.uiSorted, pkt)

		//Sorted by Latency
		sort.Slice(this.uiSorted, func(i, j int) bool {
			return this.uiSorted[i].Value > this.uiSorted[j].Value
		})
		//latencyTCP.WithLabelValues(pkt.Labels...).Set(pkt.Value)
	}

	return nil
}

type monitorBpfPrograms struct {
	MonitorEnter *ebpf.Program `ebpf:"tcp_rcv_state_process"`
	MonitorClose *ebpf.Program `ebpf:"tcp_v4_connect"`
}

type monitorBpfMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}
type monitorBpfObjects struct {
	monitorBpfPrograms
	monitorBpfMaps
}

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

	networkLatency := this.conf.(*config.MonitorConfig).NetworkLatency

	if networkLatency {
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

		this.linkData, err = link.AttachTracing(link.TracingOptions{
			Program: objs.monitorBpfPrograms.MonitorClose,
		})
		if err != nil {
			this.logger.Printf("%s\tBPF bytecode filename FATAL: [%s]\n", this.Name(), bpfFileName)
			log.Fatal(err)
		}

		this.eventMaps = append(this.eventMaps, objs.monitorBpfMaps.Events)
		this.eventFuncMaps[objs.monitorBpfMaps.Events] = &event.MonitorEvent{}

	} else {

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
	}

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
	networkcall := this.conf.(*config.MonitorConfig).NetworkCall
	userFunction := this.conf.(*config.MonitorConfig).UserFunctions
	this.promCh = this.conf.(*config.MonitorConfig).PromCh
	this.uiCh = this.conf.(*config.MonitorConfig).UiCh

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
	eventMap := "events"

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

		if len(userFunction) == 0 {
			userFunction = append(userFunction, "receive_msg")
		}

		this.userFunctionArray = append(this.userFunctionArray, userFunction...)

		for index, userFunction := range this.userFunctionArray {
			probes = append(probes, &manager.Probe{
				Section:          "uprobe/user_function",
				EbpfFuncName:     "user_function",
				AttachToFuncName: userFunction,
				BinaryPath:       binaryPath,
				Cookie:           uint64(index + 1),
			})
			probes = append(probes, &manager.Probe{
				Section:          "uretprobe/user_function",
				EbpfFuncName:     "user_ret_function",
				AttachToFuncName: userFunction,
				BinaryPath:       binaryPath,
				Cookie:           uint64(index + 1),
			})
		}
	} else if networkcall {

		probes = append(probes, &manager.Probe{
			Section:          "kprobe/tcp_v4_connect",
			EbpfFuncName:     "tcp_v4_connect",
			AttachToFuncName: "tcp_v4_connect",
			Cookie:           uint64(1),
		})

		/*
			probes = append(probes, &manager.Probe{
				Section:          "kretprobe/tcp_v4_connect",
				EbpfFuncName:     "tcp_v4_connect_ret",
				AttachToFuncName: "tcp_v4_connect",
				Cookie:           uint64(1),
			})

			probes = append(probes, &manager.Probe{
				Section:          "kprobe/tcp_rcv_state_process",
				EbpfFuncName:     "tcp_rcv_state_process",
				AttachToFuncName: "tcp_rcv_state_process",
				Cookie:           uint64(2),
			})

		*/
		probes = append(probes, &manager.Probe{
			Section:          "tracepoint/sock/inet_sock_set_state",
			EbpfFuncName:     "handle_set_state",
			AttachToFuncName: "handle_set_state",
			Cookie:           uint64(3),
		})

		eventMap = "netevents"

	} else {
		fmt.Println("No syscall or usercall")
		return nil
	}
	/*
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
	*/

	this.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: eventMap,
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

	//Src addr        Port   -> Dest addr       Port   RTT
	//monitor_2024/04/12 22:43:22  Time: 268211073705288 Pid: 1525079 Tid: 1525079 Comm: [kamailio] SysID: 100 Func:receive_msg Time Latency: 603834 ns, Max Cpu: 16, Recent CPU: 1, Exit Code: 0, Cookie: 1

	this.logger.Printf("%s%-6s %-6s %-6s %-6s %-6s %-6s %-6s %-6s %-6s %-6s %-6s %s", prefix, "Time", "Pid", "Tid", "Comm", "SysID", "Func", "Latency", "Max Cpu", "Recent Cpu", "Exit Code", "Cookie", event.COLORRESET)

	return nil
}

func (this *MMonitorProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func (this *MMonitorProbe) Dispatcher(e event.IEventStruct) {

	switch e.EventType() {
	case event.EventTypeOutput:
		if this.conf.GetHex() {
			this.logger.Println(e.StringHex())
		} else {
			e.DoCorrelation(this.userFunctionArray)
			this.promCh <- e.GenerateMetric()
			this.uiCh <- e.GenerateTimeMetric()
			//this.logger.Println(e.String())
		}
	case event.EventTypeEventProcessor:
		this.processor.Write(e)
	case event.EventTypeModuleData:
		// Save to cache
		this.child.Dispatcher(e)
	}
}

func init() {
	mod := &MMonitorProbe{}
	mod.name = ModuleNameMonitor
	mod.mType = ProbeTypeFentry
	Register(mod)
}
