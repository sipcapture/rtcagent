//go:build !androidgki
// +build !androidgki

package cmd

import (
	"context"
	"log"
	"os"
	"os/signal"
	"rtcagent/hepclient"
	"rtcagent/hepclient/hepsender"
	"rtcagent/user/config"
	"rtcagent/user/module"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var rtpengineConfig = config.NewRtpengineConfig()

var rtpengineCmd = &cobra.Command{
	Use:   "rtpengine",
	Short: "capture RTP/RTCP media from RTPEngine via recvfrom/sendto syscalls",
	Long:  `Captures UDP media packets from the RTPEngine process and forwards them over HEP.`,
	Run:   rtpengineCommandFunc,
}

func init() {
	rtpengineCmd.PersistentFlags().StringVarP(&rtpengineConfig.Rtpenginepath, "rtpengine", "m", "/usr/bin/rtpengine", "RTPEngine binary path used for validation")
	rootCmd.AddCommand(rtpengineCmd)
}

func rtpengineCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	mod := module.GetModuleByName(module.ModuleNameRtpengine)

	logger := log.New(os.Stdout, "rtpengine_", log.LstdFlags)
	logger.Printf("RTCAGENT :: version :%s", GitVersion)
	logger.Printf("RTCAGENT :: start to run %s module", mod.Name())

	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	rtpengineConfig.Pid = gConf.Pid
	rtpengineConfig.Debug = gConf.Debug
	rtpengineConfig.IsHex = gConf.IsHex
	rtpengineConfig.NoSearch = gConf.NoSearch

	if (gConf.HepServer != "" || len(strings.TrimSpace(gConf.HepServer)) > 0) && hepsender.Hepsender == nil {
		log.Println("HEP client will be started")
		var err error
		hepsender.Hepsender, err = hepclient.NewHepClient(gConf.HepServer, gConf.HepPort, gConf.HepTransport)
		if err != nil {
			log.Fatalf("HEP client couldn't be init: addr:%s, port: %s, transport: %s. Error: %s", gConf.HepServer, gConf.HepPort, gConf.HepTransport, err.Error())
			os.Exit(1)
		}
		log.Println("HEP client started")
	}

	if e := rtpengineConfig.Check(); e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}

	if err := mod.Init(ctx, logger, rtpengineConfig); err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}

	go func(module module.IModule) {
		if err := module.Run(); err != nil {
			logger.Fatalf("%v", err)
		}
	}(mod)
	<-stopper
	cancelFun()
	os.Exit(0)
}
