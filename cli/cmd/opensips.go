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

var opensipsConfig = config.NewOpensipsConfig()

// opensipsCmd represents the opensips command
var opensipsCmd = &cobra.Command{
	Use:   "opensips",
	Short: "capture SIP messages from opensips: recv_msg, udp_send, tcp_send.",
	Long:  ` Tested on opensips 3.x`,
	Run:   opensipsCommandFunc,
}

func init() {
	opensipsCmd.PersistentFlags().StringVarP(&opensipsConfig.Opensipspath, "opensips", "m", "/usr/sbin/opensips", "opensips binary file path, use to hook")
	rootCmd.AddCommand(opensipsCmd)
}

// opensipsCommandFunc executes the "opensips" command.
func opensipsCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	mod := module.GetModuleByName(module.ModuleNameOpensips)

	logger := log.New(os.Stdout, "opensips_", log.LstdFlags)
	logger.Printf("RTCAGENT :: version :%s", GitVersion)
	logger.Printf("RTCAGENT :: start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	opensipsConfig.Pid = gConf.Pid
	opensipsConfig.Debug = gConf.Debug
	opensipsConfig.IsHex = gConf.IsHex
	opensipsConfig.NoSearch = gConf.NoSearch

	logger.Printf("RTCAGENT :: opensips - nosearch: %v", opensipsConfig.NoSearch)

	if (gConf.HepServer != "" || len(strings.TrimSpace(gConf.HepServer)) > 0) && hepsender.Hepsender == nil {

		log.Println("HEP client will be started")

		var err error
		hepsender.Hepsender, err = hepclient.NewHepClient(gConf.HepServer, gConf.HepPort, gConf.HepTransport)
		if err != nil {
			log.Fatalf("HEP client couldn't be init: addr:%s, port: %s, transport: %s. Error: %s", gConf.HepServer, gConf.HepPort, gConf.HepTransport, err.Error())
			os.Exit(1)
		} else {
			log.Println("HEP client started")
		}
	}

	log.Printf("RTCAGENT :: pid info :%d -%s", os.Getpid(), gConf.HepServer)
	//bc.Pid = globalFlags.Pid
	if e := opensipsConfig.Check(); e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}

	err := mod.Init(ctx, logger, opensipsConfig)
	if err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}

	go func(module module.IModule) {
		err := module.Run()
		if err != nil {
			logger.Fatalf("%v", err)
		}
	}(mod)
	<-stopper
	cancelFun()
	os.Exit(0)
}
