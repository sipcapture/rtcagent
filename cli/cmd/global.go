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
	"github.com/spf13/cobra"
)

// GlobalFlags are flags that defined globally
// and are inherited to all sub-commands.
type GlobalFlags struct {
	IsHex        bool
	Debug        bool
	Pid          uint64 // PID
	Uid          uint64 // UID
	NoSearch     bool   // No lib search
	loggerFile   string // save file
	HepServer    string
	HepPort      string
	HepTransport string
	HepEnable    bool
}

func getGlobalConf(command *cobra.Command) (conf GlobalFlags, err error) {
	conf.Pid, err = command.Flags().GetUint64("pid")
	if err != nil {
		return
	}

	conf.Uid, err = command.Flags().GetUint64("uid")
	if err != nil {
		return
	}

	conf.Debug, err = command.Flags().GetBool("debug")
	if err != nil {
		return
	}

	conf.IsHex, err = command.Flags().GetBool("hex")
	if err != nil {
		return
	}

	conf.NoSearch, err = command.Flags().GetBool("nosearch")
	if err != nil {
		return
	}

	conf.loggerFile, err = command.Flags().GetString("log-file")
	if err != nil {
		return
	}

	conf.HepServer, err = command.Flags().GetString("hep-server")
	if err != nil {
		return
	}

	conf.HepPort, err = command.Flags().GetString("hep-port")
	if err != nil {
		return
	}

	conf.HepTransport, err = command.Flags().GetString("hep-transport")
	if err != nil {
		return
	}

	return
}
