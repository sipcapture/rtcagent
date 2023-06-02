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
	"os"
	"rtcagent/cli/cobrautl"

	"github.com/spf13/cobra"
)

const (
	cliName        = "rtcagent"
	cliDescription = "Capture and debug RTC Projects."
)

var (
	GitVersion = "v0.0.0_unknow"
	//ReleaseDate = "2022-03-16"
)

const (
	defaultPid uint64 = 0
	defaultUid uint64 = 0
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:        cliName,
	Short:      cliDescription,
	SuggestFor: []string{"rtcagent"},

	Long: `RTCAgent is a tool that can capture and trace SIP packets by hijacking application's function like kamailio, freeswitch
		it can also make tcpdrop statics on the server.

Repository: https://github.com/adubovikov/rtcagent
HomePage: https://www.qxip.net

Usage:
  rtcagent kamailio -h
  rtcagent freeswitch -h
`,
}

func usageFunc(c *cobra.Command) error {
	return cobrautl.UsageFunc(c, GitVersion)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SetUsageFunc(usageFunc)
	rootCmd.SetHelpTemplate(`{{.UsageString}}`)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Version = GitVersion
	rootCmd.SetVersionTemplate(`{{with .Name}}{{printf "%s " .}}{{end}}{{printf "version:\t%s" .Version}}
`)

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}

}

func init() {
	cobra.EnablePrefixMatching = true
	var globalFlags = GlobalFlags{}

	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().BoolVarP(&globalFlags.Debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&globalFlags.IsHex, "hex", false, "print byte strings as hex encoded strings")
	rootCmd.PersistentFlags().BoolVar(&globalFlags.NoSearch, "nosearch", false, "no lib search")
	rootCmd.PersistentFlags().Uint64VarP(&globalFlags.Pid, "pid", "p", defaultPid, "if pid is 0 then we target all pids")
	rootCmd.PersistentFlags().Uint64VarP(&globalFlags.Uid, "uid", "u", defaultUid, "if uid is 0 then we target all users")
	rootCmd.PersistentFlags().StringVarP(&globalFlags.loggerFile, "log-file", "l", "", "-l save the packets to file")
	rootCmd.PersistentFlags().StringVarP(&globalFlags.HepServer, "hep-server", "S", "", "hep server to duplicate: i.e. 10.0.0.1")
	rootCmd.PersistentFlags().StringVarP(&globalFlags.HepPort, "hep-port", "P", "9060", "hep port - default 9060")
	rootCmd.PersistentFlags().StringVarP(&globalFlags.HepTransport, "hep-transport", "T", "udp", "hep transport default udp. Can be udp, tcp, tls")

}
