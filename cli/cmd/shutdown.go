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

	"rtcagent/user/module"
)

// waitForShutdown blocks until a termination signal is received, then cancels
// the context and closes the module so that eBPF maps, probes and perf event
// readers are released before the process exits.
//
// It does not call os.Exit, so deferred cleanups (for example the metrics
// server) still run when the command function returns.
func waitForShutdown(stopper <-chan os.Signal, logger *log.Logger, cancel context.CancelFunc, mod module.IModule) {
	<-stopper
	logger.Printf("RTCAGENT :: received shutdown signal, stopping %s", mod.Name())

	cancel()

	if err := mod.Close(); err != nil {
		logger.Printf("RTCAGENT :: shutdown error: %v", err)
	}
}
