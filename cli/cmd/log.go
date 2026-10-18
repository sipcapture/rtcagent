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
	"io"
	"log"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// newLogger returns a *log.Logger that emits structured slog records to stdout,
// tagged with the given component name.
//
// Returning a *log.Logger keeps the module interface and every existing
// logger.Printf call site unchanged; --debug switches the records to the DEBUG
// level.
func newLogger(component string, command *cobra.Command) *log.Logger {
	return newLoggerTo(os.Stdout, component, command)
}

func newLoggerTo(w io.Writer, component string, command *cobra.Command) *log.Logger {
	level := slog.LevelInfo
	if debug, err := command.Flags().GetBool("debug"); err == nil && debug {
		level = slog.LevelDebug
	}

	var handler slog.Handler = slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	handler = handler.WithAttrs([]slog.Attr{slog.String("component", component)})

	return slog.NewLogLogger(handler, level)
}
