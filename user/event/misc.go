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

package event

import (
	"bytes"
	"fmt"
)

const ChunkSize = 16
const ChunkSizeHalf = ChunkSize / 2

const (
	COLORRESET  = "\033[0m"
	COLORRED    = "\033[31m"
	COLORGREEN  = "\033[32m"
	COLORYELLOW = "\033[33m"
	COLORBLUE   = "\033[34m"
	COLORPURPLE = "\033[35m"
	COLORCYAN   = "\033[36m"
	COLORWHITE  = "\033[37m"
)

func dumpByteSlice(b []byte, perfix string) *bytes.Buffer {
	var a [ChunkSize]byte
	bb := new(bytes.Buffer)
	n := (len(b) + (ChunkSize - 1)) &^ (ChunkSize - 1)

	for i := 0; i < n; i++ {

		//
		if i%ChunkSize == 0 {
			bb.WriteString(perfix)
			bb.WriteString(fmt.Sprintf("%04d", i))
		}

		if i%ChunkSizeHalf == 0 {
			bb.WriteString("    ")
		} else if i%(ChunkSizeHalf/2) == 0 {
			bb.WriteString("  ")
		}

		if i < len(b) {
			bb.WriteString(fmt.Sprintf(" %02X", b[i]))
		} else {
			bb.WriteString("  ")
		}

		if i >= len(b) {
			a[i%ChunkSize] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%ChunkSize] = '.'
		} else {
			a[i%ChunkSize] = b[i]
		}

		if i%ChunkSize == (ChunkSize - 1) {
			bb.WriteString(fmt.Sprintf("    %s\n", string(a[:])))
		}
	}
	return bb
}

func CToGoString(c []byte) string {
	n := -1
	for i, b := range c {
		if b == 0 {
			break
		}
		n = i
	}
	return string(c[:n+1])
}
