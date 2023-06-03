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

const (
	ProbeTypeUprobe = "uprobe"
	ProbeTypeKprobe = "kprobe"
	ProbeTypeTC     = "TC"
	ProbeTypeTP     = "tracepoint"
	ProbeTypeFentry = "fentry"
	ProbeTypeXDP    = "XDP"
)

const (
	ModuleNameKamailio   = "EBPFProbeKamailio"
	ModuleNameFreeSwitch = "EBPFProbeFreeSwitch"
	ModuleNameTcprtt     = "EBPFProbeTcprtt"
)

const (
	BashErrnoDefault int = 128
)

// buffer size times of ebpf perf map
// buffer size = BufferSizeOfEbpfMap * os.pagesize
const BufferSizeOfEbpfMap = 1024
