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

package config

import "log"

const (
	LdLoadPath       = "/etc/ld.so.conf"
	ElfArchIsandroid = false
)

/*
1, the RPATH binary header (set at build-time) of the library causing the lookup (if any)
2, the RPATH binary header (set at build-time) of the executable
3, the LD_LIBRARY_PATH environment variable (set at run-time)
4, the RUNPATH binary header (set at build-time) of the executable
5, /etc/ld.so.cache
6, base library directories (/lib and /usr/lib)
ref: http://blog.tremily.us/posts/rpath/
*/
var (
	default_so_paths = []string{
		"/lib",
		"/usr/lib",
		"/usr/lib64",
		"/lib64",
	}
)

func GetDynLibDirs() []string {
	dirs, err := ParseDynLibConf(LdLoadPath)
	if err != nil {
		log.Println(err.Error())
		return default_so_paths
	}
	return append(dirs, "/lib64", "/usr/lib64")
}
