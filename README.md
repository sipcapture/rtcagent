<a href="https://github.com/sipcapture">
<img src="https://github.com/sipcapture/rtcagent/assets/1423657/e1d78a7e-cf2e-4775-9177-b0a730ba66c6" height=100>
</a>

RTCagent is an HEP/eBPF powered observability tool for VoIP/WebRTC Applications.

<br>

### Made with eBPF
Before proceeding, learn everything you need to know about [eBPF](https://ebpf.io)

<a href="https://github.com/sipcapture">
<img src="https://github.com/sipcapture/rtcagent/assets/1423657/8a8d5057-12d0-432a-847e-80a8354825b6" height=400>
</a>

### Download
Download an `amd64/x86` static build of `rtcagent` and use it immediately.
```bash
curl -fsSL github.com/sipcapture/rtcagent/releases/latest/download/rtcagent -O && chmod +x rtcagent
```

Prefer using packages? Get the latest [deb and rpm](https://github.com/sipcapture/rtcagent/releases) releases for `amd64/x86`

### Usage

```

NAME:	rtcagent - Capture and debug RTC Projects.
USAGE:	rtcagent [flags]

COMMANDS:

	freeswitch	capture SIP messages from freeswitch (libsofia): t_port, su_recv
	help		Help about any command
	kamailio	capture SIP messages from kamailio: recv_msg, udp_send, tcp_send.
	tcprtt		show tcp rtt stats
  opensips	capture SIP messages from v: recv_msg, udp_send, tcp_send.


DESCRIPTION:

	RTCAgent is a tool that can capture and trace SIP packets using eBPF hooks and HEP
	
	Usage:
	  rtcagent <command> -h

OPTIONS:
  -d, --debug[=false]		enable debug logging
  -h, --help[=false]		help for rtcagent
  -P, --hep-port="9060"		hep port - default 9060
  -S, --hep-server=""		hep server to duplicate: i.e. 10.0.0.1
  -T, --hep-transport="udp"	hep transport default udp. Can be udp, tcp, tls
      --hex[=false]		print byte strings as hex encoded strings
  -l, --log-file=""		-l save the packets to file
      --nosearch[=false]	no lib search
  -p, --pid=0			if pid is 0 then we target all pids
  -u, --uid=0			if uid is 0 then we target all users
  -v, --version[=false]		version for rtcagent

```

<br>

### Build

> Compatible with Linux/Android kernel versions >= **x86_64 4.18**, >= **aarch64 5.5**.<br>
> Linux only. Does not support Windows and macOS.

#### Requirements 
* golang 1.18 or newer
* clang 9.0 or newer
* cmake 3.18.4 or newer
* clang backend: llvm 9.0 or newer
* kernel config:CONFIG_DEBUG_INFO_BTF=y

#### Instructions

##### Ubuntu
If you are using Ubuntu 20.04 or later versions, you can use a single command to complete the initialization of the compilation environment.
```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com//sipcapture/rtcagent/master/builder/init_env.sh)"
```
##### Any Linux
In addition to the software listed in the 'Toolchain Version' section above, the following software is also required for the compilation environment. Please install before proceeding.

* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**Clone the repository code and compile**
```shell
git clone git@github.com:/sipcapture/rtcagent.git
cd rtcagent
make
bin/rtcagent
```
#### compile without BTF
RTCAgent support BTF disabled with command `make nocore` to compile at 2022/04/17 and can run on Linux systems that do not support BTF.
```shell
make nocore
bin/rtcagent --help
```

<br>

### Docker
```
rtcagent:
    privileged: true
    pid: host
    image: ghcr.io/sipcapture/rtcagent
    container_name: rtcagent
    restart: unless-stopped
    volumes:
      - /sys/fs/cgroup:/host/sys/fs/cgroup:ro
      - /sys/kernel/debug:/sys/kernel/debug:rw
    command: --cgroupfs-root=/host/sys/fs/cgroup
```

### Credits

RTCAgent is inspired by Cilum, Odigos, eCapture and the many eBPF guides, libraries and implementations.
