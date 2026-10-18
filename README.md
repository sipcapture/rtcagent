<a href="https://github.com/sipcapture">
<img src="https://github.com/sipcapture/rtcagent/assets/1423657/e1d78a7e-cf2e-4775-9177-b0a730ba66c6" height=100>
</a>

[![CI](https://github.com/sipcapture/rtcagent/actions/workflows/ci.yml/badge.svg)](https://github.com/sipcapture/rtcagent/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sipcapture/rtcagent/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/sipcapture/rtcagent/security/code-scanning)
[![Release](https://img.shields.io/github/v/release/sipcapture/rtcagent?sort=semver)](https://github.com/sipcapture/rtcagent/releases/latest)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

> RTCagent is an HEP/eBPF powered observability tool for VoIP/WebRTC Applications.

<br>

### About

**RTCAgent** is a _next-generation **HEP Agent**_ developed using the latest **[eBPF](https://ebpf.io)** technologies.

RTCAgent greatly differs from any other previous HEP Agent in several ways:

- Unlike _native agents_, it does not require any code modifications or patches
- Unlike _passive agents_, it does not require access to network interfaces and packets
- Unlike _any other agent_, it traces functions used for _sending/receiving_ data

_The result is a new, lightweight and portable HEP Agent able to mirror SIP packets through eBPF hooks<br>
from the core of supported applications bypassing manual code integrations, network encryption and complexity._

<br>

<a href="https://github.com/sipcapture">
<img src="https://github.com/sipcapture/rtcagent/assets/1423657/3869ea12-f172-40d8-9baf-5f7a82b9e09c" height=400>
</a>


### Download
Download a static build of `rtcagent` and use it immediately on modern kernels.

`amd64/x86`:
```bash
curl -fsSL github.com/sipcapture/rtcagent/releases/latest/download/rtcagent -O && chmod +x rtcagent
```

`arm64/aarch64`:
```bash
curl -fsSL github.com/sipcapture/rtcagent/releases/latest/download/rtcagent-arm64 -O && chmod +x rtcagent-arm64
```

Prefer using packages? Get the latest [deb and rpm](https://github.com/sipcapture/rtcagent/releases) releases for `amd64/x86` and `arm64/aarch64`.

Each release also ships `checksums.txt`, keyless cosign signatures (`*.sig`/`*.pem`) and an SPDX SBOM, and the build has GitHub [artifact attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations) (`gh attestation verify <file> -R sipcapture/rtcagent`). The container image is signed and accompanied by an SBOM and a Trivy scan report (`rtcagent-image.spdx.json`, `trivy-image.sarif`), with the SBOM attached to the image as a cosign attestation.

#### Verifying a release

```bash
# Checksums for every artifact
sha256sum -c checksums.txt

# GitHub build provenance
gh attestation verify rtcagent -R sipcapture/rtcagent

# Keyless cosign signature
cosign verify-blob --certificate rtcagent.pem --signature rtcagent.sig \
  --certificate-identity-regexp 'https://github.com/sipcapture/rtcagent/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com rtcagent

# Container image and its SBOM attestation
cosign verify --certificate-identity-regexp 'https://github.com/sipcapture/rtcagent/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sipcapture/rtcagent:latest
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp 'https://github.com/sipcapture/rtcagent/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sipcapture/rtcagent:latest
```

### Usage

```

NAME:	rtcagent - Capture and debug RTC Projects.
USAGE:	rtcagent [flags]

COMMANDS:

	help		Help about any command
	freeswitch	capture SIP messages from freeswitch (libsofia): t_port, su_recv
	kamailio	capture SIP messages from kamailio: recv_msg, udp_send, tcp_send.
	opensips	capture SIP messages from v: recv_msg, udp_send, tcp_send.
	rtpengine	capture RTP/RTCP media from RTPEngine via recvfrom/sendto syscalls.
	tcprtt		show tcp rtt stats
  monitor		show advanced monitor statistics


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

> Compatible with Linux/Android kernel versions >= **x86_64 5.x**, >= **aarch64 5.5**.<br>
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

### Usage
Run `rtcagent` on a native host attaching to a local binary target
##### Kamailio
```
./rtcagent kamailio -T udp -P 9060 -S $HOMER -m /usr/sbin/kamailio
```
##### OpenSIPS
```
./rtcagent opensips -T tcp -P 9061 -S $HOMER -m /usr/sbin/opensips
```
##### FreeSwitch
```
./rtcagent freeswitch -T udp -P 9060 -S $HOMER -m /usr/sbin/freeswitch
```

### Docker
#### Hypervisor Mode
Run `rtcagent` as a priviledged container on your host attaching to a local binary target
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

#### Cross-Container Mode
Run `rtcagent` as a priviledged container attached to a target container via docker volume mounts
##### Kamailio
```
rtcagent:
    privileged: true
    image: ghcr.io/sipcapture/rtcagent
    container_name: rtcagent
    restart: unless-stopped
    volumes:
      - $(docker inspect --format="{{.GraphDriver.Data.MergedDir}}" kamailio)/usr/sbin/kamailio:/kamailio:ro
    command: /rtcagent kamailio -m /kamailio
    depends_on:
      - kamailio
```
##### OpenSIPS
```
rtcagent:
    privileged: true
    image: ghcr.io/sipcapture/rtcagent
    container_name: rtcagent
    restart: unless-stopped
    volumes:
      - $(docker inspect --format="{{.GraphDriver.Data.MergedDir}}" opensips)/usr/sbin/opensips:/opensips:ro
    command: /rtcagent opensips -m /opensips
    depends_on:
      - opensips
```


### Credits

RTCAgent is inspired by Cilum, Odigos, eCapture and the many eBPF guides, libraries and implementations.
