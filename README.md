<img src="https://github.com/sipcapture/rtcagent/assets/1423657/e1d78a7e-cf2e-4775-9177-b0a730ba66c6" height=100>

RTCagent is an eBPF powered observability tool for VoIP/RTC Applications compatible with the HEP protocol.

----

### About eBPF
Before proceeding, learn everything you need to know about [eBPF](https://ebpf.io)

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
RTCAgent support BTF disabled with command `make nocore` to compile at 2022/04/17. It can work normally even on Linux systems that do not support BTF.
```shell
make nocore
bin/rtcagent --help
```


### Credits

This Project was inspired by Cilum, Odigos, eCapture and the many libraries, implementations making this possible.
