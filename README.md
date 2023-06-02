# RtcAgent

The agent is focusing on VoIP/RTC Applications to make troubleshooting, support and monitoring much easily.

The Project was inspired by Cilum, Odigos, eCapture. Thank you these projects for nice libraries, implementations and huge job! Without you it will be impossible!

> **Note**
>
> Supports Linux/Android kernel versions x86_64 4.18 and above, **aarch64 5.5** and above.
> Does not support Windows and macOS system.
----

# What's eBPF
[eBPF](https://ebpf.io)

# How to compile
Linux Kernel: >= 4.18.

## Tools 
* golang 1.18 or newer
* clang 9.0 or newer
* cmake 3.18.4 or newer
* clang backend: llvm 9.0 or newer
* kernel config:CONFIG_DEBUG_INFO_BTF=y (Optional, 2022-04-17)

## command

### ubuntu
If you are using Ubuntu 20.04 or later versions, you can use a single command to complete the initialization of the compilation environment.
```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/adubovikov/rtcagent/master/builder/init_env.sh)"
```
### other Linux
In addition to the software listed in the 'Toolchain Version' section above, the following software is also required for the compilation environment. Please install it yourself.
* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**Clone the repository code and compile it**
```shell
git clone git@github.com:adubovikov/rtcagent.git
cd rtcagent
make
bin/rtcagent
```
## compile without BTF
RtcAgent support BTF disabled with command `make nocore` to compile at 2022/04/17. It can work normally even on Linux systems that do not support BTF.
```shell
make nocore
bin/rtcagent --help
```
