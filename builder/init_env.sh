#!/usr/bin/env bash

# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com//sipcapture/rtcagent/master/builder/init_env.sh)"

# check env
release_num=$(lsb_release -r --short)
if [ $? -ne 0 ]; then
  echo "command not found, supported ubuntu only."
  exit
fi

CLANG_NUM=12
# shellcheck disable=SC2209
MAKE_RTCAGENT=make
if [ ${release_num} == "20.04" ]; then
  CLANG_NUM=9
  MAKE_RTCAGENT="make nocore"
  elif [ ${release_num} == "20.10" ]; then
  CLANG_NUM=10
  MAKE_RTCAGENT="make nocore"
  elif [ ${release_num} == "21.04" ]; then
  CLANG_NUM=11
  elif [ ${release_num} == "21.10" ]; then
  CLANG_NUM=12
  elif [ ${release_num} == "22.04" ]; then
  CLANG_NUM=12
  elif [ ${release_num} == "22.10" ]; then
  CLANG_NUM=12
  elif [ ${release_num} == "24.04" ]; then
  CLANG_NUM=18
  elif [ ${release_num} == "24.10" ]; then
  CLANG_NUM=18
  else
  CLANG_NUM=18
  echo "unknown release ${release_num}, defaulting to clang-${CLANG_NUM}"
fi

echo "CLANG_NUM=${CLANG_NUM}"

UNAME_M=`uname -m`
ARCH="amd64"
if [[ ${UNAME_M} =~ "x86_64" ]];then
  ARCH="amd64"
  elif [[ ${UNAME_M} =~ "aarch64" ]]; then
    ARCH="arm64"
  else
    echo "unsupported arch ${UNAME_M}";
fi

GOBIN_ZIP="go1.21.12.linux-${ARCH}.tar.gz"
echo "GOBIN_ZIP:${GOBIN_ZIP}"

cd ~

uname -a
sudo apt-get update

# install packages
sudo apt-get install --yes build-essential pkgconf libelf-dev llvm-${CLANG_NUM} clang-${CLANG_NUM} \
  linux-tools-common linux-tools-generic upx-ucl
KVER="$(uname -r)"
sudo apt-get install -y "linux-tools-${KVER}" 2>/dev/null || \
  sudo apt-get install -y linux-tools-azure linux-cloud-tools-azure 2>/dev/null || true
if ! command -v bpftool >/dev/null; then
  for p in /usr/lib/linux-tools/*/bpftool /usr/sbin/bpftool; do
    if [ -x "$p" ]; then
      sudo ln -sf "$p" /usr/local/bin/bpftool
      break
    fi
  done
fi
for tool in "clang" "llc" "llvm-strip"
do
  sudo rm -f /usr/bin/$tool
  sudo ln -s /usr/bin/$tool-${CLANG_NUM} /usr/bin/$tool
done

clang --version
bpftool version 2>/dev/null || echo "bpftool not available; CI may use SKIP_AUTOGEN=1"


if ! command -v go >/dev/null; then
    wget https://go.dev/dl/${GOBIN_ZIP}
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf ${GOBIN_ZIP}
    export PATH=/usr/local/go/bin:$PATH
fi

if [ "${GITHUB_ACTIONS}" = "true" ]; then
  echo "CI mode: dependencies installed, skipping clone/build"
  exit 0
fi

git clone https://github.com/sipcapture/rtcagent.git
cd ./rtcagent || exit
go mod tidy
${MAKE_RTCAGENT}
