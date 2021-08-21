#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1

YUBIHSMSDK_VERSION="2021-04"
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update && sudo  apt-get dist-upgrade -y
sudo apt-get install -y build-essential      \
                        chrpath              \
                        git                  \
                        cmake                \
                        pkg-config           \
                        gengetopt            \
                        help2man             \
                        libedit-dev          \
                        libcurl4-openssl-dev \
                        liblzma-dev          \
                        libssl-dev           \
                        libseccomp-dev       \
                        libusb-1.0.0-dev     \
                        dh-exec              \
                        git-buildpackage     \
                        curl                 \
                        libpcsclite-dev

export PATH=$PATH:~/.cargo/bin
if [[ ! -x $(command -v rustc) ]]; then
  curl -o rustup.sh https://sh.rustup.rs
  bash ./rustup.sh -y
#  rustup update 1.33.0
  cargo install cargo-deb
fi

export INPUT=/shared/
export OUTPUT=/shared/resources/release/build/$PLATFORM/yubihsm-setup
rm -rf "${OUTPUT}"
mkdir -p "${OUTPUT}"

pushd "/tmp" &>/dev/null
  # install yubihsm-shell
  mkdir yubihsm2-sdk
  pushd "yubihsm2-sdk" &>/dev/null
    curl -L --max-redirs 2 -o - https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-$YUBIHSMSDK_VERSION-$PLATFORM-amd64.tar.gz |\
      tar -xzvf -
    pushd "yubihsm2-sdk" &>/dev/null
      sudo dpkg -i ./libyubihsm*_amd64.deb
    popd &>/dev/null
  popd &>/dev/null

  # install yubihsmrs
  rm -rf yubihsmrs
  git clone https://github.com/Yubico/yubihsmrs.git

  # copy and build yubihsm-setup
  rm -rf yubihsm-setup
  git clone "$INPUT" yubihsm-setup
  pushd "yubihsm-setup" &>/dev/null
    YUBIHSM_LIB_DIR=$(dpkg -L libyubihsm1 | grep -e "libyubihsm.so.2$" | xargs dirname) \
      cargo build --release
    strip --strip-all target/release/yubihsm-setup
    cargo deb --no-build
    cp target/debian/*.deb "${OUTPUT}"
  popd &>/dev/null
popd &>/dev/null

LICENSE_DIR="$OUTPUT/share/yubihsm-setup"
mkdir -p $LICENSE_DIR
pushd "/shared" &>/dev/null
  cp -r resources/release/licenses $LICENSE_DIR/
  for lf in $LICENSE_DIR/licenses/*; do
	  chmod 644 $lf
  done

  pushd "$OUTPUT" &>/dev/null
    rm -f yubihsm-setup-$PLATFORM-amd64.tar.gz
    tar -C .. -zcvf ../yubihsm-setup-$PLATFORM-amd64.tar.gz yubihsm-setup
    rm -f *.deb
    rm -rf licenses
    rm -rf ../yubihsm-setup
  popd &>/dev/null
popd &>/dev/null