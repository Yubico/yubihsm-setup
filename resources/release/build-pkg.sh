#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1

YUBIHSMSDK_VERSION="2022-06" # To download the latest released version of yubihsm-shell
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update && sudo  apt-get dist-upgrade -y
#sudo apt-get install -y build-essential git cmake pkg-config libedit-dev libssl-dev libcurl4-openssl-dev libpcsclite-dev libusb-1.0-0-dev
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
  if [ "$PLATFORM" == "ubuntu1404" ] || [ "$PLATFORM" == "ubuntu1604" ]; then
    cargo install cargo-deb --version 1.28.0
  else
    cargo install cargo-deb
  fi
fi

export INPUT=/shared/
export OUTPUT=/shared/resources/release/build/$PLATFORM/yubihsm-setup
rm -rf "${OUTPUT}"
mkdir -p "${OUTPUT}"

pushd "/tmp" &>/dev/null
  # install yubihsm-shell
#  mkdir yubihsm2-sdk
#  pushd "yubihsm2-sdk" &>/dev/null
#    curl -L --max-redirs 2 -o - https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-$YUBIHSMSDK_VERSION-$PLATFORM-amd64.tar.gz |\
#      tar -xzvf -
#    pushd "yubihsm2-sdk" &>/dev/null
#      sudo dpkg -i ./libyubihsm*_amd64.deb
#    popd &>/dev/null
#  popd &>/dev/null

  #git clone https://github.com/Yubico/yubihsm-shell.git
  #cp -r /shared/resources/yubihsm-shell .
  #pushd "yubihsm-shell" &>/dev/null
  #  mkdir build
  #  pushd "build" &>/dev/null
  #    cmake .. -DBUILD_ONLY_LIB=ON
  #    make
  #  popd
  #  if [ "${PLATFORM:0:6}" == "debian" ] || [ "$PLATFORM" == "ubuntu1804" ]; then
  #    dpkg-buildpackage -b --no-sign
  #  else
  #    dpkg-buildpackage
  #  fi
  #popd
  #cp libyubihsm1*.deb "${OUTPUT}"
  #cp libyubihsm-usb1*.deb "${OUTPUT}"
  #cp libyubihsm-http1*.deb "${OUTPUT}"

  sudo dpkg -i $INPUT/resources/release/libyubihsm*_amd64.deb

  # install yubihsmrs
  rm -rf yubihsmrs
  git clone https://github.com/Yubico/yubihsmrs.git

  # copy and build yubihsm-setup
  rm -rf yubihsm-setup
  git clone "$INPUT" yubihsm-setup
  pushd "yubihsm-setup" &>/dev/null
    #YUBIHSM_LIB_DIR=$(dpkg -L libyubihsm1 | grep -e "libyubihsm.so.2$" | xargs dirname) \
    #  cargo build --release
    #YUBIHSM_LIB_DIR=/tmp/yubihsm-shell/build/lib cargo build --release
    YUBIHSM_LIB_DIR=/usr/lib/x86_64-linux-gnu cargo build --release
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