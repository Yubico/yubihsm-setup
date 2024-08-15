#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1
LIBYUBIHSM_VERSION="2.4.0" # To download the latest released version of yubihsm-shell

if [ "$PLATFORM" == "centos7" ]; then
  sudo yum -y install centos-release-scl
  sudo yum -y update && sudo yum -y upgrade
  sudo yum -y install devtoolset-7-gcc     \
                      devtoolset-7-gcc-c++ \
                      git                  \
                      cmake                \
                      openssl-devel        \
                      libcurl-devel        \
                      libusbx-devel        \
                      clang                \
                      rpm-build

  . /opt/rh/devtoolset-7/enable
  export CMAKE="cmake"

elif [ "$PLATFORM" == "centos8" ]; then
  sudo yum -y install epel-release
  sudo yum -y update && sudo yum -y upgrade

  sudo dnf group -y install "Development Tools"
  sudo dnf config-manager -y --set-enabled powertools
  sudo yum -y install cmake3               \
                      libcurl-devel        \
                      libusbx-devel        \
                      openssl-devel

  export CMAKE="cmake3"

elif [ "${PLATFORM:0:6}" == "fedora" ]; then
  sudo dnf -y update
  sudo dnf -y install binutils         \
                      git              \
                      cmake            \
                      openssl-devel    \
                      libusb1-devel     \
                      libcurl-devel    \
                      rpmdevtools      \
                      pcsc-lite-devel

  export CMAKE="cmake"
fi


export PATH=$PATH:~/.cargo/bin
if [[ ! -x $(command -v rustc) ]]; then
  curl -o rustup.sh https://sh.rustup.rs
  bash ./rustup.sh -y
fi

export INPUT=/shared
export OUTPUT=/shared/resources/release/build/$PLATFORM/yubihsm-setup
rm -rf $OUTPUT
mkdir -p $OUTPUT

pushd "/tmp" &>/dev/null
  # build yubihsm-shell from source
  #rm -rf yubihsm-shell-$LIBYUBIHSM_VERSION
  #curl -L --max-redirs 2 -o - https://developers.yubico.com/yubihsm-shell/Releases/yubihsm-shell-$LIBYUBIHSM_VERSION.tar.gz |\
  #    tar -xzvf -

  #git clone https://github.com/Yubico/yubihsm-shell.git
  #cp -r /shared/resources/yubihsm-shell .
  #pushd "yubihsm-shell-$LIBYUBIHSM_VERSION" &>/dev/null
  #pushd "yubihsm-shell" &>/dev/null
  #  mkdir build
  #  pushd "build" &>/dev/null
  #    $CMAKE .. -DBUILD_ONLY_LIB=ON
  #    make
  #  popd &>/dev/null
  #popd &>/dev/null

  sudo dnf -y install yubihsm-shell-2.4.1-1.fc38.x86_64.rpm
  sudo dnf -y install yubihsm-devel-2.4.1-1.fc38.x86_64.rpm


  # install yubihsmrs
  rm -rf yubihsmrs
  git clone https://github.com/Yubico/yubihsmrs.git

  # copy and build yubihsm-setup
  rm -rf yubihsm-setup
  git clone "$INPUT" yubihsm-setup
  pushd "yubihsm-setup" &>/dev/null
    cargo install cargo-rpm
    cargo rpm init
    #YUBIHSM_LIB_DIR=/tmp/yubihsm-shell-$LIBYUBIHSM_VERSION/build/lib cargo build --release
    #YUBIHSM_LIB_DIR=/tmp/yubihsm-shell-$LIBYUBIHSM_VERSION/build/lib cargo rpm build
    #YUBIHSM_LIB_DIR=/tmp/yubihsm-shell/build/lib cargo build --release
    #YUBIHSM_LIB_DIR=/tmp/yubihsm-shell/build/lib cargo rpm build
    cargo build --release
    cargo rpm build
    cp target/release/rpmbuild/RPMS/x86_64/*.rpm $OUTPUT
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
    rm -f "yubihsm-setup-$PLATFORM-amd64.tar.gz"
    tar -C ".." -zcvf "../yubihsm-setup-$PLATFORM-amd64.tar.gz" "yubihsm-setup"
    rm -f *.rpm
    rm -rf licenses
    rm -rf ../yubihsm-setup
  popd &>/dev/null
popd &>/dev/null
