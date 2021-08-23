#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1
LIBYUBIHSM_VERSION="2.2.0"

if [ "$PLATFORM" == "centos7" ]; then
  sudo yum -y install centos-release-scl
  sudo yum -y update && sudo yum -y upgrade
  sudo yum -y install devtoolset-7-gcc     \
                    devtoolset-7-gcc-c++ \
                    devtoolset-7-make    \
                    chrpath              \
                    git                  \
                    cmake               \
                    gengetopt            \
                    help2man             \
                    libevent-devel       \
                    openssl-devel        \
                    libedit-devel        \
                    libcurl-devel        \
                    libusbx-devel        \
                    libseccomp-devel     \
                    rpm-build            \
                    redhat-rpm-config    \
                    imlib2-devel         \
                    libjpeg-devel        \
                    libpng-devel         \
                    libXt-devel          \
                    libXinerama-devel    \
                    libexif-devel        \
                    perl-Test-Command    \
                    perl-Test-Harness    \
                    clang                \
                    cppcheck             \
                    lcov                 \
                    pcsc-lite-devel

  . /opt/rh/devtoolset-7/enable
  export CMAKE="cmake"

elif [ "$PLATFORM" == "centos8" ]; then
  sudo yum -y install epel-release
  sudo yum -y update && sudo yum -y upgrade

  sudo dnf group -y install "Development Tools"
  sudo dnf config-manager -y --set-enabled powertools

  sudo yum -y install chrpath              \
                    cmake3               \
                    help2man             \
                    libevent-devel       \
                    libedit-devel        \
                    libcurl-devel        \
                    libusbx-devel        \
                    libseccomp-devel     \
                    imlib2-devel         \
                    libjpeg-devel        \
                    libXt-devel          \
                    libXinerama-devel    \
                    perl-Test-Harness    \
                    clang                \
                    golang               \
                    texinfo              \
                    opensp-devel         \
                    openssl-devel        \
                    pcsc-lite-devel

  export CMAKE="cmake3"

elif [ "${PLATFORM:0:6}" == "fedora" ]; then
  sudo dnf -y update
  sudo dnf -y install gcc              \
                    gcc-c++          \
                    binutils         \
                    chrpath          \
                    git              \
                    make             \
                    cmake            \
                    gengetopt        \
                    help2man         \
                    openssl-devel    \
                    libusb-devel     \
                    libevent-devel   \
                    libseccomp-devel \
                    libedit-devel    \
                    libcurl-devel    \
                    rpmdevtools      \
                    imlib2-devel     \
                    libjpeg-devel    \
                    libpng-devel     \
                    libXt-devel      \
                    libXinerama-devel \
                    libexif-devel     \
                    perl-Test-Command \
                    perl-Test-Harness \
                    clang             \
                    cppcheck          \
                    lcov              \
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
  # install yubihsm-shell
  rm -rf yubihsm-shell-$LIBYUBIHSM_VERSION
  curl -L --max-redirs 2 -o - https://developers.yubico.com/yubihsm-shell/Releases/yubihsm-shell-$LIBYUBIHSM_VERSION.tar.gz |\
      tar -xzvf -
  pushd "yubihsm-shell-$LIBYUBIHSM_VERSION" &>/dev/null
    mkdir build; cd build
    $CMAKE .. -DBUILD_ONLY_LIB=ON
    make
  popd &>/dev/null

  # install yubihsmrs
  rm -rf yubihsmrs
  git clone https://github.com/Yubico/yubihsmrs.git

  # copy and build yubihsm-setup
  rm -rf yubihsm-setup
  git clone "$INPUT" yubihsm-setup
  pushd "yubihsm-setup" &>/dev/null
    cargo install cargo-rpm
    cargo rpm init
    YUBIHSM_LIB_DIR=/tmp/yubihsm-shell-$LIBYUBIHSM_VERSION/build/lib cargo build --release
    YUBIHSM_LIB_DIR=/tmp/yubihsm-shell-$LIBYUBIHSM_VERSION/build/lib cargo rpm build
    cp target/release/rpmbuild/RPMS/x86_64/*.rpm $OUTPUT
  popd &>/dev/null
popd &>/dev/null

pushd "/shared" &>/dev/null
  cp -r resources/release/licenses "$OUTPUT/"
  for lf in $OUTPUT/licenses/*; do
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