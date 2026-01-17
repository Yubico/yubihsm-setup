Name:           yubihsm-setup
Version:        2.3.3
Release:        1%{?dist}
Summary:        Command line tool for YubiHSM 2
License:        Apache-2.0
URL:            https://github.com/Yubico/yubihsm-setup

%description
Command line tool for YubiHSM 2

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 $BIN_DIR/yubihsm-setup %{buildroot}/usr/bin/yubihsm-setup

%files
/usr/bin/yubihsm-setup

%changelog
* Mon Nov 03 2025 Your Name <your@email.com> - 2.3.3-1
- Build on Fedora 43