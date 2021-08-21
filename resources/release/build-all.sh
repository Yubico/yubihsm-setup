#!/bin/bash

set -e -o pipefail -x

mkdir sources
cd sources
git clone https://github.com/Yubico/yubihsmrs.git

for machine in focal hirsute debian10 fedora33 fedora34 centos7 centos8; do
  vagrant box update $machine
  time vagrant up $machine
  vagrant rsync-back $machine
  set +e
  vagrant destroy -f $machine
  set -e
done

for machine in trusty xenial bionic debian9; do
  vagrant box update $machine
  time vagrant up $machine
  set +e
  vagrant destroy -f $machine
  set -e
done
