#!/bin/bash

set -e -o pipefail -x

for machine in focal impish jammy debian10 debian11 fedora35 fedora36 centos7; do
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
