#!/bin/sh

set -u

dir_path="$(realpath $(dirname "${0}"))"

arch=amd64
version=7.3

doas mkobsd \
  -o "${dir_path}/example-${version}-${arch}.img" \
  -t "img" \
  -a ${arch} \
  -r ${version} \
  -i "${dir_path}/auto_install.conf" \
  -d "${dir_path}/generic" \
  -x "${dir_path}/customize-installer.sh"
