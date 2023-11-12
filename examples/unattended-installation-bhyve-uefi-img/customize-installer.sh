#!/bin/sh

set -eu

# MKOBSD_WORK_DIR will be set to the new installer's directory.
#
# Note: Without this boot directive, the installer will not
# write to the bhyve's serial console.
echo "set tty com0" >> "${MKOBSD_WORK_DIR}/etc/boot.conf"
