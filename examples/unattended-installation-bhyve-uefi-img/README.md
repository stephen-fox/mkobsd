# Unattended installation example

The files in this directory demonstrate how to create an OpenBSD installer
img that installs the OS without any user input in a secure manner.
This example is specifically meant to be a FreeBSD bhyve UEFI guest
that loads a img-type installer as a second virtio-blk device.
Here is the [vm-bhyve configuration](https://github.com/churchers/vm-bhyve):

```
loader="uefi"
cpu=1
memory=256M
network0_type="virtio-net"
network0_switch="your_network"
disk0_type="virtio-blk"
disk0_name="disk0.img"
disk1_type="virtio-blk"
disk1_name="example-7.3-amd64.img"
bhyve_options="-w"
```

To try this example, do the following:

1. Replace the placeholder SSH public key (the `BUH` string) with your own in
   [generic/install.site](generic/install.site)
2. Execute [create.sh](create.sh)

## How it works

The [`create.sh`](create.sh) shell script executes `mkobsd` as root
and points it at [`auto_install.conf`](auto_install.conf) and the
[`generic directory`](generic).

For a detailed description of the files in this directory, please refer
to the [unattended-installation-iso](../unattended-installation-iso) example.
