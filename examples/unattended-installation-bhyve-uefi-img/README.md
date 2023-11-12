# Unattended installation bhyve UEFI img example

The files in this directory demonstrate how to create an OpenBSD installer
img that installs the OS without any user input in a secure manner.
This example is specifically meant to be a FreeBSD bhyve UEFI guest
that loads a img-type installer.

In addition to using autoinstall and install.site automation, it
configures the installer to use `com0` as the tty at build time.
Without this customization, the installer and newly-installed OS
will not write the bhyve serial console.

This example halts the VM's CPU when the installer finishes. It does this
to work around vm-bhyve not "ejecting" the installer.

Here is the [vm-bhyve template](https://github.com/churchers/vm-bhyve):

```
# openbsd-uefi.conf
# vm-bhyve template file.
loader="uefi"
cpu=1
memory=256M
network0_type="virtio-net"
network0_switch="your_network"
disk0_type="virtio-blk"
disk0_name="disk0.img"
bhyve_options="-w"
```

To try this example, do the following:

1. Replace the placeholder SSH public key (the `BUH` string) with your own in
   [generic/install.site](generic/install.site)
2. Execute [create.sh](create.sh)
3. Save the contents of the above snippet in a vm-bhyve template file named
   "openbsd-uefi.conf"
4. Execute `vm create -t openbsd-uefi example`
5. Execute `vm install example example.img`
6. Make sure to restart the VM after it finishes installing the OS.
   This sucks, but there does not appear to be a good way to make
   vm-bhyve "eject" the img installer disk. Stopping the VM process
   with `vm poweroff example` will eject the installer. The install
   automation in this example halts the VM when the installer finishes.
   Without this automation, the VM will reboot back into the installer
   in an endless loop

## How it works

The [`create.sh`](create.sh) shell script executes `mkobsd` as root
and points it at [`auto_install.conf`](auto_install.conf) and the
[`generic directory`](generic).

For a detailed description of the files in this directory, please refer
to the [unattended-installation-iso](../unattended-installation-iso) example.
