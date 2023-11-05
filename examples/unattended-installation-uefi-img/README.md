# Unattended installation example

The files in this directory demonstrate how to create an OpenBSD installer
img that installs the OS without any user input in a secure manner.
This example is specifically meant to be a FreeBSD bhyve UEFI guest.

To try this example, do the following:

1. Replace the placeholder SSH public key (the `BUH` string) with your own in
   [generic/install.site](generic/install.site)
2. Execute [create.sh](create.sh)

## How it works

The [`create.sh`](create.sh) shell script executes `mkobsd` as root
and points it at [`auto_install.conf`](auto_install.conf) and the
[`generic directory`](generic).

For a detailed description of the files in this directory, please refer
to the other [unattended-installation](../unattended-installation) example.
