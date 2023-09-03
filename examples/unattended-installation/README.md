# Unattended installation example

The files in this directory demonstrate how to create an OpenBSD installer
ISO that installs the OS without any user input in a secure manner.

To try this example, do the following:

1. Replace the placeholder SSH public key ending in `buh` with your own in
   [generic/install.site](generic/install.site)
2. Execute [create.sh](create.sh)

## How it works

The `create.sh` shell script executes `mkobsd` as root. The script points
mkobsd at the following automation:

- An [autoinstall configuration file](auto_install.conf). This tells the
  OpenBSD installer how you would like to customize the OS. Basically, it
  answers all the interactive questions it normally asks you
- An [install.site directory](generic). This directory becomes a tar file
  (known as a "set") that is un-tarred on top of `/` at install-time.
  It contains two things of interest:
  - An `install.site` shell script which, when present, is automatically
    executed when the OS finishes installing prior to reboot
  - Files and directories that are dropped on-top of `/`. For example,
    if you create the path `generic/usr/local/bin/example.sh`, then you
    will find that file in `/usr/local/bin/example.sh` after the installer
    finishes and reboots
