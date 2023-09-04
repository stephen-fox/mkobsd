# Unattended installation example

The files in this directory demonstrate how to create an OpenBSD installer
ISO that installs the OS without any user input in a secure manner.

To try this example, do the following:

1. Replace the placeholder SSH public key ending in `buh` with your own in
   [generic/install.site](generic/install.site)
2. Execute [create.sh](create.sh)

## How it works

The [`create.sh`](create.sh) shell script executes `mkobsd` as root
and points it at [`auto_install.conf`](auto_install.conf) and the
[`generic directory`](generic).

The following tree describes how this example works:

```
.
|--- auto_install.conf // Automates the OpenBSD installer's interactive
|                      // questions. Refer to "man 8 autoinstall" for
|                      // more information.
|
|--- create.sh         // A shell script that automates the execution
|                      // of mkobsd. Execute this shell script to
|                      // generate an ISO file for this example.
|
+--- generic          // This directory is a special "file set" that is used
     |                // by install.site(5) to place files and directories
     |                // in the newly-installed OS's root file system.
     |                // This directory is copied into a tar.gz file
     |                // which is untarred just prior to the installer
     |                // rebooting onto "/". Refer to "man 5 install.site"
     |                // for more information.
     |
     |--- usr/local/bin/example.sh // An example shell script that will
     |                             // be copied into /usr/local/bin/ when
     |                             // when the installer finishes.
     |
     |--- etc/adduser.conf // This is a copy of OpenBSD's default
     |                     // /etc/adduser.conf file. This is
     |                     // needed by the adduser(8) program
     |                     // when adding a user non-interactively.
     |
     +--- install.site     // This shell script is automatically
                           // executed by the OpenBSD installer
                           // if it is present in the install.site
                           // siteXX.tar.gz just prior to reboot.
                           // Refer to "man 5 install.site" for
                           // more information.
```
