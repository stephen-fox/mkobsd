# mkobsd

mkobsd automates the creation of OpenBSD installer ISO images.

It was designed to create unattended installer images by including
an autoinstall file and/or an install.site script and tar set in
the ISO file itself.

## Features

- Automates the creation of unattended OpenBSD installer images
  (note: interactive installations are also supported)
- Automatic downloading and verification of original OpenBSD ISO images.
  Original ISOs are cached in a configurable directory to improve build
  times and are re-verified on each build
- Downloading and verification of the original OpenBSD ISO are carried
  out by `ftp(1)` and `signify(1)` as a non-root user. Both applications
  implement `pledge(2)`, adding a meaningful security barrier between
  mkobsd and unverified data
- Optionally specify an [autoinstall(8)][autoinstall] configuration file
  to be included in the new ISO
- Optionally specify an [install.site(5)][install.site] script and
  a directory containing files that will be dropped in `/` at install-time
  (note: by default, file ownership is not preserved and `root:wheel`
  is used)

[autoinstall]: https://man.openbsd.org/autoinstall.8
[install.site]: https://man.openbsd.org/install.site.5

## Requirements

- An OpenBSD system (the application can be compiled on any OS, but it
  relies on tools included with OpenBSD)
- Go (Golang)
- Must be run as `root` (sadly, it needs to do too many things as root)

## Installation

The preferred method of installation is using `go install` (as this is
a Golang application). This automates downloading and building Go
applications from source in a secure manner. By default, applications
are copied into `~/go/bin/`.

You must first [install Go](https://golang.org/doc/install). If you are
compiling the application on OpenBSD, you can install Go by executing:

```sh
doas pkg_add go
```

After installing Go, run the following commands to install the application:

```sh
go install gitlab.com/stephen-fox/mkobsd@latest
doas cp ~/go/bin/mkobsd /usr/local/bin/
```

## Examples

Please refer to the [examples](examples) directory.

## For new OpenBSD users

If you are new to OpenBSD, I recommend reading the [About OpenBSD][about]
page. OpenBSD is a minimalistic operating system focused on simplicity and
security. The installation workflow and its customization are documented in
the [Overview of the Installation Procedure FAQ][installation].

Installation is normally accomplished using interactive text prompts.
mkobsd makes it easy to automate these interactive prompts and/or
supplement the default installer behavior with automation.

[about]: https://www.openbsd.org/faq/faq1.html#WhatIs
[installation]: https://www.openbsd.org/faq/faq4.html#bsd.rd

## Troubleshooting

The `-D` option enables debug mode, which is very useful for troubleshooting.
In debug mode, mkobsd will pause after executing each stage of the build.
This allows users to inspect the build directory and files as the build
runs. Additional information about the build is provided in log messages.

## Special thanks

This project was heavily inspired by Tim Baumgard's
[openbsd-custom-image](https://github.com/tbaumgard/openbsd-custom-image)
project. Thank you, Tim.

A lorge thank you to [Seung Kang](https://github.com/SeungKang) for reading
over the project's documentation and providing feedback. Seung also tested
an image produced by the application. Thank you Seung <3
