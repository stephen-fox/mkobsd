# mkobsd

mkobsd automates the creation of OpenBSD installer ISO images.

It was designed to create unattended installer images by including
an autoinstall file and/or an install.site script and tar set in
the ISO file itself.

## Features

- Easily automates the creation of unattended OpenBSD installer images
  (note: interactive installations are also supported)
- Automatic downloading and verification of original OpenBSD ISO images.
  Original ISOs are stored in a dedicated, configurable directory
- Optionally specify an [autoinstall(7)][autoinstall] configuration file
- Optionally specify an [install.site(58)][install.site] script and
  a directory containing files that will be dropped in `/` at install-time.
  (note: by default, the file ownership is not preserved and `root:wheel`
  is used)

[autoinstall]: https://man.openbsd.org/autoinstall.8
[install.site]: https://man.openbsd.org/install.site.5

## Installation

The preferred method of installation is using `go install` (as this is
a Golang application). This automates downloading and building Go
applications from source in a secure manner. By default, applications
are copied into `~/go/bin/`.

You must first [install Go](https://golang.org/doc/install). After installing
Go, simply run the following commands to install the applications:

```sh
go install gitlab.com/stephen-fox/mkobsd@latest
doas cp ~/go/bin/mkobsd /usr/local/bin/
```

## Examples

Please refer to the [examples](examples) directory.
