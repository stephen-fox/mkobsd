// mkobsd automates the creation of OpenBSD installer ISO images.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"gitlab.com/stephen-fox/mkobsd/internal/advhelp"
	"gitlab.com/stephen-fox/mkobsd/internal/mkobsd"
)

const (
	appName = "mkobsd"
	usage   = appName + `

SYNOPSIS
  ` + appName + ` [options] -` + releaseArg + ` <release> -` + cpuArchArg + ` <arch> -` + isoOutputPathArg + ` </path/to/new.iso>

DESCRIPTION
  ` + appName + ` automates the creation of OpenBSD installer ISO images.

  It was designed to create unattended installer images by including
  an autoinstall file and/or an install.site script and tar set in
  the ISO file itself.

EXAMPLES
  For examples, please execute: ` + appName + ` -` + advHelpArg + `

SEE ALSO
  autoinstall(8), install.site(5)

OPTIONS
`

	advHelpDoc = appName + "\n\n" + advhelp.Usage

	helpArg               = "h"
	advHelpArg            = "H"
	isoOutputPathArg      = "o"
	baseDirPathArg        = "B"
	releaseArg            = "r"
	cpuArchArg            = "a"
	isoMirrorArg          = "m"
	autoinstallArg        = "i"
	installsiteDirArg     = "d"
	preserveSiteTarIDsArg = "P"
	logTimestampsArg      = "t"
	debugArg              = "D"
	debugVerifyISOArg     = "K"

	debugEnvName = "MKOBSD_DEBUG"

	defaultBaseDirPath = "/home/_" + appName
)

func main() {
	log.SetFlags(0)

	err := mainWithError(os.Args)
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError(osArgs []string) error {
	flagSet := flag.NewFlagSet(osArgs[0], flag.ExitOnError)

	help := flagSet.Bool(
		helpArg,
		false,
		"Display this information")
	advHelp := flagSet.Bool(
		advHelpArg,
		false,
		"Display advanced usage information and examples")
	isoOutputPath := flagSet.String(
		isoOutputPathArg,
		"",
		"The file path to save the resulting .iso file to")
	baseDirPath := flagSet.String(
		baseDirPathArg,
		defaultBaseDirPath,
		"The base directory for builds")
	release := flagSet.String(
		releaseArg,
		"",
		"OpenBSD release version (e.g., '7.3')")
	cpuArch := flagSet.String(
		cpuArchArg,
		"",
		"Target CPU architecture (e.g., 'amd64')")
	isoMirror := flagSet.String(
		isoMirrorArg,
		"https://cdn.openbsd.org/pub/OpenBSD",
		"OpenBSD mirror URL")
	autoinstallFilePath := flagSet.String(
		autoinstallArg,
		"",
		"Optionally provide the path to an autoinstall(8) configuration file\n"+
			"to include in the ISO")
	installsiteDirPath := flagSet.String(
		installsiteDirArg,
		"",
		"Optionally specify an install.site(5) directory to be included in the\n"+
			"resulting ISO file. The directory's contents will be placed in a tar\n"+
			"archive and extracted to '/' at install time. If an executable file\n"+
			"named 'install.site' exists at the root of the directory, it will be\n"+
			"executed by the installer")
	preserveSiteTarIDs := flagSet.Bool(
		preserveSiteTarIDsArg,
		false,
		"Preserve UID and GIDs of the install.site directory when creating a tar.\n"+
			"If unspecified, root:wheel is used")
	logTimestamps := flagSet.Bool(
		logTimestampsArg,
		false,
		"Include timestamps in log messages")
	debug := flagSet.Bool(
		debugArg,
		false,
		"Enable debug mode. This allows the user to step through each\nstage of the build workflow. May also be enabled by setting\n"+
			"the '"+debugEnvName+"' environment variable to 'true'")
	debugVerifyISO := flagSet.Bool(
		debugVerifyISOArg,
		false,
		"Do not delete original OpenBSD .iso if verification fails")

	flagSet.Parse(osArgs[1:])

	if *help {
		_, _ = os.Stderr.WriteString(usage)
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	if *advHelp {
		_, _ = os.Stderr.WriteString(advHelpDoc)
		os.Exit(1)
	}

	var err error

	flagSet.VisitAll(func(f *flag.Flag) {
		if err != nil {
			return
		}

		if f.Value.String() == "" && !strings.HasPrefix(f.Usage, "Optional") {
			err = fmt.Errorf("please specify '-%s' - %s",
				f.Name, strings.ReplaceAll(f.Usage, "\n", " "))
		}
	})
	if err != nil {
		return err
	}

	if os.Getenv(debugEnvName) == "true" {
		*debug = true
	}

	if *logTimestamps {
		log.SetFlags(log.Flags() | log.Ldate | log.Ltime)
	}

	owner := os.Getuid()
	if owner != 0 {
		return fmt.Errorf("must be root to execute this program (proc uid is: %d)", owner)
	}

	group := os.Getgid()
	if group != 0 {
		return fmt.Errorf("must be root to exexcute this program (proc gid is: %d)", group)
	}

	cache := &mkobsd.BuildCache{
		BasePath:       *baseDirPath,
		DebugISOVerify: *debugVerifyISO,
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancelFn()

	var beforeFn func(string, map[string]string) error
	var afterFn func(string, map[string]string) error

	if *debug {
		beforeFn = func(s string, info map[string]string) error {
			log.Printf("[%s] start - info: %+v - press enter to continue", s, info)
			err := readNewlineCtx(ctx)
			if err != nil {
				return err
			}
			return nil
		}

		afterFn = func(s string, info map[string]string) error {
			log.Printf("[%s] finished - info: %+v - press enter to continue", s, info)
			err := readNewlineCtx(ctx)
			if err != nil {
				return err
			}
			return nil
		}
	} else {
		beforeFn = func(s string, _ map[string]string) error {
			log.Printf("[%s] start", s)
			return nil
		}

		afterFn = func(s string, _ map[string]string) error {
			log.Printf("[%s] finished", s)
			return nil
		}
	}

	err = cache.BuildISO(ctx, &mkobsd.BuildISOConfig{
		ISOOutputPath:          *isoOutputPath,
		Mirror:                 *isoMirror,
		Release:                *release,
		Arch:                   *cpuArch,
		OptAutoinstallFilePath: *autoinstallFilePath,
		OptInstallsiteDirPath:  *installsiteDirPath,
		PreserveSiteTarIDs:     *preserveSiteTarIDs,
		OptBeforeActionFn:      beforeFn,
		OptAfterActionFn:       afterFn,
	})
	if err != nil {
		return fmt.Errorf("failed to build iso - %w", err)
	}

	return nil
}

func readNewlineCtx(ctx context.Context) error {
	newline := make(chan error, 1)

	go func() {
		_, err := fmt.Scanln()
		newline <- err
	}()

	select {
	case <-ctx.Done():
		os.Stdin.Close()

		return ctx.Err()
	case err := <-newline:
		if err != nil {
			return err
		}

		return nil
	}
}

type filePermFlag struct {
	perm fs.FileMode
}

func (o *filePermFlag) Set(v string) error {
	i, err := strconv.ParseUint(v, 8, 32)
	if err != nil {
		return err
	}

	o.perm = fs.FileMode(uint32(i))

	return nil
}

func (o *filePermFlag) String() string {
	return fmt.Sprintf("0o%o | %s", o.perm, o.perm.String())
}
