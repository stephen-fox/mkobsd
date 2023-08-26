// mkobsd creates custom OpenBSD ISO images for automated installations.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"gitlab.com/stephen-fox/mkobsd"
)

const (
	appName = "mkobsd"

	helpArg           = "h"
	commandModeArg    = "c"
	isoOutputPathArg  = "o"
	baseDirPathArg    = "b"
	dirPermArg        = "p"
	releaseArg        = "r"
	cpuArchArg        = "a"
	isoMirrorArg      = "m"
	autoinstallArg    = "i"
	installsiteDirArg = "d"
	debugArg          = "D"
	debugVerifyISOArg = "I"
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
	commandMode := flagSet.String(
		commandModeArg,
		"",
		"Optionally execute like a shell command similar to '/bin/sh -c ...'")
	isoOutputPath := flagSet.String(
		isoOutputPathArg,
		"",
		"The file path to save the resulting .iso file to")
	baseDirPath := flagSet.String(
		baseDirPathArg,
		"",
		"Optionally specify the base directory for builds\n"+
			"(defaults to '~/mkobsd' if not specified)")
	baseDirsPerm := filePermFlag{perm: 0755}
	flagSet.Var(
		&baseDirsPerm,
		dirPermArg,
		"The default file mode permission bits for directories\n")
	release := flagSet.String(
		releaseArg,
		"",
		"OpenBSD release version (e.g., '7.2')")
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
		"The path to the autoinstall configuration file (see also:\n"+
			"'man autoinstall')")
	installsiteDirPath := flagSet.String(
		installsiteDirArg,
		"",
		"Optionally specify an install.site directory to be included in the\n"+
			"resulting ISO file. The directory's contents will be placed in a tar\n"+
			"archive and extracted to '/' at install time. If an executable file\n"+
			"named 'install.site' exists at the root of the directory, it will be\n"+
			"executed by the installer (see also: 'man install.site')")
	debug := flagSet.Bool(
		debugArg,
		false,
		"Enable debug mode and step through each stage of the build workflow")
	debugVerifyISO := flagSet.Bool(
		debugVerifyISOArg,
		false,
		"Do not delete OpenBSD .iso if verification fails")

	flagSet.Parse(osArgs[1:])

	if *help {
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	if *commandMode != "" {
		args, err := split(*commandMode)
		if err != nil {
			return err
		}

		temp := []string{osArgs[0]}

		return mainWithError(append(temp, args...))
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

	owner := os.Getuid()
	if owner != 0 {
		return fmt.Errorf("must be root to execute this program (proc uid is: %d)", owner)
	}

	group := os.Getgid()
	if group != 0 {
		return fmt.Errorf("must be root to exexcute this program (proc gid is: %d)", group)
	}

	if *baseDirPath == "" {
		homeDirPath, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		*baseDirPath = filepath.Join(homeDirPath, appName)
	}

	cache := &mkobsd.BuildCache{
		BasePath:       *baseDirPath,
		BaseDirsPerm:   baseDirsPerm.perm,
		HTTPClient:     http.DefaultClient,
		DebugISOVerify: *debugVerifyISO,
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancelFn()

	var beforeFn func(string, map[string]string) error
	var afterFn func(string, map[string]string) error

	if *debug {
		beforeFn = func(s string, info map[string]string) error {
			log.Printf("[%s] start - info: %+v - press enter to continue", s, info)
			fmt.Scanln()
			return nil
		}

		afterFn = func(s string, info map[string]string) error {
			log.Printf("[%s] finished - info: %+v - press enter to continue", s, info)
			fmt.Scanln()
			return nil
		}
	}

	err = cache.BuildISO(ctx, &mkobsd.BuildISOConfig{
		ISOOutputPath:       *isoOutputPath,
		Mirror:              *isoMirror,
		Release:             *release,
		Arch:                *cpuArch,
		AutoinstallFilePath: *autoinstallFilePath,
		InstallsiteDirPath:  *installsiteDirPath,
		BeforeActionFn:      beforeFn,
		AfterActionFn:       afterFn,
	})
	if err != nil {
		return err
	}

	return nil
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
	return fmt.Sprintf("%o | %s", o.perm, o.perm.String())
}

// The following code is copied from Kevin Ballard.
// https://github.com/kballard/go-shellquote.
// See 'LICENSE-THIRD-PARTY.md' for details.
const (
	splitChars        = " \n\t"
	singleChar        = '\''
	doubleChar        = '"'
	escapeChar        = '\\'
	doubleEscapeChars = "$`\"\n\\"
)

// The following code is copied from Kevin Ballard.
// https://github.com/kballard/go-shellquote.
// See 'LICENSE-THIRD-PARTY.md' for details.
//
// Split splits a string according to /bin/sh's word-splitting rules. It
// supports backslash-escapes, single-quotes, and double-quotes. Notably it does
// not support the $” style of quoting. It also doesn't attempt to perform any
// other sort of expansion, including brace expansion, shell expansion, or
// pathname expansion.
//
// If the given input has an unterminated quoted string or ends in a
// backslash-escape, one of UnterminatedSingleQuoteError,
// UnterminatedDoubleQuoteError, or UnterminatedEscapeError is returned.
func split(input string) (words []string, err error) {
	var buf bytes.Buffer
	words = make([]string, 0)

	for len(input) > 0 {
		// skip any splitChars at the start
		c, l := utf8.DecodeRuneInString(input)
		if strings.ContainsRune(splitChars, c) {
			input = input[l:]
			continue
		} else if c == escapeChar {
			// Look ahead for escaped newline so we can skip over it
			next := input[l:]
			if len(next) == 0 {
				err = fmt.Errorf("unterminated backslash-escape")
				return
			}
			c2, l2 := utf8.DecodeRuneInString(next)
			if c2 == '\n' {
				input = next[l2:]
				continue
			}
		}

		var word string
		word, input, err = splitWord(input, &buf)
		if err != nil {
			return
		}
		words = append(words, word)
	}
	return
}

// The following code is copied from Kevin Ballard.
// https://github.com/kballard/go-shellquote.
// See 'LICENSE-THIRD-PARTY.md' for details.
func splitWord(input string, buf *bytes.Buffer) (word string, remainder string, err error) {
	buf.Reset()

raw:
	{
		cur := input
		for len(cur) > 0 {
			c, l := utf8.DecodeRuneInString(cur)
			cur = cur[l:]
			if c == singleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto single
			} else if c == doubleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto double
			} else if c == escapeChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto escape
			} else if strings.ContainsRune(splitChars, c) {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				return buf.String(), cur, nil
			}
		}
		if len(input) > 0 {
			buf.WriteString(input)
			input = ""
		}
		goto done
	}

escape:
	{
		if len(input) == 0 {
			return "", "", fmt.Errorf("unterminated backslash-escape")
		}
		c, l := utf8.DecodeRuneInString(input)
		if c == '\n' {
			// a backslash-escaped newline is elided from the output entirely
		} else {
			buf.WriteString(input[:l])
		}
		input = input[l:]
	}
	goto raw

single:
	{
		i := strings.IndexRune(input, singleChar)
		if i == -1 {
			return "", "", fmt.Errorf("unterminated single-quoted string")
		}
		buf.WriteString(input[0:i])
		input = input[i+1:]
		goto raw
	}

double:
	{
		cur := input
		for len(cur) > 0 {
			c, l := utf8.DecodeRuneInString(cur)
			cur = cur[l:]
			if c == doubleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto raw
			} else if c == escapeChar {
				// bash only supports certain escapes in double-quoted strings
				c2, l2 := utf8.DecodeRuneInString(cur)
				cur = cur[l2:]
				if strings.ContainsRune(doubleEscapeChars, c2) {
					buf.WriteString(input[0 : len(input)-len(cur)-l-l2])
					if c2 == '\n' {
						// newline is special, skip the backslash entirely
					} else {
						buf.WriteRune(c2)
					}
					input = cur
				}
			}
		}
		return "", "", fmt.Errorf("unterminated double-quoted string")
	}

done:
	return buf.String(), input, nil
}
