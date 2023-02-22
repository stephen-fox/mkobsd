// mkobsd creates custom OpenBSD ISO images for automated installations.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
)

const (
	appName = "mkobsd"

	helpArg        = "h"
	commandModeArg = "c"
	baseDirPathArg = "b"
	releaseArg     = "r"
	cpuArchArg     = "a"
	isoMirrorArg   = "m"
	debugArg       = "d"
)

func main() {
	log.SetFlags(0)

	err := mainWithError(os.Args)
	if err != nil {
		log.Fatalln("error:", err)
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
	baseDirPath := flagSet.String(
		baseDirPathArg,
		"",
		"Optionally specify the base directory for builds\n"+
			"(defaults to '~/mkobsd' is not specified)")
	release := flagSet.String(
		releaseArg,
		"",
		"OpenBSD release number (e.g., '7.2')")
	cpuArch := flagSet.String(
		cpuArchArg,
		"",
		"Target CPU architecture (e.g., 'amd64')")
	isoMirror := flagSet.String(
		isoMirrorArg,
		"https://cdn.openbsd.org/pub/OpenBSD",
		"OpenBSD mirror URL")
	debug := flagSet.Bool(
		debugArg,
		false,
		"Enable debug mode")

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
				f.Name, f.Usage)
		}
	})
	if err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("must be root execute this program")
	}

	if *baseDirPath == "" {
		homeDirPath, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		*baseDirPath = filepath.Join(homeDirPath, appName)
	}

	cache := &buildCache{
		BasePath:   *baseDirPath,
		HTTPClient: http.DefaultClient,
		Debug:      *debug,
	}

	err = cache.setup()
	if err != nil {
		return fmt.Errorf("failed to setup cache - %w", err)
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancelFn()

	isoPath, err := cache.buildISO(ctx, &isoConfig{
		Mirror:  *isoMirror,
		Release: *release,
		Arch:    *cpuArch,
	})
	if err != nil {
		return err
	}

	log.Println(isoPath)

	return nil
}

type buildCache struct {
	BasePath      string
	HTTPClient    *http.Client
	Debug         bool
	dlcDirPath    string
	buiildDirPath string
}

func (o *buildCache) setup() error {
	if !filepath.IsAbs(o.BasePath) {
		return fmt.Errorf("base path is not absolute ('%s')", o.BasePath)
	}

	info, err := os.Stat(o.BasePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	if !info.IsDir() {
		return errors.New("base path is a file (it should be a directory")
	}

	o.dlcDirPath = filepath.Join(o.BasePath, "/downloads")
	o.buiildDirPath = filepath.Join(o.BasePath, "/build")

	err = os.MkdirAll(o.dlcDirPath, 0700)
	if err != nil {
		return err
	}

	err = os.MkdirAll(o.buiildDirPath, 0700)
	if err != nil {
		return err
	}

	return nil
}

func (o *buildCache) buildISO(ctx context.Context, config *isoConfig) (string, error) {
	// Check if we already have the built iso.
	buildConfigHash, err := config.buildConfigHash()
	if err != nil {
		return "", err
	}

	buildDirPath := filepath.Join(o.buiildDirPath, buildConfigHash)

	isoFilePath := filepath.Join(buildDirPath, fmt.Sprintf("openbsd-%s-%s.iso",
		config.Release, config.Arch))

	info, err := os.Stat(isoFilePath)
	if err == nil {
		if info.IsDir() {
			return "", fmt.Errorf("iso path is a directory: '%s'", isoFilePath)
		}

		return isoFilePath, nil
	}

	newISODirPath, err := o.extractOpenbsdISO(ctx, buildDirPath, openbsdSrcFilesConfig{
		Mirror:  config.Mirror,
		Release: config.Release,
		Arch:    config.Arch,
	})
	if err != nil {
		return "", fmt.Errorf("failed to extract openbsd iso - %w", err)
	}
	if !o.Debug {
		defer os.RemoveAll(newISODirPath)
	}

	rdFilePath := filepath.Join(newISODirPath, config.Release, config.Arch, "bsd.rd")

	unmapRDFn, err := mapRAMDisk(ctx, rdFilePath, buildDirPath)
	if err != nil {
		return "", fmt.Errorf("failed to map ram disk - %w", err)
	}
	defer unmapRDFn(context.Background())

	err = unmapRDFn(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to un-map rd - %w", err)
	}

	const mkhybridPath = "/usr/sbin/mkhybrid"
	relArch := config.Release + "/" + config.Arch
	volumeID := "OpenBSD/" + config.Arch + " " + config.Release + " Install CD"

	mkhybrid := exec.CommandContext(
		ctx,
		mkhybridPath,
		"-a", "-R", "-T", "-L", "-l", "-d", "-D", "-N",
		"-o", isoFilePath,
		"-v", "-v",
		"-A", volumeID,
		"-P", "Copyright (c) Theo de Raadt <deraadt@openbsd.org>",
		"-V", volumeID,
		"-b", relArch+"/cbr",
		"-c", relArch+"/boot.catalog",
		newISODirPath)

	out, err := mkhybrid.CombinedOutput()
	if err != nil {
		_ = os.Remove(isoFilePath)
		return "", fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			mkhybrid.String(), err, out)
	}

	return isoFilePath, nil
}

type isoConfig struct {
	Mirror            string
	Release           string
	Arch              string
	Hostname          string
	DNSDomainName     string
	RootUserSSHPubKey string
	SetNames          string
}

func (o *isoConfig) buildConfigHash() (string, error) {
	sha512Hash := sha512.New()

	_, err := sha512Hash.Write([]byte(o.Release))
	if err != nil {
		return "", err
	}

	_, err = sha512Hash.Write([]byte(o.Arch))
	if err != nil {
		return "", err
	}

	_, err = sha512Hash.Write([]byte(o.Hostname))
	if err != nil {
		return "", err
	}

	_, err = sha512Hash.Write([]byte(o.DNSDomainName))
	if err != nil {
		return "", err
	}

	_, err = sha512Hash.Write([]byte(o.RootUserSSHPubKey))
	if err != nil {
		return "", err
	}

	_, err = sha512Hash.Write([]byte(o.SetNames))
	if err != nil {
		return "", err
	}

	return string(sha512Hash.Sum(nil)), nil
}

func (o *buildCache) extractOpenbsdISO(ctx context.Context, buildDirPath string, filesConfig openbsdSrcFilesConfig) (string, error) {
	baseISOMountPath := filepath.Join(buildDirPath, "base-iso")

	err := os.MkdirAll(baseISOMountPath, 0700)
	if err != nil {
		return "", fmt.Errorf("failed to create base openbsd iso mount dir '%s' - %w",
			baseISOMountPath, err)
	}
	defer os.Remove(baseISOMountPath)

	baseISOPath, err := o.openbsdISO(ctx, filesConfig)
	if err != nil {
		return "", fmt.Errorf("failed to get openbsd iso - %w", err)
	}

	vndID, unconfigFn, err := allocateVNDForFile(ctx, baseISOPath)
	if err != nil {
		return "", fmt.Errorf("failed to allocate vnd for '%s' - %w",
			baseISOPath, err)
	}
	defer unconfigFn(context.Background())

	vndPath := "/dev/" + vndID

	unmountFn, err := mount(
		ctx,
		[]string{"-t", "cd9660"},
		vndPath+"c", baseISOMountPath)
	if err != nil {
		return "", fmt.Errorf("failed to mount base openbsd iso vnd '%s' to '%s' - %w",
			vndPath, baseISOMountPath, err)
	}
	defer unmountFn(context.Background())

	newISOContentsPath := filepath.Join(buildDirPath, "new-iso")

	err = os.MkdirAll(newISOContentsPath, 0700)
	if err != nil {
		return "", fmt.Errorf("failed to create new iso dir '%s' - %w",
			newISOContentsPath, err)
	}

	cpISO := exec.CommandContext(
		ctx,
		"/bin/cp",
		"-Rp",
		baseISOMountPath+"/.",
		newISOContentsPath)
	out, err := cpISO.CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(newISOContentsPath)
		return "", fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			cpISO.String(), err, out)
	}

	return newISOContentsPath, nil
}

func (o *buildCache) openbsdISO(ctx context.Context, config openbsdSrcFilesConfig) (string, error) {
	dirPath := filepath.Join(o.dlcDirPath, config.Arch, config.Release)
	isoPath := filepath.Join(o.dlcDirPath, config.isoName())
	sha256SigPath := filepath.Join(dirPath, config.sha256SigName())

	verifyConfig := signifyVerifyConfig{
		PubKeyPath:       "/etc/signify/openbsd-" + config.releaseID() + "-base.pub",
		DotSigPath:       sha256SigPath,
		FileNameToVerify: config.isoName(),
	}

	err := signifyVerify(ctx, verifyConfig)
	if err == nil {
		return isoPath, nil
	}

	if errors.Is(err, context.Canceled) {
		return "", ctx.Err()
	}

	err = os.MkdirAll(dirPath, 0700)
	if err != nil {
		return "", err
	}

	err = httpGetToFilePath(ctx, o.HTTPClient, config.sha256SigUrl(), sha256SigPath)
	if err != nil {
		return "", err
	}

	err = httpGetToFilePath(ctx, o.HTTPClient, config.isoUrl(), isoPath)
	if err != nil {
		return "", err
	}

	err = signifyVerify(ctx, verifyConfig)
	if err != nil {
		_ = os.Remove(isoPath)
		return "", err
	}

	return isoPath, nil
}

type openbsdSrcFilesConfig struct {
	Mirror  string
	Release string
	Arch    string
}

func (o openbsdSrcFilesConfig) isoUrl() string {
	return o.Mirror + "/" + o.Release + "/" + o.Arch + "/" + o.isoName()
}

func (o openbsdSrcFilesConfig) isoName() string {
	return "install" + strings.ReplaceAll(o.Release, ".", "") + ".iso"
}

func (o openbsdSrcFilesConfig) sha256SigUrl() string {
	return o.Mirror + "/" + o.Release + "/" + o.Arch + "/" + o.sha256SigName()
}

func (o openbsdSrcFilesConfig) sha256SigName() string {
	return "SHA256.sig"
}

func (o openbsdSrcFilesConfig) signnifyPubKeyPath() string {
	return fmt.Sprintf("/etc/signify/openbsd-%s-base.pub", o.releaseID())
}

func (o openbsdSrcFilesConfig) releaseID() string {
	return strings.ReplaceAll(o.Release, ".", "")
}

type signifyVerifyConfig struct {
	PubKeyPath       string
	DotSigPath       string
	FileNameToVerify string
}

func signifyVerify(ctx context.Context, config signifyVerifyConfig) error {
	signify := exec.CommandContext(ctx, "/usr/bin/signify",
		"-C",
		"-p", config.PubKeyPath,
		"-x", config.DotSigPath,
		config.FileNameToVerify)

	signify.Dir = filepath.Dir(config.DotSigPath)

	out, err := signify.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute '%s' - %w - output: %s",
			signify.String(), err, out)
	}

	return nil
}

func httpGetToFilePath(ctx context.Context, client *http.Client, urlStr string, toPath string) error {
	f, err := os.OpenFile(toPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 300 {
		return fmt.Errorf("http response is not 200 - got %d",
			resp.StatusCode)
	}

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func mapRAMDisk(ctx context.Context, rdFilePath string, buildDirPath string) (func(context.Context) error, error) {
	isCompressed, err := gzipDecompressIfNeeded(ctx, rdFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to check / decompress ramdisk - %w", err)
	}

	diskFSPath := filepath.Join(buildDirPath, "rd-disk-fs")

	// Create an empty file for rdsetroot.
	err = os.WriteFile(diskFSPath, nil, 0600)
	if err != nil {
		return nil, err
	}

	rdMountDirPath := filepath.Join(buildDirPath, "rd-mnt")

	err = os.MkdirAll(rdMountDirPath, 0700)
	if err != nil {
		return nil, err
	}

	const rdsetrootPath = "/usr/sbin/rdsetroot"

	rdsetrootExtract := exec.CommandContext(ctx, rdsetrootPath,
		"-x", rdFilePath,
		diskFSPath)

	out, err := rdsetrootExtract.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			rdsetrootExtract.String(), err, out)
	}

	vndID, unconfigureFn, err := allocateVNDForFile(ctx, diskFSPath)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate vnd for ram disk - %w", err)
	}

	vndPath := "/dev/" + vndID + "a"

	umountFn, err := mount(ctx, nil, vndPath, rdMountDirPath)
	if err != nil {
		_ = unconfigureFn(context.Background())
		return nil, fmt.Errorf("failed to mount ram disk - %w", err)
	}

	once := &sync.Once{}

	return func(ctx context.Context) error {
		var needsDone bool

		once.Do(func() {
			needsDone = true
		})

		if !needsDone {
			return nil
		}

		defer unconfigureFn(ctx)
		defer umountFn(ctx)

		err = umountFn(ctx)
		if err != nil {
			return fmt.Errorf("failed to unmount ram disk - %w", err)
		}

		err = unconfigureFn(ctx)
		if err != nil {
			return fmt.Errorf("failed to unconfigure ram disk vnd - %w", err)
		}

		rdsetrootInsert := exec.CommandContext(ctx,
			rdsetrootPath,
			rdFilePath,
			diskFSPath)

		out, err := rdsetrootInsert.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
				rdsetrootInsert.String(), err, out)
		}

		if isCompressed {
			err = gzipCompress(rdFilePath)
			if err != nil {
				return fmt.Errorf("failed to gzip compress ram disk - %w", err)
			}
		}

		return nil
	}, nil
}

func gzipDecompressIfNeeded(ctx context.Context, targetPath string) (bool, error) {
	const filePath = "/usr/bin/file"

	file := exec.CommandContext(ctx, filePath, targetPath)

	out, err := file.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			file.String(), err, out)
	}

	if !bytes.Contains(out, []byte("gzip compressed data")) {
		return false, nil
	}

	rd, err := os.OpenFile(targetPath, os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	defer rd.Close()

	rdCompressed, err := io.ReadAll(rd)
	if err != nil {
		return false, err
	}

	_, err = rd.Seek(0, io.SeekStart)
	if err != nil {
		return false, err
	}

	err = rd.Truncate(0)
	if err != nil {
		return false, err
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(rdCompressed))
	if err != nil {
		return false, err
	}
	defer gzipReader.Close()

	_, err = io.Copy(rd, gzipReader)
	if err != nil {
		return false, fmt.Errorf("failed to decompress ramdisk - %w", err)
	}

	return true, nil
}

func gzipCompress(filePath string) error {
	rd, err := os.OpenFile(filePath, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer rd.Close()

	rdUncompressed, err := io.ReadAll(rd)
	if err != nil {
		return err
	}

	_, err = rd.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	err = rd.Truncate(0)
	if err != nil {
		return err
	}

	gzipWriter := gzip.NewWriter(rd)

	_, err = io.Copy(gzipWriter, bytes.NewReader(rdUncompressed))
	if err != nil {
		return fmt.Errorf("failed to compress ramdisk - %w", err)
	}
	defer gzipWriter.Close()

	err = gzipWriter.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush gzip writer - %w", err)
	}

	return nil
}

func allocateVNDForFile(ctx context.Context, filePath string) (string, func(context.Context) error, error) {
	const vnconfigPath = "/sbin/vnconfig"

	vnconfig := doasOrNormalExecCmd(ctx, vnconfigPath, filePath)

	stderr := bytes.NewBuffer(nil)
	vnconfig.Stderr = stderr
	stdout := bytes.NewBuffer(nil)
	vnconfig.Stdout = stdout

	err := vnconfig.Run()
	if err != nil {
		return "", nil, fmt.Errorf("failed to execute '%s' - %w - stderr: '%s'",
			vnconfig.String(), err, stderr.String())
	}

	idRaw := bytes.TrimSpace(stdout.Bytes())
	if len(idRaw) == 0 {
		return "", nil, fmt.Errorf("vnconfig's stdout does not contain a vnode device ID")
	}

	id := string(idRaw)

	once := &sync.Once{}

	return id, func(ctx context.Context) error {
		var err error

		once.Do(func() {
			vnconfigU := doasOrNormalExecCmd(ctx, vnconfigPath, "-u", id)

			var out []byte
			out, err = vnconfigU.CombinedOutput()
			if err != nil {
				err = fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
					vnconfigU.String(), err, out)
			}
		})

		return err
	}, nil
}

func mount(ctx context.Context, additionalArgs []string, srcPath string, dstPath string) (func(context.Context) error, error) {
	const mountPath = "/sbin/mount"

	args := make([]string, len(additionalArgs)+2)

	for i := range additionalArgs {
		args[i] = additionalArgs[i]
	}

	args[len(args)-2] = srcPath
	args[len(args)-1] = dstPath

	mount := doasOrNormalExecCmd(ctx, mountPath, args...)

	out, err := mount.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			mount.String(), err, out)
	}

	once := &sync.Once{}

	return func(ctx context.Context) error {
		var err error

		once.Do(func() {
			const umountPath = "/sbin/umount"

			umount := doasOrNormalExecCmd(ctx, umountPath, dstPath)

			var out []byte
			out, err = umount.CombinedOutput()
			if err != nil {
				err = fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
					umount.String(), err, out)
			}

		})

		return err
	}, nil
}

func doasOrNormalExecCmd(ctx context.Context, exe string, args ...string) *exec.Cmd {
	var app *exec.Cmd

	if os.Geteuid() == 0 {
		app = exec.CommandContext(ctx, exe, args...)
	} else {
		const doasPath = "/usr/bin/doas"
		app = exec.CommandContext(ctx,
			doasPath,
			append([]string{exe}, args...)...)
	}

	return app
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
