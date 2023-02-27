// mkobsd creates custom OpenBSD ISO images for automated installations.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
)

const (
	appName = "mkobsd"

	helpArg           = "h"
	commandModeArg    = "c"
	baseDirPathArg    = "b"
	dirPermArg        = "p"
	releaseArg        = "r"
	cpuArchArg        = "a"
	isoMirrorArg      = "m"
	autoinstallArg    = "i"
	installsiteDirArg = "d"
	debugArg          = "D"
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
				f.Name, strings.ReplaceAll(f.Usage, "\n", " "))
		}
	})
	if err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("must be root to execute this program")
	}

	if *baseDirPath == "" {
		homeDirPath, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		*baseDirPath = filepath.Join(homeDirPath, appName)
	}

	cache := &buildCache{
		BasePath:     *baseDirPath,
		BaseDirsPerm: baseDirsPerm.perm,
		HTTPClient:   http.DefaultClient,
		Debug:        *debug,
	}

	err = cache.setup()
	if err != nil {
		return fmt.Errorf("failed to setup cache - %w", err)
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancelFn()

	isoPath, err := cache.buildISO(ctx, &isoConfig{
		Mirror:              *isoMirror,
		Release:             *release,
		Arch:                *cpuArch,
		AutoinstallFilePath: *autoinstallFilePath,
		InstallsiteDirPath:  *installsiteDirPath,
	})
	if err != nil {
		return err
	}

	log.Println(isoPath)

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

type buildCache struct {
	BasePath      string
	BaseDirsPerm  fs.FileMode
	HTTPClient    *http.Client
	Debug         bool
	dlcDirPath    string
	buiildDirPath string
}

func (o *buildCache) setup() error {
	if !filepath.IsAbs(o.BasePath) {
		return fmt.Errorf("base path is not absolute ('%s')", o.BasePath)
	}

	if o.BaseDirsPerm == 0 {
		return errors.New("base directory permissions not set")
	}

	_, baseInfo, err := pathExists(o.BasePath)
	if err != nil {
		return err
	}

	if baseInfo != nil && !baseInfo.IsDir() {
		return errors.New("base path is a file (it should be a directory")
	}

	o.dlcDirPath = filepath.Join(o.BasePath, "/downloads")
	o.buiildDirPath = filepath.Join(o.BasePath, "/build")

	err = os.MkdirAll(o.dlcDirPath, o.BaseDirsPerm)
	if err != nil {
		return err
	}

	err = os.MkdirAll(o.buiildDirPath, o.BaseDirsPerm)
	if err != nil {
		return err
	}

	return nil
}

func (o *buildCache) buildISO(ctx context.Context, config *isoConfig) (string, error) {
	err := config.validate()
	if err != nil {
		return "", fmt.Errorf("failed to validate iso config - %w", err)
	}

	// Check if we already have the built iso.
	buildConfigHash, err := config.buildConfigHash()
	if err != nil {
		return "", err
	}

	buildDirPath := filepath.Join(o.buiildDirPath, buildConfigHash)

	isoFilePath := filepath.Join(buildDirPath, fmt.Sprintf("openbsd-%s-%s.iso",
		config.Release, config.Arch))

	isoExists, isoInfo, _ := pathExists(isoFilePath)
	if isoExists {
		if isoInfo.IsDir() {
			return "", fmt.Errorf("iso path is a directory: '%s'", isoFilePath)
		}

		return isoFilePath, nil
	}

	err = os.MkdirAll(buildDirPath, o.BaseDirsPerm)
	if err != nil {
		return "", err
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

	rdMountDirPath, unmapRDFn, err := mapRAMDisk(ctx, rdFilePath, buildDirPath)
	if err != nil {
		return "", fmt.Errorf("failed to map ram disk - %w", err)
	}
	defer unmapRDFn(context.Background())

	err = o.copyInstallAutomation(ctx, copyInstallAutomationConfig{
		ISOConfig:  config,
		ISODirPath: newISODirPath,
		RDDirPath:  rdMountDirPath,
	})
	if err != nil {
		return "", fmt.Errorf("failed to copy installer automation - %w", err)
	}

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
		"-b", relArch+"/cdbr",
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

func pathExists(filePath string) (bool, os.FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil, nil
		}

		return false, nil, err
	}

	return true, info, nil
}

type isoConfig struct {
	Mirror              string
	Release             string
	Arch                string
	AutoinstallFilePath string
	InstallsiteDirPath  string
}

func (o *isoConfig) validate() error {
	if o.Mirror == "" {
		return errors.New("mirror url is empty")
	}

	if o.Release == "" {
		return errors.New("release version is empty")
	}

	if o.Arch == "" {
		return errors.New("cpu architecture is empty")
	}

	if o.AutoinstallFilePath == "" {
		return errors.New("auto_install file path is empty")
	}

	if !filepath.IsAbs(o.AutoinstallFilePath) {
		return errors.New("auto_install file path must be absolute")
	}

	_, err := os.Stat(o.AutoinstallFilePath)
	if err != nil {
		return err
	}

	if o.InstallsiteDirPath != "" {
		if !filepath.IsAbs(o.InstallsiteDirPath) {
			return errors.New("install.site directory path must be absolute")
		}

		info, err := os.Stat(o.InstallsiteDirPath)
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return fmt.Errorf("install.site dir path is not a directory ('%s')",
				o.InstallsiteDirPath)
		}
	}

	return nil
}

func (o *isoConfig) buildConfigHash() (string, error) {
	hashAlgo := sha1.New()

	_, err := hashAlgo.Write([]byte(o.Release))
	if err != nil {
		return "", err
	}

	_, err = hashAlgo.Write([]byte(o.Arch))
	if err != nil {
		return "", err
	}

	_, err = hashAlgo.Write([]byte(o.AutoinstallFilePath))
	if err != nil {
		return "", err
	}

	_, err = hashAlgo.Write([]byte(o.InstallsiteDirPath))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hashAlgo.Sum(nil)), nil
}

func (o *buildCache) extractOpenbsdISO(ctx context.Context, buildDirPath string, filesConfig openbsdSrcFilesConfig) (string, error) {
	baseISOMountPath := filepath.Join(buildDirPath, "base-iso-mnt")

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
	isoPath := filepath.Join(dirPath, config.isoName())
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
		if !o.Debug {
			_ = os.Remove(isoPath)
		}

		return "", err
	}

	return isoPath, nil
}

type copyInstallAutomationConfig struct {
	ISOConfig  *isoConfig
	ISODirPath string
	RDDirPath  string
}

func (o *buildCache) copyInstallAutomation(ctx context.Context, config copyInstallAutomationConfig) error {
	if config.ISOConfig.AutoinstallFilePath != "" {
		err := copyFilePathToWithMode(
			config.ISOConfig.AutoinstallFilePath,
			filepath.Join(config.RDDirPath, "auto_install.conf"),
			0644)
		if err != nil {
			return fmt.Errorf("failed to copy auto_install config - %w", err)
		}
	}

	if config.ISOConfig.InstallsiteDirPath != "" {
		siteParentDirPath := filepath.Join(
			config.ISODirPath,
			config.ISOConfig.Release,
			config.ISOConfig.Arch)

		err := createInstallsiteTar(ctx, createInstallsiteTarConfig{
			SiteDirPath: config.ISOConfig.InstallsiteDirPath,
			OutDirPath:  siteParentDirPath,
			Release:     config.ISOConfig.Release,
		})
		if err != nil {
			return fmt.Errorf("failed to create install.site tar - %w", err)
		}
	}

	return nil
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

func copyDirectoryTo(srcDirPath string, dstDirPath string) error {
	dstExists, _, _ := pathExists(dstDirPath)
	if dstExists {
		return errors.New("destination directory already exists")
	}

	err := filepath.WalkDir(srcDirPath, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		dstPath := filepath.Join(
			dstDirPath,
			strings.TrimPrefix(filePath, srcDirPath))

		if d.IsDir() {
			dirInfo, err := os.Stat(filePath)
			if err != nil {
				return err
			}

			err = os.MkdirAll(dstPath, dirInfo.Mode().Perm())
			if err != nil {
				return err
			}

			return nil
		}

		err = copyFilePathTo(filePath, dstPath)
		if err != nil {
			return fmt.Errorf("failed to copy '%s' to '%s' - %w",
				filePath, dstPath, err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func copyFilePathToWithMode(srcPath string, dstPath string, mode fs.FileMode) error {
	err := copyFilePathTo(srcPath, dstPath)
	if err != nil {
		return err
	}

	err = os.Chmod(dstPath, mode)
	if err != nil {
		return err
	}

	return nil
}

func copyFilePathTo(srcPath string, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	srcInfo, err := src.Stat()
	if err != nil {
		return err
	}

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dst.Close()

	err = dst.Chmod(srcInfo.Mode())
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}

	return nil
}

func mapRAMDisk(ctx context.Context, rdFilePath string, buildDirPath string) (string, func(context.Context) error, error) {
	isCompressed, err := gzipDecompressIfNeeded(ctx, rdFilePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to check / decompress ramdisk - %w", err)
	}

	diskFSPath := filepath.Join(buildDirPath, "rd-disk-fs")

	// Create an empty file for rdsetroot.
	err = os.WriteFile(diskFSPath, nil, 0600)
	if err != nil {
		return "", nil, err
	}

	rdMountDirPath := filepath.Join(buildDirPath, "rd-mnt")

	err = os.MkdirAll(rdMountDirPath, 0700)
	if err != nil {
		return "", nil, err
	}

	const rdsetrootPath = "/usr/sbin/rdsetroot"

	rdsetrootExtract := exec.CommandContext(ctx, rdsetrootPath,
		"-x", rdFilePath,
		diskFSPath)

	out, err := rdsetrootExtract.CombinedOutput()
	if err != nil {
		return "", nil, fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			rdsetrootExtract.String(), err, out)
	}

	vndID, unconfigureFn, err := allocateVNDForFile(ctx, diskFSPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to allocate vnd for ram disk - %w", err)
	}

	vndPath := "/dev/" + vndID + "a"

	umountFn, err := mount(ctx, nil, vndPath, rdMountDirPath)
	if err != nil {
		_ = unconfigureFn(context.Background())
		return "", nil, fmt.Errorf("failed to mount ram disk - %w", err)
	}

	once := &sync.Once{}

	return rdMountDirPath, func(ctx context.Context) error {
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

type createInstallsiteTarConfig struct {
	SiteDirPath string
	OutDirPath  string
	Release     string
}

func createInstallsiteTar(ctx context.Context, config createInstallsiteTarConfig) error {
	// Example: "/path/to/iso-dir/site72.tgz"
	targzFilePath := filepath.Join(
		config.OutDirPath,
		"site"+strings.ReplaceAll(config.Release, ".", "")+".tgz")

	const tarExePath = "/bin/tar"

	// TODO: Use Go's 'tar' and 'gzip' libraries.
	// Already exec'ing a bunch of garbage, plus
	// it would have been a pain to figure out
	// some of the edge cases (symlinks).
	t := exec.CommandContext(ctx, tarExePath,
		"-C", config.SiteDirPath,
		"-czf", targzFilePath,
		".")

	out, err := t.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			t.String(), err, out)
	}

	return nil
}

func gzipCompress(filePath string) error {
	f, err := os.OpenFile(filePath, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	uncompressed, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	err = f.Truncate(0)
	if err != nil {
		return err
	}

	gzipWriter := gzip.NewWriter(f)

	_, err = io.Copy(gzipWriter, bytes.NewReader(uncompressed))
	if err != nil {
		return fmt.Errorf("failed to compress file - %w", err)
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
