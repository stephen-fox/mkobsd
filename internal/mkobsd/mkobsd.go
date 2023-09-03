package mkobsd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type BuildCache struct {
	BasePath       string
	BaseDirsPerm   fs.FileMode
	HTTPClient     *http.Client
	DebugISOVerify bool
	dlcDirPath     string
	setupOnce      sync.Once
}

func (o *BuildCache) setup() error {
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}

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
		return errors.New("base path is a file (it should be a directory)")
	}

	o.dlcDirPath = filepath.Join(o.BasePath, "downloads")

	err = os.MkdirAll(o.dlcDirPath, o.BaseDirsPerm)
	if err != nil {
		return fmt.Errorf("failed to create dlc dir '%s' - %w",
			o.dlcDirPath, err)
	}

	return nil
}

const (
	setupAction                 = "setup"
	extractOpenBSDIsoAction     = "extract-obsd-iso"
	mapKernelRAMDiskAction      = "map-kernel-ram-disk"
	copyInstallAutomationAction = "copy-install-automation"
	unmapKernelRAMDiskAction    = "unmap-kernel-ram-disk"
	makeNewISOAction            = "make-new-iso"
)

func (o *BuildCache) BuildISO(ctx context.Context, config *BuildISOConfig) error {
	if config.BeforeActionFn != nil {
		err := config.BeforeActionFn(setupAction, nil)
		if err != nil {
			return err
		}
	}

	var err error
	o.setupOnce.Do(func() {
		err = o.setup()
	})
	if err != nil {
		return err
	}

	err = config.validate()
	if err != nil {
		return fmt.Errorf("failed to validate iso config - %w", err)
	}

	buildDirPath, err := os.MkdirTemp(o.BasePath, ".build-"+filepath.Base(config.ISOOutputPath)+"-")
	if err != nil {
		return fmt.Errorf("failed to create temp build directory - %w", err)
	}
	defer os.RemoveAll(buildDirPath)

	if config.AfterActionFn != nil {
		err := config.AfterActionFn(setupAction, map[string]string{
			"build-dir-path": buildDirPath,
		})
		if err != nil {
			return err
		}
	}

	if config.BeforeActionFn != nil {
		err := config.BeforeActionFn(extractOpenBSDIsoAction, nil)
		if err != nil {
			return err
		}
	}

	newISODirPath, err := o.extractOpenbsdISO(ctx, buildDirPath, openbsdSrcFilesConfig{
		Mirror:  config.Mirror,
		Release: config.Release,
		Arch:    config.Arch,
	})
	if err != nil {
		return fmt.Errorf("failed to extract openbsd iso - %w", err)
	}
	defer os.RemoveAll(newISODirPath)

	if config.AfterActionFn != nil {
		err := config.AfterActionFn(extractOpenBSDIsoAction, map[string]string{
			"extracted-iso-dir-path": newISODirPath,
		})
		if err != nil {
			return err
		}
	}

	rdFilePath := filepath.Join(newISODirPath, config.Release, config.Arch, "bsd.rd")

	if config.BeforeActionFn != nil {
		err := config.BeforeActionFn(mapKernelRAMDiskAction, map[string]string{
			"ram-risk-file-path": rdFilePath,
		})
		if err != nil {
			return err
		}
	}

	rdMountDirPath, unmapRDFn, err := mapRAMDisk(ctx, rdFilePath, buildDirPath)
	if err != nil {
		return fmt.Errorf("failed to map ram disk - %w", err)
	}
	defer unmapRDFn(context.Background())

	if config.AfterActionFn != nil {
		err := config.AfterActionFn(mapKernelRAMDiskAction, map[string]string{
			"ram-disk-mount-dir-path": rdMountDirPath,
		})
		if err != nil {
			return err
		}
	}

	if config.BeforeActionFn != nil {
		err := config.BeforeActionFn(copyInstallAutomationAction, nil)
		if err != nil {
			return err
		}
	}

	err = o.copyInstallAutomation(ctx, copyInstallAutomationConfig{
		ISOConfig:  config,
		ISODirPath: newISODirPath,
		RDDirPath:  rdMountDirPath,
	})
	if err != nil {
		return fmt.Errorf("failed to copy installer automation - %w", err)
	}

	if config.AfterActionFn != nil {
		err := config.AfterActionFn(copyInstallAutomationAction, nil)
		if err != nil {
			return err
		}
	}

	if config.BeforeActionFn != nil {
		err := config.BeforeActionFn(unmapKernelRAMDiskAction, nil)
		if err != nil {
			return err
		}
	}

	err = unmapRDFn(ctx)
	if err != nil {
		return fmt.Errorf("failed to un-map rd - %w", err)
	}

	if config.AfterActionFn != nil {
		err := config.AfterActionFn(unmapKernelRAMDiskAction, nil)
		if err != nil {
			return err
		}
	}

	if config.BeforeActionFn != nil {
		err := config.BeforeActionFn(makeNewISOAction, nil)
		if err != nil {
			return err
		}
	}

	const mkhybridPath = "/usr/sbin/mkhybrid"
	relArch := config.Release + "/" + config.Arch
	volumeID := "OpenBSD/" + config.Arch + " " + config.Release + " Install CD"

	mkhybrid := exec.CommandContext(
		ctx,
		mkhybridPath,
		"-a", "-R", "-T", "-L", "-l", "-d", "-D", "-N",
		"-o", config.ISOOutputPath,
		"-v", "-v",
		"-A", volumeID,
		"-P", "Copyright (c) Theo de Raadt <deraadt@openbsd.org>",
		"-V", volumeID,
		"-b", relArch+"/cdbr",
		"-c", relArch+"/boot.catalog",
		newISODirPath)

	out, err := mkhybrid.CombinedOutput()
	if err != nil {
		_ = os.Remove(config.ISOOutputPath)
		return fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			mkhybrid.String(), err, out)
	}

	if config.AfterActionFn != nil {
		err := config.AfterActionFn(makeNewISOAction, nil)
		if err != nil {
			return err
		}
	}

	return nil
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

type BuildISOConfig struct {
	ISOOutputPath          string
	Mirror                 string
	Release                string
	Arch                   string
	OptAutoinstallFilePath string
	OptInstallsiteDirPath  string
	PreserveSiteTarIDs     bool
	BeforeActionFn         func(string, map[string]string) error
	AfterActionFn          func(string, map[string]string) error
}

func (o *BuildISOConfig) validate() error {
	if o.ISOOutputPath == "" {
		return errors.New("iso output path is empty")
	}

	isoAlreadyExists, _, _ := pathExists(o.ISOOutputPath)
	if isoAlreadyExists {
		return fmt.Errorf("a file or directory already exists at '%s'", o.ISOOutputPath)
	}

	if o.Mirror == "" {
		return errors.New("mirror url is empty")
	}

	if o.Release == "" {
		return errors.New("release version is empty")
	}

	if o.Arch == "" {
		return errors.New("cpu architecture is empty")
	}

	if o.OptAutoinstallFilePath != "" {
		if !filepath.IsAbs(o.OptAutoinstallFilePath) {
			return errors.New("auto_install config file path must be absolute")
		}

		_, err := os.Stat(o.OptAutoinstallFilePath)
		if err != nil {
			return err
		}
	}

	if o.OptInstallsiteDirPath != "" {
		if !filepath.IsAbs(o.OptInstallsiteDirPath) {
			return errors.New("install.site directory path must be absolute")
		}

		info, err := os.Stat(o.OptInstallsiteDirPath)
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return fmt.Errorf("install.site dir path is not a directory ('%s')",
				o.OptInstallsiteDirPath)
		}
	}

	return nil
}

func (o *BuildCache) extractOpenbsdISO(ctx context.Context, buildDirPath string, filesConfig openbsdSrcFilesConfig) (string, error) {
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

	// TODO: It would be nice to replace this with th copyDirectoryTo func.
	// I think I used cp here because there are a bunch of cases like symlinks.
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

func (o *BuildCache) openbsdISO(ctx context.Context, config openbsdSrcFilesConfig) (string, error) {
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
		return "", fmt.Errorf("failed to create dlc iso path '%s' - %w", dirPath, err)
	}

	err = httpGetToFilePath(ctx, o.HTTPClient, config.sha256SigUrl(), sha256SigPath)
	if err != nil {
		return "", fmt.Errorf("failed to http get sha256 file '%s' - %w",
			config.sha256SigUrl(), err)
	}

	err = httpGetToFilePath(ctx, o.HTTPClient, config.isoUrl(), isoPath)
	if err != nil {
		return "", fmt.Errorf("failed to http get openbsd iso '%s' - %w",
			config.isoUrl(), err)
	}

	err = signifyVerify(ctx, verifyConfig)
	if err != nil {
		if !o.DebugISOVerify {
			_ = os.Remove(isoPath)
		}

		return "", err
	}

	return isoPath, nil
}

type copyInstallAutomationConfig struct {
	ISOConfig  *BuildISOConfig
	ISODirPath string
	RDDirPath  string
}

func (o *BuildCache) copyInstallAutomation(ctx context.Context, config copyInstallAutomationConfig) error {
	if config.ISOConfig.OptAutoinstallFilePath != "" {
		err := copyFilePathToWithMode(
			config.ISOConfig.OptAutoinstallFilePath,
			filepath.Join(config.RDDirPath, "auto_install.conf"),
			0644)
		if err != nil {
			return fmt.Errorf("failed to copy autoinstall config file - %w", err)
		}
	}

	if config.ISOConfig.OptInstallsiteDirPath != "" {
		siteParentDirPath := filepath.Join(
			config.ISODirPath,
			config.ISOConfig.Release,
			config.ISOConfig.Arch)

		err := createInstallsiteTar(ctx, createInstallsiteTarConfig{
			SiteDirPath: config.ISOConfig.OptInstallsiteDirPath,
			OutDirPath:  siteParentDirPath,
			Release:     config.ISOConfig.Release,
			PreserveIDs: config.ISOConfig.PreserveSiteTarIDs,
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
				return fmt.Errorf("failed to stat directory '%s' - %w",
					filePath, err)
			}

			err = os.MkdirAll(dstPath, dirInfo.Mode().Perm())
			if err != nil {
				return fmt.Errorf("failed to create directory '%s' - %w",
					dstPath, err)
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
		return "", nil, fmt.Errorf("failed to create rd mount dir path '%s' - %w",
			rdMountDirPath, err)
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
	PreserveIDs bool
}

func createInstallsiteTar(ctx context.Context, config createInstallsiteTarConfig) error {
	// Example: "/path/to/iso-dir/site72.tgz"
	targzFilePath := filepath.Join(
		config.OutDirPath,
		"site"+strings.ReplaceAll(config.Release, ".", "")+".tgz")

	f, err := os.OpenFile(targzFilePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create tar file - %w", err)
	}
	defer f.Close()

	err = tarGzDir(ctx, config.SiteDirPath, f, config.PreserveIDs)
	if err != nil {
		return fmt.Errorf("failed to tar directory - %w", err)
	}

	return nil
}

func tarGzDir(ctx context.Context, dirPath string, w io.Writer, preserveIDs bool) error {
	absDirPath, err := filepath.Abs(dirPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for directory '%s' - %w",
			dirPath, err)
	}

	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	err = filepath.WalkDir(absDirPath, func(srcPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		tarPath := strings.TrimPrefix(srcPath, absDirPath)

		err = addFileToTar(tarWriter, srcPath, tarPath, preserveIDs)
		if err != nil {
			return fmt.Errorf("failed to add file '%s' to tar - %w",
				srcPath, err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func addFileToTar(tw *tar.Writer, filePath string, tarHeaderName string, preserveIDs bool) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, filePath)
	if err != nil {
		return err
	}

	// Use full path as name (FileInfoHeader only takes the basename)
	// If we don't do this the directory strucuture would
	// not be preserved:
	// https://golang.org/src/archive/tar/common.go?#L626
	//
	// Also remove any leading slash to avoid warnings from the
	// tar program like this:
	//  tar: Removing leading / from absolute path names in the archive
	header.Name = strings.TrimPrefix(tarHeaderName, "/")

	if !preserveIDs {
		header.Uid = 0
		header.Gid = 0
		header.Uname = "root"
		header.Gname = "wheel"
	}

	err = tw.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(tw, file)
	if err != nil {
		return err
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
