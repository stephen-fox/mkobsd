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
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type BuildCache struct {
	BasePath      string
	DebugVerify   bool
	dlcDirPath    string
	buildUserInfo *userInfo
	setupOnce     sync.Once
}

func (o *BuildCache) setup() error {
	if o.buildUserInfo == nil {
		const buildUsername = "build"

		userInfo, err := lookupUser(buildUsername)
		if err != nil {
			return fmt.Errorf("failed to lookup user: '%s' - %w", buildUsername, err)
		}

		o.buildUserInfo = userInfo
	}

	if !filepath.IsAbs(o.BasePath) {
		return fmt.Errorf("base path is not absolute ('%s')", o.BasePath)
	}

	_, baseInfo, err := pathExists(o.BasePath)
	if err != nil {
		return err
	}

	if baseInfo != nil && !baseInfo.IsDir() {
		return errors.New("base path is a file (it should be a directory)")
	}

	o.dlcDirPath = filepath.Join(o.BasePath, "downloads")

	err = os.MkdirAll(o.dlcDirPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create dlc dir '%s' - %w",
			o.dlcDirPath, err)
	}

	return nil
}

func lookupUser(username string) (*userInfo, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("lookup failed - %w", err)
	}

	uid, err := strconv.ParseInt(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to convert uid string '%s' to int - %w",
			u.Uid, err)
	}

	gid, err := strconv.ParseInt(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to convert gid string '%s' to int - %w",
			u.Gid, err)
	}

	return &userInfo{
		Name:        username,
		UID:         uint32(uid),
		GID:         uint32(gid),
		HomeDirPath: u.HomeDir,
	}, nil
}

type userInfo struct {
	Name        string
	UID         uint32
	GID         uint32
	HomeDirPath string
}

const (
	setupAction                 = "setup"
	setupOpenBSDInstallerTree   = "setup-obsd-installer-tree"
	mapKernelRAMDiskAction      = "map-kernel-ram-disk"
	copyInstallAutomationAction = "copy-install-automation"
	unmapKernelRAMDiskAction    = "unmap-kernel-ram-disk"
	makeNewISOAction            = "make-new-iso"
)

func (o *BuildCache) Build(ctx context.Context, config *BuildConfig) error {
	if config.OptBeforeActionFn != nil {
		err := config.OptBeforeActionFn(setupAction, nil)
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
		return fmt.Errorf("failed to validate build config - %w", err)
	}

	buildDirPath, err := os.MkdirTemp(
		o.BasePath,
		".build-"+filepath.Base(config.InstallerOutputPath)+"-")
	if err != nil {
		return fmt.Errorf("failed to create temp build directory - %w", err)
	}
	defer os.RemoveAll(buildDirPath)

	if config.OptAfterActionFn != nil {
		err := config.OptAfterActionFn(setupAction, map[string]string{
			"build-dir-path": buildDirPath,
		})
		if err != nil {
			return err
		}
	}

	if config.OptBeforeActionFn != nil {
		err := config.OptBeforeActionFn(setupOpenBSDInstallerTree, nil)
		if err != nil {
			return err
		}
	}

	var installerDirPath string
	var earlyUnmountFn func(context.Context) error
	var optImgPath string

	originalInstallerPath, err := o.findOrDownloadInstaller(ctx, openbsdSrcFilesConfig{
		Mirror:  config.Mirror,
		Release: config.Release,
		Arch:    config.Arch,
		FileExt: config.InstallerType,
	})
	if err != nil {
		return fmt.Errorf("failed to find or download openbsd installer - %w", err)
	}

	switch config.InstallerType {
	case "iso":
		installerDirPath, err = o.extractOpenbsdISO(ctx, originalInstallerPath, buildDirPath)
		if err != nil {
			return fmt.Errorf("failed to extract openbsd iso - %w", err)
		}
		defer os.RemoveAll(installerDirPath)
	case "img":
		optImgPath, installerDirPath, earlyUnmountFn, err = o.copyAndMountOpenbsdImg(
			ctx,
			originalInstallerPath,
			buildDirPath)
		if err != nil {
			return fmt.Errorf("failed to create new openbsd img - %w", err)
		}
		defer earlyUnmountFn(context.Background())
	default:
		return fmt.Errorf("unsupported installer type: %q", config.InstallerType)
	}

	if config.OptAfterActionFn != nil {
		err := config.OptAfterActionFn(setupOpenBSDInstallerTree, map[string]string{
			"dir-path": installerDirPath,
		})
		if err != nil {
			return err
		}
	}

	rdFilePath := filepath.Join(installerDirPath, config.Release, config.Arch, "bsd.rd")

	if config.OptBeforeActionFn != nil {
		err := config.OptBeforeActionFn(mapKernelRAMDiskAction, map[string]string{
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

	if config.OptAfterActionFn != nil {
		err := config.OptAfterActionFn(mapKernelRAMDiskAction, map[string]string{
			"ram-disk-mount-dir-path": rdMountDirPath,
		})
		if err != nil {
			return err
		}
	}

	if config.OptBeforeActionFn != nil {
		err := config.OptBeforeActionFn(copyInstallAutomationAction, nil)
		if err != nil {
			return err
		}
	}

	err = o.copyInstallAutomation(ctx, copyInstallAutomationConfig{
		BuildConfig:      config,
		InstallerDirPath: installerDirPath,
		RDDirPath:        rdMountDirPath,
	})
	if err != nil {
		return fmt.Errorf("failed to copy installer automation - %w", err)
	}

	if config.OptAfterActionFn != nil {
		err := config.OptAfterActionFn(copyInstallAutomationAction, nil)
		if err != nil {
			return err
		}
	}

	if config.OptBeforeActionFn != nil {
		err := config.OptBeforeActionFn(unmapKernelRAMDiskAction, nil)
		if err != nil {
			return err
		}
	}

	err = unmapRDFn(ctx)
	if err != nil {
		return fmt.Errorf("failed to un-map rd - %w", err)
	}

	if config.OptAfterActionFn != nil {
		err := config.OptAfterActionFn(unmapKernelRAMDiskAction, nil)
		if err != nil {
			return err
		}
	}

	if config.InstallerType == "img" {
		err = earlyUnmountFn(context.Background())
		if err != nil {
			return fmt.Errorf("failed to unmount new img - %w", err)
		}

		err = os.Rename(optImgPath, config.InstallerOutputPath)
		if err != nil {
			return fmt.Errorf("failed to move new img to output path - %w", err)
		}

		return nil
	}

	if config.OptBeforeActionFn != nil {
		err := config.OptBeforeActionFn(makeNewISOAction, nil)
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
		"-o", config.InstallerOutputPath,
		"-v", "-v",
		"-A", volumeID,
		"-P", "Copyright (c) Theo de Raadt <deraadt@openbsd.org>",
		"-V", volumeID,
		"-b", relArch+"/cdbr",
		"-c", relArch+"/boot.catalog",
		installerDirPath)

	out, err := mkhybrid.CombinedOutput()
	if err != nil {
		_ = os.Remove(config.InstallerOutputPath)
		return fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			mkhybrid.String(), err, out)
	}

	if config.OptAfterActionFn != nil {
		err := config.OptAfterActionFn(makeNewISOAction, nil)
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

type BuildConfig struct {
	InstallerOutputPath    string
	Mirror                 string
	Release                string
	Arch                   string
	InstallerType          string
	OptAutoinstallFilePath string
	OptInstallsiteDirPath  string
	PreserveSiteTarIDs     bool
	OptBeforeActionFn      func(string, map[string]string) error
	OptAfterActionFn       func(string, map[string]string) error
}

func (o *BuildConfig) validate() error {
	switch o.InstallerType {
	case "iso", "img":
		// OK.
	default:
		return fmt.Errorf("unsupported installer type: %q", o.InstallerType)
	}

	if o.InstallerOutputPath == "" {
		return errors.New("iso output path is empty")
	}

	installerAlreadyExists, _, _ := pathExists(o.InstallerOutputPath)
	if installerAlreadyExists {
		return fmt.Errorf("a file or directory already exists at '%s'", o.InstallerOutputPath)
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

func (o *BuildCache) extractOpenbsdISO(ctx context.Context, isoPath string, buildDirPath string) (string, error) {
	baseISOMountPath := filepath.Join(buildDirPath, "base-iso-mnt")

	err := os.MkdirAll(baseISOMountPath, 0700)
	if err != nil {
		return "", fmt.Errorf("failed to create base openbsd iso mount dir '%s' - %w",
			baseISOMountPath, err)
	}
	defer os.Remove(baseISOMountPath)

	vndID, unconfigFn, err := allocateVNDForFile(ctx, isoPath)
	if err != nil {
		return "", fmt.Errorf("failed to allocate vnd for '%s' - %w",
			isoPath, err)
	}
	defer unconfigFn(context.Background())

	vndPath := "/dev/" + vndID

	unmountFn, err := mount(
		ctx,
		[]string{"-t", "cd9660"},
		vndPath+"c",
		baseISOMountPath)
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

	// TODO: It would be nice to replace this with the copyDirectoryTo func.
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
		return "", fmt.Errorf("failed to copy iso files: '%s' - %w - output: '%s'",
			cpISO.String(), err, out)
	}

	return newISOContentsPath, nil
}

func (o *BuildCache) copyAndMountOpenbsdImg(ctx context.Context, imgPath string, buildDirPath string) (string, string, func(context.Context) error, error) {
	baseImgMountPath := filepath.Join(buildDirPath, "base-img-mnt")

	err := os.MkdirAll(baseImgMountPath, 0700)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create base openbsd img mount dir '%s' - %w",
			baseImgMountPath, err)
	}
	defer os.Remove(baseImgMountPath)

	tmpImgPath := filepath.Join(buildDirPath, "new-installer.img")

	err = copyFilePathTo(imgPath, tmpImgPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to copy openbsd img to tmp - %w", err)
	}

	vndID, unconfigFn, err := allocateVNDForFile(ctx, tmpImgPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to allocate vnd for tmp img '%s' - %w",
			tmpImgPath, err)
	}
	defer unconfigFn(context.Background())

	vndPath := "/dev/" + vndID

	unmountFn, err := mount(
		ctx,
		nil,
		vndPath+"a",
		baseImgMountPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to mount openbsd base vnd '%s' to '%s' - %w",
			vndPath, baseImgMountPath, err)
	}

	return tmpImgPath, baseImgMountPath, unmountFn, nil
}

func (o *BuildCache) findOrDownloadInstaller(ctx context.Context, config openbsdSrcFilesConfig) (string, error) {
	finalOutputDirPath := filepath.Join(o.dlcDirPath, config.Arch, config.Release)

	installerPath := filepath.Join(finalOutputDirPath, config.installerFileName())
	sha256SigPath := filepath.Join(finalOutputDirPath, config.sha256SigName())

	verifyConfig := signifyVerifyConfig{
		PubKeyPath:       "/etc/signify/openbsd-" + config.releaseID() + "-base.pub",
		DotSigPath:       sha256SigPath,
		FileNameToVerify: config.installerFileName(),
	}

	installerAlreadyExists, _, _ := pathExists(installerPath)
	if installerAlreadyExists {
		err := signifyVerifyAs(ctx, o.buildUserInfo, verifyConfig)
		if err != nil {
			return "", fmt.Errorf("failed to signify verify existing installer - %w", err)
		}

		return installerPath, nil
	}

	err := os.MkdirAll(finalOutputDirPath, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create original installer output dir '%s' - %w",
			finalOutputDirPath, err)
	}

	// TODO: I would prefer to create the directory in /tmp,
	// but that causes the file renames to fail because /tmp
	// is on a different partition. As a result, the rename
	// calls fail with: "cross-device link".
	tmpDirPath, err := os.MkdirTemp(o.dlcDirPath, ".mkobsd-download-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp download dir - %w", err)
	}
	if !o.DebugVerify && tmpDirPath != "/" {
		defer os.RemoveAll(tmpDirPath)
	}

	err = os.Chown(tmpDirPath, int(o.buildUserInfo.UID), int(o.buildUserInfo.GID))
	if err != nil {
		return "", fmt.Errorf("failed to chown temp download dir - %w", err)
	}

	sigTmpPath := filepath.Join(tmpDirPath, filepath.Base(sha256SigPath))
	installerTmpPath := filepath.Join(tmpDirPath, filepath.Base(installerPath))
	verifyTmpConfig := verifyConfig
	verifyTmpConfig.DotSigPath = sigTmpPath

	err = execFTPAs(ctx, o.buildUserInfo, config.sha256SigUrl(), sigTmpPath)
	if err != nil {
		return "", fmt.Errorf("failed to http get sha256 file '%s' into '%s' - %w",
			config.sha256SigUrl(), sigTmpPath, err)
	}

	err = execFTPAs(ctx, o.buildUserInfo, config.installerURL(), installerTmpPath)
	if err != nil {
		return "", fmt.Errorf("failed to http get openbsd installer '%s' into '%s' - %w",
			config.installerURL(), installerTmpPath, err)
	}

	err = signifyVerifyAs(ctx, o.buildUserInfo, verifyTmpConfig)
	if err != nil {
		return "", fmt.Errorf("failed to signify verify newly-downloaded installer - %w", err)
	}

	err = os.Chown(sigTmpPath, 0, 0)
	if err != nil {
		return "", fmt.Errorf("failed to chown tmp sig file to root:wheel - %w", err)
	}

	err = os.Chown(installerTmpPath, 0, 0)
	if err != nil {
		return "", fmt.Errorf("failed to chown tmp installer file to root:wheel - %w", err)
	}

	err = os.Rename(sigTmpPath, sha256SigPath)
	if err != nil {
		return "", fmt.Errorf("failed to rename sha256 file '%s' to '%s' - %w",
			sigTmpPath, sha256SigPath, err)
	}

	err = os.Rename(installerTmpPath, installerPath)
	if err != nil {
		return "", fmt.Errorf("failed to rename installer file '%s' to '%s' - %w",
			installerTmpPath, installerPath, err)
	}

	return installerPath, nil
}

func execFTPAs(ctx context.Context, u *userInfo, urlStr string, outputPath string) error {
	const ftpExePath = "/usr/bin/ftp"

	ftp := exec.CommandContext(ctx,
		ftpExePath,
		"-M",
		"-o", outputPath,
		urlStr)

	ftp.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: u.UID,
			Gid: u.GID,
		},
	}

	ftp.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + u.HomeDirPath,
	}

	out, err := ftp.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute '%s' - %w - output: %s",
			ftp.String(), err, out)
	}

	return nil
}

type copyInstallAutomationConfig struct {
	BuildConfig      *BuildConfig
	InstallerDirPath string
	RDDirPath        string
}

func (o *BuildCache) copyInstallAutomation(ctx context.Context, config copyInstallAutomationConfig) error {
	if config.BuildConfig.OptAutoinstallFilePath != "" {
		err := copyFilePathToWithMode(
			config.BuildConfig.OptAutoinstallFilePath,
			filepath.Join(config.RDDirPath, "auto_install.conf"),
			0600)
		if err != nil {
			return fmt.Errorf("failed to copy autoinstall config file - %w", err)
		}
	}

	if config.BuildConfig.OptInstallsiteDirPath != "" {
		siteParentDirPath := filepath.Join(
			config.InstallerDirPath,
			config.BuildConfig.Release,
			config.BuildConfig.Arch)

		err := createInstallsiteTar(ctx, createInstallsiteTarConfig{
			SiteDirPath: config.BuildConfig.OptInstallsiteDirPath,
			OutDirPath:  siteParentDirPath,
			Release:     config.BuildConfig.Release,
			PreserveIDs: config.BuildConfig.PreserveSiteTarIDs,
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
	FileExt string
}

func (o openbsdSrcFilesConfig) installerURL() string {
	return o.Mirror + "/" + o.Release + "/" + o.Arch + "/" + o.installerFileName()
}

func (o openbsdSrcFilesConfig) installerFileName() string {
	return "install" + strings.ReplaceAll(o.Release, ".", "") + "." + o.FileExt
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

func signifyVerifyAs(ctx context.Context, u *userInfo, config signifyVerifyConfig) error {
	_, err := os.Stat(config.PubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to stat openbsd installer signer public key file "+
			"(note: if you are building an installer for a newer version of openbsd, "+
			"you may need to copy this file from the openbsd source code) - %w", err)
	}

	signify := exec.CommandContext(ctx, "/usr/bin/signify",
		"-C",
		"-p", config.PubKeyPath,
		"-x", config.DotSigPath,
		config.FileNameToVerify)

	signify.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: u.UID,
			Gid: u.GID,
		},
	}

	signify.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + u.HomeDirPath,
	}

	signify.Dir = filepath.Dir(config.DotSigPath)

	out, err := signify.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute '%s' - %w - output: %s",
			signify.String(), err, out)
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
