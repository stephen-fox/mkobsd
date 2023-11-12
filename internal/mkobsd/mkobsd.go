package mkobsd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	setupOpenBSDInstallerTree   = "setup-new-installer-tree"
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
	var onImgDoneFn func(context.Context) error
	var optImgPath string

	originalInstallerPath, err := o.findOrDownloadInstaller(ctx, openbsdSrcFilesConfig{
		Mirror:  config.Mirror,
		Release: config.Release,
		Arch:    config.Arch,
		FileExt: config.InstallerType,
	})
	if err != nil {
		return fmt.Errorf("failed to find or download original openbsd installer - %w", err)
	}

	switch config.InstallerType {
	case "iso":
		installerDirPath, err = o.extractOpenbsdISO(ctx, originalInstallerPath, buildDirPath)
		if err != nil {
			return fmt.Errorf("failed to extract openbsd iso - %w", err)
		}
		defer os.RemoveAll(installerDirPath)
	case "img":
		optImgPath, installerDirPath, onImgDoneFn, err = o.copyAndMountOpenbsdImg(
			ctx,
			originalInstallerPath,
			buildDirPath)
		if err != nil {
			return fmt.Errorf("failed to create new openbsd img - %w", err)
		}
		defer onImgDoneFn(context.Background())
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
		err = onImgDoneFn(context.Background())
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

	vndID, unconfigVndFn, err := allocateVNDForFile(ctx, isoPath)
	if err != nil {
		return "", fmt.Errorf("failed to allocate vnd for '%s' - %w",
			isoPath, err)
	}
	defer unconfigVndFn(context.Background())

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

	vndID, unconfigVndFn, err := allocateVNDForFile(ctx, tmpImgPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to allocate vnd for tmp img '%s' - %w",
			tmpImgPath, err)
	}

	vndPath := "/dev/" + vndID

	unmountFn, err := mount(
		ctx,
		nil,
		vndPath+"a",
		baseImgMountPath)
	if err != nil {
		vndErr := unconfigVndFn(context.Background())
		if vndErr != nil {
			return "", "", nil, fmt.Errorf("failed to unconfigure vnd after mount failure - vnconfig error: %s | mount error: %w", vndErr, err)
		}

		return "", "", nil, fmt.Errorf("failed to mount openbsd base vnd '%s' to '%s' - %w",
			vndPath, baseImgMountPath, err)
	}

	onDoneFn := func(ctx context.Context) error {
		err := unmountFn(ctx)
		if err != nil {
			_ = unconfigVndFn(ctx)
			return fmt.Errorf("unmount failed - %w", err)
		}

		err = unconfigVndFn(ctx)
		if err != nil {
			return fmt.Errorf("vnd unconfigure failed - %w", err)
		}

		return nil
	}

	return tmpImgPath, baseImgMountPath, onDoneFn, nil
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
