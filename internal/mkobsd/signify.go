package mkobsd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

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
