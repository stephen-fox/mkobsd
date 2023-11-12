package mkobsd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

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
