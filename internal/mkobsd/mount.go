package mkobsd

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
)

func mount(ctx context.Context, additionalArgs []string, srcPath string, dstPath string) (func(context.Context) error, error) {
	const mountPath = "/sbin/mount"

	args := make([]string, len(additionalArgs)+2)

	for i := range additionalArgs {
		args[i] = additionalArgs[i]
	}

	args[len(args)-2] = srcPath
	args[len(args)-1] = dstPath

	mount := exec.CommandContext(ctx, mountPath, args...)

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

			umount := exec.CommandContext(ctx, umountPath, dstPath)

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
