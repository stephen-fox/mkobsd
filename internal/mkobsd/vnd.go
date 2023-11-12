package mkobsd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
)

func allocateVNDForFile(ctx context.Context, filePath string) (string, func(context.Context) error, error) {
	const vnconfigPath = "/sbin/vnconfig"

	vnconfig := exec.CommandContext(ctx, vnconfigPath, filePath)

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
			vnconfigU := exec.CommandContext(ctx, vnconfigPath, "-u", id)

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
