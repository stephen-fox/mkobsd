package mkobsd

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

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
