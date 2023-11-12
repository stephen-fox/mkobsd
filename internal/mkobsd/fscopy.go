package mkobsd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

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
