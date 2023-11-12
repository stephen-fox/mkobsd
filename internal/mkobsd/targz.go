package mkobsd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

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
