// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package file

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
)

// Option are extra options for the file writer.
type Option uint

const (
	// OptNone is the default option.
	OptNone Option = 1 << iota
	// OptOverwrite overwrites the file if it already exist.
	OptOverwrite
	// OptMkdirAll creates the parent directory if it does not exist.
	OptMkdirAll
)

// Handler is a wrapper around afero.Afero,
// providing a simple interface for reading and writing files.
type Handler struct {
	fs       afero.Afero
	filename string
}

// New returns a new FileWriter for the given filename.
//
// Returns nil if filename is empty.
func New(filename string, fs afero.Fs) *Handler {
	if filename == "" {
		return nil
	}

	return &Handler{
		fs:       afero.Afero{Fs: fs},
		filename: filename,
	}
}

// Write writes the given data to the file.
func (f *Handler) Write(data []byte, opt ...Option) error {
	opts := OptNone
	for _, o := range opt {
		opts |= o
	}

	if opts&OptMkdirAll != 0 {
		if err := f.fs.MkdirAll(filepath.Dir(f.filename), 0o755); err != nil {
			return err
		}
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if opts&OptOverwrite != 0 {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	file, err := f.fs.OpenFile(f.filename, flags, 0o600)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	errTmp := file.Close()
	return errors.Join(err, errTmp)
}

// Name returns the filename.
func (f *Handler) Name() string {
	return f.filename
}

// Read reads the file and returns its contents.
func (f *Handler) Read() ([]byte, error) {
	return f.fs.ReadFile(f.filename)
}
