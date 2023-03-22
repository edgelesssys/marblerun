// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package file

import "github.com/spf13/afero"

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
func (f *Handler) Write(data []byte) error {
	return f.fs.WriteFile(f.filename, data, 0o644)
}

// Name returns the filename.
func (f *Handler) Name() string {
	return f.filename
}

// Read reads the file and returns its contents.
func (f *Handler) Read() ([]byte, error) {
	return f.fs.ReadFile(f.filename)
}
