// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package file

import "github.com/spf13/afero"

// Writer is a wrapper around afero.Afero,
// providing a simple interface for writing files.
type Writer struct {
	fs       afero.Afero
	filename string
}

// New returns a new FileWriter for the given filename.
//
// Returns nil if filename is empty.
func New(filename string) *Writer {
	if filename == "" {
		return nil
	}

	return &Writer{
		fs:       afero.Afero{Fs: afero.NewOsFs()},
		filename: filename,
	}
}

// Write writes the given data to the file.
func (f *Writer) Write(data []byte) error {
	return f.fs.WriteFile(f.filename, data, 0o644)
}

// Name returns the filename.
func (f *Writer) Name() string {
	return f.filename
}
