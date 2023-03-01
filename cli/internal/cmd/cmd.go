// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package cmd implements the MarbleRun's CLI commands.
package cmd

import (
	"context"
	"io"
)

type getter interface {
	Get(ctx context.Context, path string, body io.Reader) ([]byte, error)
}

type poster interface {
	Post(ctx context.Context, path, contentType string, body io.Reader) ([]byte, error)
}
