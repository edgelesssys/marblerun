// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"io"
)

type stubGetter struct {
	response    []byte
	requestPath string
	query       []string
	err         error
}

func (s *stubGetter) Get(_ context.Context, request string, _ io.Reader, query ...string) ([]byte, error) {
	s.requestPath = request
	s.query = query
	return s.response, s.err
}

type stubPoster struct {
	response    []byte
	requestPath string
	header      string
	err         error
}

func (s *stubPoster) Post(_ context.Context, request string, header string, _ io.Reader) ([]byte, error) {
	s.requestPath = request
	s.header = header
	return s.response, s.err
}
