// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"encoding/pem"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutputFlagNotEmpty(t *testing.T) {
	testCases := map[string]struct {
		cmd     *cobra.Command
		wantErr bool
	}{
		"flag not defined": {
			cmd:     &cobra.Command{},
			wantErr: true,
		},
		"flag empty": {
			cmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("output", "", "")
				return cmd
			}(),
			wantErr: true,
		},
		"flag not empty": {
			cmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("output", "foo", "")
				return cmd
			}(),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			err := outputFlagNotEmpty(tc.cmd, nil)
			if tc.wantErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}

func TestCertificateRoot(t *testing.T) {
	testCases := map[string]struct {
		file    *file.Handler
		certs   []*pem.Block
		wantErr bool
	}{
		"no certs": {
			file:    file.New("unit-test", afero.NewMemMapFs()),
			certs:   []*pem.Block{},
			wantErr: true,
		},
		"one cert": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			certs: []*pem.Block{
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("ROOT CERTIFICATE"),
				},
			},
		},
		"multiple certs": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			certs: []*pem.Block{
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("INTERMEDIATE CERTIFICATE"),
				},
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("ROOT CERTIFICATE"),
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := cliCertificateRoot(&out, tc.file, tc.certs)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			writtenCert, err := tc.file.Read()
			require.NoError(t, err)
			assert.Equal(pem.EncodeToMemory(tc.certs[len(tc.certs)-1]), writtenCert)
		})
	}
}

func TestCertificateIntermediate(t *testing.T) {
	testCases := map[string]struct {
		file    *file.Handler
		certs   []*pem.Block
		wantErr bool
	}{
		"no certs": {
			file:    file.New("unit-test", afero.NewMemMapFs()),
			certs:   []*pem.Block{},
			wantErr: true,
		},
		"one cert": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			certs: []*pem.Block{
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("ROOT CERTIFICATE"),
				},
			},
			wantErr: true,
		},
		"multiple certs": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			certs: []*pem.Block{
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("INTERMEDIATE CERTIFICATE"),
				},
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("ROOT CERTIFICATE"),
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := cliCertificateIntermediate(&out, tc.file, tc.certs)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			writtenCert, err := tc.file.Read()
			require.NoError(t, err)
			assert.Equal(pem.EncodeToMemory(tc.certs[0]), writtenCert)
		})
	}
}

func TestCertificateChain(t *testing.T) {
	testCases := map[string]struct {
		file    *file.Handler
		certs   []*pem.Block
		wantErr bool
	}{
		"no certs": {
			file:    file.New("unit-test", afero.NewMemMapFs()),
			certs:   []*pem.Block{},
			wantErr: true,
		},
		"one cert": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			certs: []*pem.Block{
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("ROOT CERTIFICATE"),
				},
			},
		},
		"multiple certs": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			certs: []*pem.Block{
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("INTERMEDIATE CERTIFICATE"),
				},
				{
					Type:  "CERTIFICATE",
					Bytes: []byte("ROOT CERTIFICATE"),
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := cliCertificateChain(&out, tc.file, tc.certs)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			writtenCert, err := tc.file.Read()
			require.NoError(t, err)
			for _, cert := range tc.certs {
				assert.Contains(string(writtenCert), string(pem.EncodeToMemory(cert)))
			}
		})
	}
}
