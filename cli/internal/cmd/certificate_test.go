/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"bytes"
	"crypto/x509"
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
		file         *file.Handler
		root         *x509.Certificate
		intermediate *x509.Certificate
		wantErr      bool
	}{
		"no certs": {
			file:         file.New("unit-test", afero.NewMemMapFs()),
			root:         nil,
			intermediate: nil,
			wantErr:      true,
		},
		"one cert": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
		},
		"multiple certs": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			intermediate: &x509.Certificate{
				Raw: []byte("INTERMEDIATE CERTIFICATE"),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := saveRootCert(&out, tc.file, tc.root, tc.intermediate)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			writtenCert, err := tc.file.Read()
			require.NoError(t, err)
			assert.Equal(pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: tc.root.Raw,
			}), writtenCert)
		})
	}
}

func TestCertificateIntermediate(t *testing.T) {
	testCases := map[string]struct {
		file         *file.Handler
		root         *x509.Certificate
		intermediate *x509.Certificate
		wantErr      bool
	}{
		"no certs": {
			file:         file.New("unit-test", afero.NewMemMapFs()),
			root:         nil,
			intermediate: nil,
			wantErr:      true,
		},
		"one cert": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			wantErr: true,
		},
		"multiple certs": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			intermediate: &x509.Certificate{
				Raw: []byte("INTERMEDIATE CERTIFICATE"),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := saveIntermediateCert(&out, tc.file, tc.root, tc.intermediate)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			writtenCert, err := tc.file.Read()
			require.NoError(t, err)
			assert.Equal(pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: tc.intermediate.Raw,
			}), writtenCert)
		})
	}
}

func TestCertificateChain(t *testing.T) {
	testCases := map[string]struct {
		file         *file.Handler
		root         *x509.Certificate
		intermediate *x509.Certificate
		wantErr      bool
	}{
		"no certs": {
			file:         file.New("unit-test", afero.NewMemMapFs()),
			root:         nil,
			intermediate: nil,
			wantErr:      true,
		},
		"one cert": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			wantErr: true,
		},
		"multiple certs": {
			file: file.New("unit-test", afero.NewMemMapFs()),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			intermediate: &x509.Certificate{
				Raw: []byte("INTERMEDIATE CERTIFICATE"),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := saveCertChain(&out, tc.file, tc.root, tc.intermediate)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			writtenCert, err := tc.file.Read()
			require.NoError(t, err)
			assert.Contains(string(writtenCert), string(pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE", Bytes: tc.intermediate.Raw},
			)))
			assert.Contains(string(writtenCert), string(pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE", Bytes: tc.root.Raw},
			)))
		})
	}
}
