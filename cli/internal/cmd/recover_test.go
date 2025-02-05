/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRecoveryKeySigner(t *testing.T) {
	testCases := map[string]struct {
		keyFlag string
		fs      afero.Fs
		wantErr bool
	}{
		"PKCS #8 key": {
			keyFlag: "private.pem",
			fs: func() afero.Fs {
				fs := afero.NewMemMapFs()
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				privRaw, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				privPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: privRaw,
				})
				require.NoError(t, afero.WriteFile(fs, "private.pem", privPEM, 0o644))
				return fs
			}(),
		},
		"PKCS #1 key": {
			keyFlag: "private.pem",
			fs: func() afero.Fs {
				fs := afero.NewMemMapFs()
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				privRaw := x509.MarshalPKCS1PrivateKey(privKey)
				privPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: privRaw,
				})
				require.NoError(t, afero.WriteFile(fs, "private.pem", privPEM, 0o644))
				return fs
			}(),
		},
		"no key file": {
			keyFlag: "private.pem",
			fs:      afero.NewMemMapFs(),
			wantErr: true,
		},
		"invalid key file": {
			keyFlag: "private.pem",
			fs: func() afero.Fs {
				fs := afero.NewMemMapFs()
				require.NoError(t, afero.WriteFile(fs, "private.pem", []byte("invalid"), 0o644))
				return fs
			}(),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := NewRecoverCmd()
			require.NoError(t, cmd.Flags().Set("key", tc.keyFlag))

			signer, cancel, err := getRecoveryKeySigner(cmd, afero.Afero{Fs: tc.fs})
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.NotNil(signer)
			assert.NotNil(cancel)
			assert.NoError(cancel())
		})
	}
}
