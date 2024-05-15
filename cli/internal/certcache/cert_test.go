// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package certcache

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveCoordinatorCachedCert(t *testing.T) {
	defaultFlags := func() *pflag.FlagSet {
		flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flagSet.String("coordinator-cert", "cert", "")
		return flagSet
	}

	testCases := map[string]struct {
		flags        *pflag.FlagSet
		root         *x509.Certificate
		intermediate *x509.Certificate
		fs           afero.Fs
		wantErr      bool
	}{
		"write error": {
			flags: defaultFlags(),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			intermediate: &x509.Certificate{
				Raw: []byte("INTERMEDIATE CERTIFICATE"),
			},
			fs:      afero.NewReadOnlyFs(afero.NewMemMapFs()),
			wantErr: true,
		},
		"success": {
			flags: defaultFlags(),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			intermediate: &x509.Certificate{
				Raw: []byte("INTERMEDIATE CERTIFICATE"),
			},
			fs: afero.NewMemMapFs(),
		},
		"cert flag not defined": {
			flags: pflag.NewFlagSet("test", pflag.ContinueOnError),
			root: &x509.Certificate{
				Raw: []byte("ROOT CERTIFICATE"),
			},
			intermediate: &x509.Certificate{
				Raw: []byte("INTERMEDIATE CERTIFICATE"),
			},
			fs:      afero.NewMemMapFs(),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			err := SaveCoordinatorCachedCert(tc.flags, tc.fs, tc.root, tc.intermediate)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			certLocation, err := tc.flags.GetString("coordinator-cert")
			require.NoError(err)
			data, err := afero.ReadFile(tc.fs, certLocation)
			require.NoError(err)
			assert.Equal(2, strings.Count(string(data), "-----BEGIN CERTIFICATE-----"))
		})
	}
}

func TestLoadCoordinatorCachedCert(t *testing.T) {
	defaultCertName := "cert"
	defaultFlags := func() *pflag.FlagSet {
		flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flagSet.String("coordinator-cert", defaultCertName, "")
		flagSet.Bool("insecure", false, "")
		return flagSet
	}
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	testCert, err := x509.CreateCertificate(rand.Reader, certTpl, certTpl, testKey.Public(), testKey)
	require.NoError(t, err)

	testCases := map[string]struct {
		flags   *pflag.FlagSet
		fs      afero.Fs
		wantErr bool
	}{
		"success": {
			flags: defaultFlags(),
			fs: func() afero.Fs {
				fs := afero.NewMemMapFs()
				err := afero.WriteFile(fs, defaultCertName,
					append(
						pem.EncodeToMemory(
							&pem.Block{
								Type:  "CERTIFICATE",
								Bytes: testCert,
							},
						),
						pem.EncodeToMemory(
							&pem.Block{
								Type:  "CERTIFICATE",
								Bytes: testCert,
							},
						)...,
					), 0o644)
				require.NoError(t, err)
				return fs
			}(),
		},
		"incomplete cert chain": {
			flags: defaultFlags(),
			fs: func() afero.Fs {
				fs := afero.NewMemMapFs()
				err := afero.WriteFile(fs, defaultCertName, pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: testCert,
				}), 0o644)
				require.NoError(t, err)
				return fs
			}(),
			wantErr: true,
		},
		"cert flag not defined": {
			flags: func() *pflag.FlagSet {
				flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
				flagSet.Bool("insecure", false, "")
				return flagSet
			}(),
			fs: func() afero.Fs {
				fs := afero.NewMemMapFs()
				err := afero.WriteFile(fs, defaultCertName, pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("cert"),
				}), 0o644)
				require.NoError(t, err)
				return fs
			}(),
			wantErr: true,
		},
		"insecure flag not defined": {
			flags: func() *pflag.FlagSet {
				flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
				flagSet.String("coordinator-cert", defaultCertName, "")
				return flagSet
			}(),
			fs: func() afero.Fs {
				fs := afero.NewMemMapFs()
				err := afero.WriteFile(fs, defaultCertName, pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("cert"),
				}), 0o644)
				require.NoError(t, err)
				return fs
			}(),
			wantErr: true,
		},
		"no cert": {
			flags:   defaultFlags(),
			fs:      afero.NewMemMapFs(),
			wantErr: true,
		},
		"insecure flag disables cert loading": {
			flags: func() *pflag.FlagSet {
				flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
				flagSet.String("coordinator-cert", defaultCertName, "")
				flagSet.Bool("insecure", true, "")
				return flagSet
			}(),
			fs: afero.NewMemMapFs(),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			root, intermediate, err := LoadCoordinatorCachedCert(tc.flags, tc.fs)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			insecure, err := tc.flags.GetBool("insecure")
			require.NoError(err)
			if !insecure {
				assert.NotNil(root)
				assert.NotNil(intermediate)
			}
		})
	}
}
