/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateSecrets(t *testing.T) {
	someErr := errors.New("failed")
	testManifest := func() manifest.Manifest {
		return manifest.Manifest{
			Secrets: map[string]manifest.Secret{
				"secret-b": {
					Type: manifest.SecretTypeSymmetricKey,
					Size: 32,
				},
				"secret-c": {
					Type: manifest.SecretTypeCertRSA,
					Size: 2048,
				},
			},
		}
	}

	testCases := map[string]struct {
		manifest      manifest.Manifest
		prepareStore  func(*require.Assertions, wrapper.Wrapper)
		core          *fakeCore
		wantUnchanged []string
		wantErr       bool
	}{
		"success": {
			manifest: testManifest(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    32,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core: &fakeCore{},
		},
		"user defined secrets": {
			manifest: func() manifest.Manifest {
				m := testManifest()
				m.Secrets["secret-d"] = manifest.Secret{
					Type:        manifest.SecretTypePlain,
					UserDefined: true,
				}
				m.Secrets["secret-e"] = manifest.Secret{
					Type:        manifest.SecretTypePlain,
					UserDefined: true,
				}
				return m
			}(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:        manifest.SecretTypeSymmetricKey,
					Size:        32,
					UserDefined: true,
					Private:     bytes.Repeat([]byte{0x01}, 32),
					Public:      bytes.Repeat([]byte{0x01}, 32),
				}))
				r.NoError(w.PutSecret("secret-d", manifest.Secret{
					Type:        manifest.SecretTypePlain,
					UserDefined: true,
					Private:     bytes.Repeat([]byte{0x01}, 32),
					Public:      bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core:          &fakeCore{},
			wantUnchanged: []string{"secret-d"},
		},
		"mixed secrets": {
			manifest: func() manifest.Manifest {
				m := testManifest()
				m.Secrets["secret-d"] = manifest.Secret{
					Type: manifest.SecretTypeSymmetricKey,
					Size: 32,
				}
				return m
			}(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    32,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
				r.NoError(w.PutSecret("secret-d", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    32,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core:          &fakeCore{},
			wantUnchanged: []string{"secret-d"},
		},
		"missing root cert": {
			manifest: testManifest(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.DeleteCertificate(constants.SKCoordinatorRootCert))
			},
			wantErr: true,
		},
		"GenerateSecrets fails": {
			manifest: testManifest(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    32,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core:    &fakeCore{generateSecretsErr: someErr},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			ctx := context.Background()

			api, _ := setupAPI(t, tc.core)

			wrapper, rollback, commit, err := wrapper.WrapTransaction(ctx, api.txHandle)
			require.NoError(err)
			defer rollback()

			intermediateCert, err := wrapper.GetCertificate(constants.SKCoordinatorIntermediateCert)
			require.NoError(err)
			intermediateKey, err := wrapper.GetPrivateKey(constants.SKCoordinatorIntermediateKey)
			require.NoError(err)
			marbleCert, err := wrapper.GetCertificate(constants.SKMarbleRootCert)
			require.NoError(err)

			if tc.prepareStore != nil {
				tc.prepareStore(require, wrapper)
			}

			originalSecrets := make(map[string]manifest.Secret)
			for _, name := range tc.wantUnchanged {
				secret, err := wrapper.GetSecret(name)
				require.NoError(err)
				originalSecrets[name] = secret
			}

			err = api.updateSecrets(wrapper, tc.manifest)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(commit(ctx))

			newIntermediateCert := testutil.GetCertificate(t, api.txHandle, constants.SKCoordinatorIntermediateCert)
			assert.NotEqual(intermediateCert, newIntermediateCert)
			newIntermediateKey := testutil.GetPrivateKey(t, api.txHandle, constants.SKCoordinatorIntermediateKey)
			assert.NotEqual(intermediateKey, newIntermediateKey)
			newMarbleCert := testutil.GetCertificate(t, api.txHandle, constants.SKMarbleRootCert)
			assert.NotEqual(marbleCert, newMarbleCert)

			savedSecrets := testutil.GetSecretMap(t, api.txHandle)
			assert.Equal(len(tc.manifest.Secrets), len(savedSecrets))

			for name := range tc.manifest.Secrets {
				testutil.GetSecret(t, api.txHandle, name)
			}

			for name, secret := range originalSecrets {
				newSecret := testutil.GetSecret(t, api.txHandle, name)
				assert.True(secret.Equal(newSecret))
			}
		})
	}
}
