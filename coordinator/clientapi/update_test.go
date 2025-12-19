/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"bytes"
	"context"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateSecrets(t *testing.T) {
	testManifest := func() manifest.Manifest {
		return manifest.Manifest{
			Secrets: map[string]manifest.Secret{
				"secret-b": {
					Type: manifest.SecretTypeSymmetricKey,
					Size: 256,
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
		wantChanged   []string
		wantErr       bool
	}{
		"success": {
			manifest: testManifest(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core: &fakeCore{},
		},
		"rotate root secret": {
			manifest: func() manifest.Manifest {
				m := testManifest()
				m.Config.RotateRootSecret = true
				return m
			}(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core: &fakeCore{},
		},
		"root secret rotation updates symmetric keys": {
			manifest: func() manifest.Manifest {
				m := testManifest()
				m.Secrets["secret-d"] = manifest.Secret{
					Type:   manifest.SecretTypeSymmetricKey,
					Shared: true,
					Size:   256,
				}
				m.Config.RotateRootSecret = true
				return m
			}(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
				r.NoError(w.PutSecret("secret-d", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Shared:  true,
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core:        &fakeCore{},
			wantChanged: []string{"secret-d"},
		},
		"rotate root secret with secret definition change": {
			manifest: func() manifest.Manifest {
				m := testManifest()
				m.Secrets["secret-d"] = manifest.Secret{
					Type:   manifest.SecretTypeSymmetricKey,
					Shared: true,
					Size:   128,
				}
				m.Config.RotateRootSecret = true
				return m
			}(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
				r.NoError(w.PutSecret("secret-d", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Shared:  true,
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core:        &fakeCore{},
			wantChanged: []string{"secret-d"},
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
					Size:        256,
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
					Size: 256,
				}
				return m
			}(),
			prepareStore: func(r *require.Assertions, w wrapper.Wrapper) {
				r.NoError(w.PutSecret("secret-a", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
				r.NoError(w.PutSecret("secret-d", manifest.Secret{
					Type:    manifest.SecretTypeSymmetricKey,
					Size:    256,
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
					Size:    256,
					Private: bytes.Repeat([]byte{0x01}, 32),
					Public:  bytes.Repeat([]byte{0x01}, 32),
				}))
			},
			core:    &fakeCore{generateSecretsErr: assert.AnError},
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

			rootSecret, err := wrapper.GetRootSecret()
			require.NoError(err)
			rootCert, err := wrapper.GetCertificate(constants.SKCoordinatorRootCert)
			require.NoError(err)
			rootKey, err := wrapper.GetPrivateKey(constants.SKCoordinatorRootKey)
			require.NoError(err)
			intermediateCert, err := wrapper.GetCertificate(constants.SKCoordinatorIntermediateCert)
			require.NoError(err)
			intermediateKey, err := wrapper.GetPrivateKey(constants.SKCoordinatorIntermediateKey)
			require.NoError(err)
			marbleCert, err := wrapper.GetCertificate(constants.SKMarbleRootCert)
			require.NoError(err)

			if tc.prepareStore != nil {
				tc.prepareStore(require, wrapper)
			}

			wantUnchanged := make(map[string]manifest.Secret)
			for _, name := range tc.wantUnchanged {
				secret, err := wrapper.GetSecret(name)
				require.NoError(err)
				wantUnchanged[name] = secret
			}

			// Get a list of all secrets currently in the store and in the new manifest
			// These should all be present in previous secrets after the update
			originalSecrets, err := wrapper.GetSecretMap()
			require.NoError(err)

			err = api.updateSecrets(wrapper, tc.manifest)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(commit(ctx))

			newRootCert := testutil.GetCertificate(t, api.txHandle, constants.SKCoordinatorRootCert)
			assert.Equal(rootCert, newRootCert, "root certificate should be unchanged")
			newRootKey := testutil.GetPrivateKey(t, api.txHandle, constants.SKCoordinatorRootKey)
			assert.Equal(rootKey, newRootKey, "root private key should be unchanged")
			newIntermediateCert := testutil.GetCertificate(t, api.txHandle, constants.SKCoordinatorIntermediateCert)
			assert.NotEqual(intermediateCert, newIntermediateCert)
			newIntermediateKey := testutil.GetPrivateKey(t, api.txHandle, constants.SKCoordinatorIntermediateKey)
			assert.NotEqual(intermediateKey, newIntermediateKey)
			newMarbleCert := testutil.GetCertificate(t, api.txHandle, constants.SKMarbleRootCert)
			assert.NotEqual(marbleCert, newMarbleCert)
			previousRootSecret := testutil.GetPreviousRootSecret(t, api.txHandle)
			assert.Equal(rootSecret, previousRootSecret, "root secret should be saved as previous root secret")
			newRootSecret := testutil.GetRootSecret(t, api.txHandle)

			if tc.manifest.Config.RotateRootSecret {
				assert.NotEqual(rootSecret, newRootSecret, "root secret should have rotated")
			} else {
				assert.Equal(rootSecret, newRootSecret, "root secret should be unchanged")
			}

			for name := range tc.manifest.Secrets {
				testutil.GetSecret(t, api.txHandle, name)
			}

			savedSecrets := testutil.GetSecretMap(t, api.txHandle)
			assert.Equal(len(tc.manifest.Secrets), len(savedSecrets))
			savedPreviousSecrets := testutil.GetPreviousSecretMap(t, api.txHandle)
			assert.Equal(len(tc.manifest.Secrets), len(savedPreviousSecrets), "all current secrets should also be in previous secrets")

			for name, originalSecret := range originalSecrets {
				if savedSecret, ok := savedPreviousSecrets[name]; ok {
					assert.Equalf(originalSecret, savedSecret, "previous secret does not match expected for %s", name)
				} else {
					_, ok := savedSecrets[name]
					assert.Falsef(ok, "secret %s should have been deleted", name)
				}
			}

			for name, secret := range wantUnchanged {
				newSecret := testutil.GetSecret(t, api.txHandle, name)
				assert.True(secret.Equal(newSecret))
			}

			for _, name := range tc.wantChanged {
				assert.NotEqualf(originalSecrets[name], savedSecrets[name], "secret %s should have changed", name)
			}
		})
	}
}
