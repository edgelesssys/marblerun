// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package wrapper

import (
	"context"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestStoreWrapper(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	store := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "")
	rawManifest := []byte(test.ManifestJSON)
	curState := state.AcceptingManifest
	testSecret := manifest.Secret{
		Type:   manifest.SecretTypeSymmetricKey,
		Size:   16,
		Shared: true,
	}
	someCert, somePrivK, err := crypto.GenerateCert([]string{"192.0.2.1"}, constants.CoordinatorName, nil, nil, nil)
	require.NoError(err)
	testUserCert, _, err := crypto.GenerateCert([]string{"192.0.2.2"}, "test-user", nil, nil, nil)
	require.NoError(err)
	testUser := user.NewUser("test-user", testUserCert)

	// save values to store
	data := New(store)
	tx, err := store.BeginTransaction(ctx)
	assert.NoError(err)
	txdata := New(tx)
	assert.NoError(txdata.PutCertificate("some-cert", someCert))
	assert.NoError(txdata.PutPrivateKey("some-key", somePrivK))
	assert.NoError(txdata.PutRawManifest(rawManifest))
	assert.NoError(txdata.PutSecret("test-secret", testSecret))
	assert.NoError(txdata.PutState(curState))
	assert.NoError(txdata.PutUser(testUser))
	assert.NoError(tx.Commit(ctx))

	// see if we can retrieve them again
	savedCert, err := data.GetCertificate("some-cert")
	require.NoError(err)
	assert.Equal(someCert, savedCert)
	savedKey, err := data.GetPrivateKey("some-key")
	require.NoError(err)
	assert.Equal(somePrivK, savedKey)
	savedManifest, err := data.GetRawManifest()
	require.NoError(err)
	assert.Equal(rawManifest, savedManifest)
	savedSecret, err := data.GetSecret("test-secret")
	require.NoError(err)
	assert.Equal(testSecret, savedSecret)
	savedState, err := data.GetState()
	require.NoError(err)
	assert.Equal(curState, savedState)
	savedUser, err := data.GetUser("test-user")
	require.NoError(err)
	assert.Equal(testUser, savedUser)
}

func TestStoreWrapperRollback(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	stor := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "")
	data := New(stor)

	startingState := state.AcceptingManifest
	tx, err := stor.BeginTransaction(ctx)
	require.NoError(err)
	require.NoError(New(tx).PutState(state.AcceptingManifest))
	require.NoError(tx.Commit(ctx))

	tx, err = stor.BeginTransaction(ctx)
	require.NoError(err)
	require.NoError(New(tx).PutState(state.AcceptingMarbles))
	require.NoError(New(tx).PutRawManifest([]byte("manifes")))
	tx.Rollback()

	val, err := data.GetState()
	assert.NoError(err)
	assert.Equal(startingState, val)
	_, err = data.GetRawManifest()
	assert.ErrorIs(err, store.ErrValueUnset)
}
