/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper/testutil"
	"github.com/edgelesssys/marblerun/test"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestStoreWrapperMetrics(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	zapLogger := zaptest.NewLogger(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	store := stdstore.New(sealer, fs, "", zapLogger)
	recovery := recovery.New(store, zapLogger)

	//
	// Test unset restart and set manifest.
	//
	reg := prometheus.NewRegistry()
	fac := promauto.With(reg)
	c, _ := NewCore([]string{"localhost"}, validator, issuer, store, recovery, zapLogger, &fac, nil)
	assert.Equal(1, promtest.CollectAndCount(c.metrics.coordinatorState))
	assert.Equal(float64(state.AcceptingManifest), promtest.ToFloat64(c.metrics.coordinatorState))

	clientAPI, err := clientapi.New(c.txHandle, c.recovery, c, &distributor.Stub{}, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	assert.Equal(1, promtest.CollectAndCount(c.metrics.coordinatorState))
	assert.Equal(float64(state.AcceptingMarbles), promtest.ToFloat64(c.metrics.coordinatorState))

	//
	// Test sealing and recovery.
	//
	reg = prometheus.NewRegistry()
	fac = promauto.With(reg)
	sealer.UnsealError = &seal.EncryptionKeyError{}
	c, err = NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer, fs, "", zapLogger), recovery, zapLogger, &fac, nil)
	sealer.UnsealError = nil
	require.NoError(err)
	assert.Equal(1, promtest.CollectAndCount(c.metrics.coordinatorState))
	assert.Equal(float64(state.Recovery), promtest.ToFloat64(c.metrics.coordinatorState))

	clientAPI, err = clientapi.New(c.txHandle, c.recovery, c, &distributor.Stub{}, zapLogger)
	require.NoError(err)

	key, sig := recoveryKeyWithSignature(t, test.RecoveryPrivateKeyOne)
	_, err = clientAPI.Recover(ctx, key, sig)
	require.NoError(err)
	state := testutil.GetState(t, c.txHandle)
	assert.Equal(1, promtest.CollectAndCount(c.metrics.coordinatorState))
	assert.Equal(float64(state), promtest.ToFloat64(c.metrics.coordinatorState))
}

func TestMarbleAPIMetrics(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	zapLogger := zaptest.NewLogger(t)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	store := stdstore.New(sealer, afero.NewMemMapFs(), "", zapLogger)
	recovery := recovery.New(store, zapLogger)
	promRegistry := prometheus.NewRegistry()
	promFactory := promauto.With(promRegistry)
	c, err := NewCore([]string{"localhost"}, validator, issuer, store, recovery, zapLogger, &promFactory, nil)
	require.NoError(err)
	require.NotNil(c)

	metrics := c.metrics.marbleAPI
	assert.Equal(0, promtest.CollectAndCount(metrics.activation))
	assert.Equal(0, promtest.CollectAndCount(metrics.activationSuccess))

	spawner := marbleSpawner{
		assert:     assert,
		require:    require,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		coreServer: c,
	}

	// try to activate first backend marble prematurely before manifest is set
	marbleUUID := uuid.New()
	spawner.newMarble(t, "backendFirst", "Azure", marbleUUID, false)
	promtest.CollectAndCount(metrics.activation)
	promtest.CollectAndCount(metrics.activationSuccess)
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activation.WithLabelValues("backendFirst", marbleUUID.String())))
	assert.Equal(float64(0), promtest.ToFloat64(metrics.activationSuccess.WithLabelValues("backendFirst", marbleUUID.String())))

	// set manifest
	clientAPI, err := clientapi.New(c.txHandle, c.recovery, c, &distributor.Stub{}, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(context.Background(), []byte(test.ManifestJSON))
	require.NoError(err)

	// activate first backend
	marbleUUID = uuid.New()
	spawner.newMarble(t, "backendFirst", "Azure", marbleUUID, true)
	promtest.CollectAndCount(metrics.activation)
	promtest.CollectAndCount(metrics.activationSuccess)
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activation.WithLabelValues("backendFirst", marbleUUID.String())))
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activationSuccess.WithLabelValues("backendFirst", marbleUUID.String())))

	// try to activate another first backend
	marbleUUID = uuid.New()
	spawner.newMarble(t, "backendFirst", "Azure", marbleUUID, false)
	promtest.CollectAndCount(metrics.activation)
	promtest.CollectAndCount(metrics.activationSuccess)
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activation.WithLabelValues("backendFirst", marbleUUID.String())))
	assert.Equal(float64(0), promtest.ToFloat64(metrics.activationSuccess.WithLabelValues("backendFirst", marbleUUID.String())))
}
