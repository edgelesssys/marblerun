package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/test"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestStoreWrapperMetrics(t *testing.T) {
	assert := assert.New(t)

	noStore := NoStore{}
	reg := prometheus.NewRegistry()
	fac := promauto.With(reg)
	metrics := NewStoreWrapperMetrics(&fac, "test", "")
	sw := storeWrapper{noStore, metrics}

	stateList := map[string]state{ // using map to get randomized order
		"1":  stateUninitialized,
		"2":  stateRecovery,
		"3":  stateAcceptingManifest,
		"4":  stateAcceptingMarbles,
		"5":  stateMax,
		"6":  stateUninitialized,
		"7":  stateRecovery,
		"8":  stateAcceptingManifest,
		"9":  stateAcceptingMarbles,
		"10": stateMax,
	}
	assert.Equal(1, promtest.CollectAndCount(metrics.coordinatorState))
	assert.Equal(float64(0), promtest.ToFloat64(metrics.coordinatorState))
	for _, state := range stateList {
		sw.putState(state)
		assert.Equal(1, promtest.CollectAndCount(metrics.coordinatorState))
		assert.Equal(float64(state), promtest.ToFloat64(metrics.coordinatorState))
	}
}

type NoStore struct{}

func (s NoStore) Get(str string) ([]byte, error) {
	return []byte{}, nil
}
func (s NoStore) Put(str string, b []byte) error {
	return nil
}

func TestMarbleAPIMetrics(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()
	promRegistry := prometheus.NewRegistry()
	promFactory := promauto.With(promRegistry)
	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, &promFactory)
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
	uuid := spawner.newMarble("backend_first", "Azure", false)
	promtest.CollectAndCount(metrics.activation)
	promtest.CollectAndCount(metrics.activationSuccess)
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activation.WithLabelValues("backend_first", uuid)))
	assert.Equal(float64(0), promtest.ToFloat64(metrics.activationSuccess.WithLabelValues("backend_first", uuid)))

	// set manifest
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// activate first backend
	uuid = spawner.newMarble("backend_first", "Azure", true)
	promtest.CollectAndCount(metrics.activation)
	promtest.CollectAndCount(metrics.activationSuccess)
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activation.WithLabelValues("backend_first", uuid)))
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activationSuccess.WithLabelValues("backend_first", uuid)))

	// try to activate another first backend
	uuid = spawner.newMarble("backend_first", "Azure", false)
	promtest.CollectAndCount(metrics.activation)
	promtest.CollectAndCount(metrics.activationSuccess)
	assert.Equal(float64(1), promtest.ToFloat64(metrics.activation.WithLabelValues("backend_first", uuid)))
	assert.Equal(float64(0), promtest.ToFloat64(metrics.activationSuccess.WithLabelValues("backend_first", uuid)))
}
