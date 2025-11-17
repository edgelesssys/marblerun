/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyclient

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
	discoveryv1 "k8s.io/api/discovery/v1"
	testclock "k8s.io/utils/clock/testing"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestKeyClient(t *testing.T) {
	testCases := map[string]struct {
		endpointGetter *stubEndpointGetter
		keyRequest     *stubKeyRequest
		wantCancel     bool
		wantKey        bool
	}{
		"success": {
			endpointGetter: &stubEndpointGetter{
				endpoints: []string{"endpoint"},
			},
			keyRequest: &stubKeyRequest{
				key: []byte("key"),
			},
			wantKey: true,
		},
		"cancelled": {
			endpointGetter: &stubEndpointGetter{
				endpoints: []string{"endpoint"},
			},
			keyRequest: &stubKeyRequest{
				err: assert.AnError,
			},
			wantCancel: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			clock := &testclock.FakeClock{}
			log := zaptest.NewLogger(t)

			keyClient := &KeyClient{
				endpointGetter: tc.endpointGetter,
				keyRequester:   tc.keyRequest,
				interval:       100 * time.Millisecond,
				clock:          clock,
				log:            log,
			}

			var key []byte
			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wg.Add(1)
			go func() {
				defer wg.Done()
				key = keyClient.Run(ctx, "service", "namespace")
			}()

			clock.Step(200 * time.Millisecond)
			if tc.wantCancel {
				cancel()
			}
			wg.Wait()

			assert.Equal(tc.wantKey, key != nil)
		})
	}
}

func TestGetEndpoints(t *testing.T) {
	testCases := map[string]struct {
		kubectl *stubKubectl
		want    []string
		wantErr bool
	}{
		"success": {
			kubectl: &stubKubectl{
				endpoints: discoveryv1.EndpointSlice{
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{
								"192.0.2.1",
							},
						},
					},
					Ports: []discoveryv1.EndpointPort{
						{
							Port: toPtr(80),
						},
						{
							Port: toPtr(8080),
						},
					},
				},
			},
			want: []string{"192.0.2.1:80", "192.0.2.1:8080"},
		},
		"error": {
			kubectl: &stubKubectl{
				err: assert.AnError,
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			endpointGetter := &k8sEndpointGetter{
				client: tc.kubectl,
			}

			endpoints, err := endpointGetter.getEndpoints(context.Background(), "service", "namespace")
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.ElementsMatch(tc.want, endpoints)
		})
	}
}

func toPtr(i int32) *int32 {
	return &i
}

type stubEndpointGetter struct {
	endpoints []string
	err       error
}

func (s *stubEndpointGetter) getEndpoints(_ context.Context, _, _ string) ([]string, error) {
	return s.endpoints, s.err
}

type stubKubectl struct {
	endpoints discoveryv1.EndpointSlice
	err       error
}

func (s *stubKubectl) getEndpoints(_ context.Context, _, _ string) (discoveryv1.EndpointSlice, error) {
	return s.endpoints, s.err
}

type stubKeyRequest struct {
	key []byte
	err error
}

func (r *stubKeyRequest) requestKey(_ context.Context, _ string, _ *tls.Config) ([]byte, error) {
	return r.key, r.err
}
