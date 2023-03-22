// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// newTestClient returns *http.Client with Transport replaced to avoid making real calls.
func newTestClient(fn roundTripFunc) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

func TestGet(t *testing.T) {
	require := require.New(t)
	defaultResponseFunc := func(req *http.Request) *http.Response {
		response := server.GeneralResponse{
			Message: "response message",
			Data:    "response data",
		}
		res, err := json.Marshal(response)
		require.NoError(err)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(res)),
			Header:     make(http.Header),
		}
	}

	testCases := map[string]struct {
		roundTripFunc roundTripFunc
		body          io.Reader
		queryParams   []string
		wantResponse  []byte
		wantErr       bool
	}{
		"success": {
			roundTripFunc: defaultResponseFunc,
			wantResponse:  []byte("response data"),
		},
		"success with query params": {
			roundTripFunc: defaultResponseFunc,
			queryParams:   []string{"key1", "value1", "key2", "value2"},
			wantResponse:  []byte("response data"),
		},
		"success with body": {
			roundTripFunc: defaultResponseFunc,
			body:          strings.NewReader("request body"),
			wantResponse:  []byte("response data"),
		},
		"odd number of query params": {
			roundTripFunc: defaultResponseFunc,
			queryParams:   []string{"key1", "value1", "key2"},
			wantErr:       true,
		},
		"server error": {
			roundTripFunc: func(req *http.Request) *http.Response {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(&bytes.Reader{}),
					Header:     make(http.Header),
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			client := &Client{
				client: newTestClient(tc.roundTripFunc),
				host:   "unit-test",
			}

			res, err := client.Get(context.Background(), "unit-test", tc.body, tc.queryParams...)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.Equal(tc.wantResponse, res)
		})
	}
}

func TestPost(t *testing.T) {
	require := require.New(t)
	defaultResponseFunc := func(req *http.Request) *http.Response {
		response := server.GeneralResponse{
			Message: "response message",
			Data:    "response data",
		}
		res, err := json.Marshal(response)
		require.NoError(err)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(res)),
			Header:     make(http.Header),
		}
	}

	testCases := map[string]struct {
		roundTripFunc roundTripFunc
		body          io.Reader
		wantResponse  []byte
		wantErr       bool
	}{
		"success": {
			roundTripFunc: defaultResponseFunc,
			wantResponse:  []byte("response data"),
		},
		"success with body": {
			roundTripFunc: defaultResponseFunc,
			body:          strings.NewReader("request body"),
			wantResponse:  []byte("response data"),
		},
		"server error": {
			roundTripFunc: func(req *http.Request) *http.Response {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(&bytes.Reader{}),
					Header:     make(http.Header),
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			client := &Client{
				client: newTestClient(tc.roundTripFunc),
				host:   "unit-test",
			}

			res, err := client.Post(context.Background(), "unit-test", "test", tc.body)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.Equal(tc.wantResponse, res)
		})
	}
}
