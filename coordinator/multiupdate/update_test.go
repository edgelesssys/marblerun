/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package multiupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestMarshalJSON(t *testing.T) {
	testCases := map[string]struct {
		input    MultiPartyUpdate
		expected string
	}{
		"empty": {
			input:    MultiPartyUpdate{},
			expected: `{"manifestRaw":null, "requiredUsers":null, "missingAcknowledgments":0}`,
		},
		"with manifest": {
			input: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
			},
			expected: `{"manifestRaw":"bWFuaWZlc3Q=", "requiredUsers":null, "missingAcknowledgments":0}`,
		},
		"with required users": {
			input: MultiPartyUpdate{
				requiredUsers: map[string]bool{
					"user1": true,
					"user2": false,
				},
				missingAcknowledgments: 1,
			},
			expected: `{"manifestRaw":null, "requiredUsers":{"user1":true, "user2":false}, "missingAcknowledgments":1}`,
		},
		"with manifest and required users": {
			input: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
				requiredUsers: map[string]bool{
					"user1": true,
					"user2": false,
				},
				missingAcknowledgments: 1,
			},
			expected: `{"manifestRaw":"bWFuaWZlc3Q=", "requiredUsers":{"user1":true, "user2":false}, "missingAcknowledgments":1}`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			actual, err := tc.input.MarshalJSON()
			require.NoError(err)
			assert.JSONEq(tc.expected, string(actual))
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	testCases := map[string]struct {
		input    string
		expected MultiPartyUpdate
	}{
		"empty": {
			input:    `{"manifestRaw":null, "requiredUsers":null}`,
			expected: MultiPartyUpdate{},
		},
		"with manifest": {
			input: `{"manifestRaw":"bWFuaWZlc3Q=", "requiredUsers":null}`,
			expected: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
			},
		},
		"with required users": {
			input: `{"manifestRaw":null, "requiredUsers":{"user1":true, "user2":false}}`,
			expected: MultiPartyUpdate{
				requiredUsers: map[string]bool{
					"user1": true,
					"user2": false,
				},
				missingAcknowledgments: 1,
			},
		},
		"with manifest and required users": {
			input: `{"manifestRaw":"bWFuaWZlc3Q=", "requiredUsers":{"user1":true, "user2":false}}`,
			expected: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
				requiredUsers: map[string]bool{
					"user1": true,
					"user2": false,
				},
				missingAcknowledgments: 1,
			},
		},
		"missing acknowledgments": {
			input: `{"manifestRaw":null, "requiredUsers":{"user1":false, "user2":false}, "missingAcknowledgments":2}`,
			expected: MultiPartyUpdate{
				requiredUsers: map[string]bool{
					"user1": false,
					"user2": false,
				},
				missingAcknowledgments: 2,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			var actual MultiPartyUpdate
			err := actual.UnmarshalJSON([]byte(tc.input))
			require.NoError(err)
			assert.Equal(tc.expected, actual)
		})
	}
}

func TestMissing(t *testing.T) {
	testCases := map[string]struct {
		input                MultiPartyUpdate
		expectedMissing      int
		expectedMissingUsers []string
	}{
		"no users": {
			input:                MultiPartyUpdate{},
			expectedMissing:      0,
			expectedMissingUsers: []string{},
		},
		"1 user, 0 acks": {
			input: MultiPartyUpdate{
				requiredUsers: map[string]bool{
					"user1": false,
				},
				missingAcknowledgments: 1,
			},
			expectedMissing:      1,
			expectedMissingUsers: []string{"user1"},
		},
		"1 user, 1 ack": {
			input: MultiPartyUpdate{
				requiredUsers: map[string]bool{
					"user1": true,
				},
				missingAcknowledgments: 0,
			},
			expectedMissing:      0,
			expectedMissingUsers: []string{},
		},
		"2 users, 0 acks": {
			input: MultiPartyUpdate{
				requiredUsers: map[string]bool{
					"user1": false,
					"user2": false,
				},
				missingAcknowledgments: 2,
			},
			expectedMissing:      2,
			expectedMissingUsers: []string{"user1", "user2"},
		},
		"2 users, 1 ack": {
			input: MultiPartyUpdate{
				requiredUsers: map[string]bool{
					"user1": true,
					"user2": false,
				},
				missingAcknowledgments: 1,
			},
			expectedMissing:      1,
			expectedMissingUsers: []string{"user2"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			actual := tc.input.MissingAcknowledgments()
			assert.Equal(tc.expectedMissing, actual)

			actualUsers := tc.input.MissingUsers()
			assert.ElementsMatch(tc.expectedMissingUsers, actualUsers)
		})
	}
}

func TestAddAcknowledgment(t *testing.T) {
	testCases := map[string]struct {
		user     string
		mnf      []byte
		input    MultiPartyUpdate
		expected map[string]bool
		wantErr  bool
	}{
		"success": {
			user: "user1",
			mnf:  []byte("manifest"),
			input: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
				requiredUsers: map[string]bool{
					"user1": false,
				},
			},
			expected: map[string]bool{
				"user1": true,
			},
		},
		"success, multiple users": {
			user: "user1",
			mnf:  []byte("manifest"),
			input: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
				requiredUsers: map[string]bool{
					"user1": false,
					"user2": false,
				},
			},
			expected: map[string]bool{
				"user1": true,
				"user2": false,
			},
		},
		"manifest mismatch": {
			user: "user1",
			mnf:  []byte("different manifest"),
			input: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
				requiredUsers: map[string]bool{
					"user1": false,
				},
			},
			wantErr: true,
		},
		"user is not allowed to ack": {
			user: "user1",
			mnf:  []byte("manifest"),
			input: MultiPartyUpdate{
				manifestRaw: []byte("manifest"),
				requiredUsers: map[string]bool{
					"user2": false,
				},
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			err := tc.input.AddAcknowledgment(tc.mnf, tc.user)
			if tc.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tc.expected, tc.input.requiredUsers)
		})
	}
}
