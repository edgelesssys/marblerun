/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package multiupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// RequestPendingUpdate is the request type for pending updates.
const RequestPendingUpdate = "pendingUpdate"

// MultiPartyUpdate handles multi-party updates to the manifest.
type MultiPartyUpdate struct {
	manifestRaw            []byte
	requiredUsers          map[string]bool
	missingAcknowledgments int
}

// New creates a new MultiPartyUpdate.
func New(manifest []byte, requiredUsers []string, missingAcknowledgments int) *MultiPartyUpdate {
	m := &MultiPartyUpdate{
		manifestRaw:   manifest,
		requiredUsers: make(map[string]bool),
	}
	for _, user := range requiredUsers {
		m.requiredUsers[user] = false
	}
	m.missingAcknowledgments = missingAcknowledgments
	return m
}

// MarshalJSON marshals the MultiPartyUpdate to JSON string.
func (m *MultiPartyUpdate) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ManifestRaw            []byte          `json:"manifestRaw"`
		RequiredUsers          map[string]bool `json:"requiredUsers"`
		MissingAcknowledgments *int            `json:"missingAcknowledgments,omitempty"`
	}{
		ManifestRaw:            m.manifestRaw,
		RequiredUsers:          m.requiredUsers,
		MissingAcknowledgments: &m.missingAcknowledgments,
	})
}

// UnmarshalJSON unmarshals the MultiPartyUpdate from a JSON string.
func (m *MultiPartyUpdate) UnmarshalJSON(data []byte) error {
	var tmp struct {
		ManifestRaw            []byte          `json:"manifestRaw"`
		RequiredUsers          map[string]bool `json:"requiredUsers"`
		MissingAcknowledgments *int            `json:"missingAcknowledgments,omitempty"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	m.manifestRaw = tmp.ManifestRaw
	m.requiredUsers = tmp.RequiredUsers

	if tmp.MissingAcknowledgments == nil {
		m.missingAcknowledgments = len(m.MissingUsers()) // Fallback in case the field is not set.
	} else {
		m.missingAcknowledgments = *tmp.MissingAcknowledgments
	}
	return nil
}

// Manifest returns the manifest set for the update.
func (m *MultiPartyUpdate) Manifest() []byte {
	return m.manifestRaw
}

// ManifestFingerprint returns the SHA256 hash of the manifest.
func (m *MultiPartyUpdate) ManifestFingerprint() string {
	hash := sha256.Sum256(m.manifestRaw)
	return hex.EncodeToString(hash[:])
}

// MissingAcknowledgments returns the number of missing acknowledgments.
func (m *MultiPartyUpdate) MissingAcknowledgments() int {
	return m.missingAcknowledgments
}

// MissingUsers returns a list of users that have not yet acknowledged the update.
func (m *MultiPartyUpdate) MissingUsers() []string {
	var missing []string

	for user, ack := range m.requiredUsers {
		if !ack {
			missing = append(missing, user)
		}
	}
	return missing
}

// AddAcknowledgment adds an acknowledgment for a user.
func (m *MultiPartyUpdate) AddAcknowledgment(updateManifest []byte, user string) error {
	if _, ok := m.requiredUsers[user]; !ok {
		return fmt.Errorf("user %s is not allowed to acknowledge manifest updates", user)
	}
	if !bytes.Equal(m.manifestRaw, updateManifest) {
		return errors.New("provided manifest does not match the pending manifest")
	}

	if !m.requiredUsers[user] {
		m.missingAcknowledgments--
	}
	m.requiredUsers[user] = true
	return nil
}
