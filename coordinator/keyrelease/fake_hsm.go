//go:build fakehsm

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"bytes"
	"context"
)

// requestKey requests the release of a key from Azure Key Vault by providing
// an Azure attestation token. The policy on the key must allow release based
// on the claims in the provided token.
func (k *KeyReleaser) requestKey(_ context.Context) error {
	k.log.Warn("Binary was built with fake hsm. Using static key")
	k.hsmSealingKey = bytes.Repeat([]byte{0x00, 0xFF}, 16)
	return nil
}
