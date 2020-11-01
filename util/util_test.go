// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveKey(t *testing.T) {
	assert := assert.New(t)
	key, err := DeriveKey([]byte("secret"), []byte("salt"))
	assert.NoError(err)
	assert.Len(key, 32)
}

func TestMustGetenv(t *testing.T) {
	assert := assert.New(t)

	const name = "EDG_TEST_MUST_GETENV"
	const value = "foo"

	assert.NoError(os.Setenv(name, value))
	assert.Equal(value, MustGetenv(name))
	assert.NoError(os.Unsetenv(name))
}
