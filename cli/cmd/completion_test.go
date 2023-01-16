// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCliCompletion(t *testing.T) {
	assert := assert.New(t)

	bashCompletion, err := cliCompletion("bash", NewRootCmd())
	assert.NoError(err)
	assert.Contains(bashCompletion, "# bash completion for marblerun")

	// fishCompletion, err := cliCompletion("fish", rootCmd)
	// assert.NoError(err)
	// assert.Contains(fishCompletion, "# fish completion for marblerun")

	zshCompletion, err := cliCompletion("zsh", NewRootCmd())
	assert.NoError(err)
	assert.Contains(zshCompletion, "# zsh completion for marblerun")

	_, err = cliCompletion("unsupported-shell", NewRootCmd())
	assert.Error(err)
}
