// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package updatelog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateLog(t *testing.T) {
	assert := assert.New(t)

	testString := "MarbleRun Unit Test"

	log, err := New()
	assert.NoError(err)
	log.Info(testString)
	assert.Contains(log.String(), testString)
	err = log.Sync()
	assert.NoError(err)
	err = log.Close()
	assert.NoError(err)
}
