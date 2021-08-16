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
