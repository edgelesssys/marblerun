package updateLog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateLog(t *testing.T) {
	assert := assert.New(t)

	testString := "Marblerun Unit Test"

	log, err := New()
	assert.NoError(err)
	log.Info(testString)
	assert.Contains(log.String(), testString)
	err = log.StringSink.Sync()
	assert.NoError(err)
	err = log.StringSink.Close()
	assert.NoError(err)
}
