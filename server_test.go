package coordinator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	var s *Server
	var err error

	t.Run("new", func(t *testing.T) {
		s, err = NewServer("edgeless")
		assert.NotNil(t, s)
		assert.Nil(t, err)
		assert.Equal(t, s.state, acceptingManifest)
		assert.Equal(t, s.cert.Subject.Organization, []string{"edgeless"})
		assert.Equal(t, s.cert.Subject.CommonName, coordinatorName)
	})

	t.Run("set manifest", func(t *testing.T) {

	})
}
