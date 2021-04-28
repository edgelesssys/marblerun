package cmd

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(handler http.Handler) (server *httptest.Server, addr string, cert *pem.Block) {
	s := httptest.NewTLSServer(handler)
	return s, s.Listener.Addr().String(), &pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}
}

func TestPromptYesNo(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	var stdin bytes.Buffer

	stdin.Write([]byte("y\n"))
	approved, err := promptYesNo(&stdin, promptForChanges)
	require.NoError(err)
	assert.True(approved)

	// Typos are intentional to test if strings are lowercased later correctly
	stdin.Reset()
	stdin.Write([]byte("yEs\n"))
	approved, err = promptYesNo(&stdin, promptForChanges)
	require.NoError(err)
	assert.True(approved)

	stdin.Reset()
	stdin.Write([]byte("n\n"))
	approved, err = promptYesNo(&stdin, promptForChanges)
	require.NoError(err)
	assert.False(approved)

	stdin.Reset()
	stdin.Write([]byte("nO\n"))
	approved, err = promptYesNo(&stdin, promptForChanges)
	require.NoError(err)
	assert.False(approved)

	stdin.Reset()
	stdin.Write([]byte("ja\n"))
	approved, err = promptYesNo(&stdin, promptForChanges)
	require.NoError(err)
	assert.False(approved)
}
