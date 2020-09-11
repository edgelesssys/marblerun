package server

import (
	"net/http/httptest"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/stretchr/testify/assert"
)

func TestSimple(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	c, err := core.NewCore("edgeless", validator, issuer)
	if err != nil {
		panic(err)
	}

	mux := CreateServeMux(c)

	req := httptest.NewRequest("GET", "http://localhost:25555/status", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(200, resp.StatusCode)

}
