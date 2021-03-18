package cmd

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
)

func newTestServer(handler http.Handler) (server *httptest.Server, addr string, cert *pem.Block) {
	s := httptest.NewTLSServer(handler)
	return s, s.Listener.Addr().String(), &pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}
}
