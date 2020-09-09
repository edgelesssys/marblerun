package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type certQuoteResp struct {
	Cert  string
	Quote []byte
}
type statusResp struct {
	Status   string
	Signatur []byte
}
type manifestSignatureResp struct {
	ManifestSignature [32]byte
}

// RunMarbleServer starts a gRPC with the given Coordinator core.
// `address` is the desired TCP address like "localhost:0".
// The effective TCP address is returned via `addrChan`.
func RunMarbleServer(core *core.Core, addr string, addrChan chan string, errChan chan error) {
	cert, err := core.GetTLSCertificate()
	if err != nil {
		errChan <- err
		return
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{*cert},
		// NOTE: we'll verify the cert later using the given quote
		ClientAuth: tls.RequireAnyClientCert,
	}
	creds := credentials.NewTLS(&tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	rpc.RegisterMarbleServer(grpcServer, core)
	socket, err := net.Listen("tcp", addr)
	if err != nil {
		errChan <- err
		return
	}
	addrChan <- socket.Addr().String()
	err = grpcServer.Serve(socket)
	if err != nil {
		errChan <- err
	}
}

// CreateServeMux creates a mux that serves the client API. provisionally
func CreateServeMux(cc core.ClientCore) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status, statussignature, err := cc.GetStatus(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusTeapot) //todo figure which status to use.
		}
		strct := statusResp{status, statussignature}
		jsn, err := json.Marshal(strct)
		if err != nil {
			http.Error(w, err.Error(), http.StatusTeapot) //todo figure which status to use.
		}

		io.WriteString(w, string(jsn))
	})
	mux.HandleFunc("/manifestsignature", func(w http.ResponseWriter, r *http.Request) {
		signature, err := cc.GetManifestSignature(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusTeapot) //todo figure which status to use.
		}
		strct := manifestSignatureResp{signature}
		jsn, err := json.Marshal(strct)
		if err != nil {
			http.Error(w, err.Error(), http.StatusTeapot) //todo figure which status to use.
		}
		io.WriteString(w, string(jsn))

	})
	mux.HandleFunc("/certquote", func(w http.ResponseWriter, r *http.Request) {
		cert, certquote, err := cc.GetCertQuote(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusTeapot) //todo figure which status to use.
		}
		strct := certQuoteResp{cert, certquote}
		jsn, err := json.Marshal(strct)
		if err != nil {
			http.Error(w, err.Error(), http.StatusTeapot) //todo figure which status to use.
		}
		io.WriteString(w, string(jsn))
		//io.WriteString(w, string(certquote))
	})
	mux.HandleFunc("/setManifest", func(w http.ResponseWriter, r *http.Request) {
		manifest := r.FormValue("manifest")
		err := cc.SetManifest(r.Context(), []byte(manifest))
		if err != nil {
			http.Error(w, err.Error(), http.StatusTeapot) //todo figure which status to use.
			fmt.Println("errrrrrrrrrrrrrrrrrrrrrrrrrr")
		}
		fmt.Println(manifest)
	})

	return mux
}

// RunClientServer runs a HTTP server serving mux. provisionally
func RunClientServer(mux *http.ServeMux, address string, tlsConfig *tls.Config) {
	server := http.Server{
		Addr:      address,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	fmt.Println("start client server at ", address)
	fmt.Println(server.ListenAndServe())
}
