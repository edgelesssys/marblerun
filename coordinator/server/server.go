package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

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
func CreateServeMux(core *core.Core) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/quote", func(w http.ResponseWriter, r *http.Request) {
		report := "hello world"
		fmt.Println("/quote hit")
		if len(report) == 0 {
			http.Error(w, "failed to get quote", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(report))
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
