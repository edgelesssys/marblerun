package core

import (
	"crypto/tls"
	"net"

	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RunGRPCServer starts a gRPC with the given Coordinator core.
// `address` is the desired TCP address like "localhost:0".
// The effective TCP address is returned via `addrChan`.
func RunGRPCServer(core *Core, addr string, addrChan chan string, errChan chan error) {
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
