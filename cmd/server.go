package cmd

import (
	"crypto/tls"
	"log"
	"net"

	"edgeless.systems/mesh/coordinator/rpc"

	"edgeless.systems/mesh/coordinator"
	"edgeless.systems/mesh/coordinator/quote"
	"google.golang.org/grpc"
)

func ensure(err error) {
	log.Fatalln(err)
}

func main() {
	// TODO: parse args
	const orgName string = "edgeless"

	// TODO: use proper quote validator/issuer
	core, err := coordinator.NewCore(orgName, quote.NewMockValidator(), quote.NewMockIssuer())
	ensure(err)

	creds := NewServerTLSFromCert(core.Cert)
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	rpc.RegisterNodeServer(grpcServer, core)
	socket, err := net.Listen("tcp", "localhost:50051")
	ensure(err)
	ensure(grpcServer.Serve(socket))
}
