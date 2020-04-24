package cmd

import (
	"log"
	"net"

	"google.golang.org/grpc/credentials"

	"edgeless.systems/mesh/coordinator/rpc"

	"edgeless.systems/mesh/coordinator"
	"edgeless.systems/mesh/coordinator/quote"
	"google.golang.org/grpc"
)

func ensure(err error) {
	log.Fatalln(err)
}

type dummyValidator struct{}

func (*dummyValidator) Validate([]byte, []byte, quote.PackageProperties, quote.InfrastructureProperties) error {
	return nil
}

func main() {
	// TODO: parse args
	const orgName string = "edgeless"

	// TODO: use proper quote validator/issuer
	core, err := coordinator.NewCore(orgName, &dummyValidator{}, quote.NewMockIssuer())
	ensure(err)
	cert, err := core.GetTLSCertificate()
	ensure(err)

	creds := credentials.NewServerTLSFromCert(cert)
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	rpc.RegisterNodeServer(grpcServer, core)
	socket, err := net.Listen("tcp", "localhost:50051")
	ensure(err)
	ensure(grpcServer.Serve(socket))
}
