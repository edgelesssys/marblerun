package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"golang.org/x/net/context"

	"edgeless.systems/mesh/coordinator"
	"edgeless.systems/mesh/coordinator/quote"
	"edgeless.systems/mesh/coordinator/rpc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// never expires
const certPEM string = `
-----BEGIN CERTIFICATE-----
MIIBoTCCAVOgAwIBAgIUUgB+7+uPqaq2vxmI6Xi2baZzDG4wBQYDK2VwMEUxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwIBcNMjAwNDI0MDk0MDQ5WhgPMjI5NDAyMDcwOTQw
NDlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK
DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwKjAFBgMrZXADIQA9AjWWkS+0QCcM
CbJYmivc/GX7llTYQ47y+AFrk4xIxKNTMFEwHQYDVR0OBBYEFGUbBgdWfCaCq3Ux
xLhBytN45vWKMB8GA1UdIwQYMBaAFGUbBgdWfCaCq3UxxLhBytN45vWKMA8GA1Ud
EwEB/wQFMAMBAf8wBQYDK2VwA0EA7/mD0kH5sZ667wpanvh8CMNoG9yOvi4MWxN/
Rjh/ffRk8mZYG7QmJZFznvgxKBvuH51mwUomPErDOsllJBvUCQ==
-----END CERTIFICATE-----
`

// ed25519
const privkPEM string = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOQ0poG+b78ePPUcCLK3AVSZv+rPD8T8gqbeO4egHl2I
-----END PRIVATE KEY-----
`

// TODO: duplicate code
func ensure(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

type dummyValidator struct{}

func (*dummyValidator) Validate([]byte, []byte, quote.PackageProperties, quote.InfrastructureProperties) error {
	return nil
}

func runServer(url chan string) {
	core, err := coordinator.NewCore("edgeless", &dummyValidator{}, quote.NewMockIssuer())
	ensure(err)
	cert, err := core.GetTLSCertificate()
	ensure(err)

	creds := credentials.NewServerTLSFromCert(cert)
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	rpc.RegisterNodeServer(grpcServer, core)
	// any port is fine...
	socket, err := net.Listen("tcp", "localhost:0")
	ensure(err)
	url <- socket.Addr().String()
	ensure(grpcServer.Serve(socket))
}

func main() {
	url := make(chan string)
	go runServer(url)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(privkPEM))
	ensure(err)
	creds := credentials.NewServerTLSFromCert(&cert)
	conn, err := grpc.Dial(<-url, grpc.WithTransportCredentials(creds))
	ensure(err)
	client := rpc.NewNodeClient(conn)
	resp, err := client.Activate(context.TODO(), &rpc.ActivationReq{})
	fmt.Println("Done.")
	ensure(err)
	fmt.Println(resp.GetCertificate())
}
