package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"golang.org/x/net/context"

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

func main() {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(privkPEM))
	ensure(err)
	creds := credentials.NewServerTLSFromCert(&cert)
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	ensure(err)
	client := rpc.NewNodeClient(conn)
	req := rpc.ActivationReq{
		NodeType: "abc",
	}
	resp, err := client.Activate(context.TODO(), &req)
	ensure(err)
	fmt.Println(resp.GetCertificate())
}
