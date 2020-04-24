package main

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	creds, _ := credentials.NewClientTLSFromFile(certFile, "")
	conn, _ := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
}
