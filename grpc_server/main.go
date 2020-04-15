//go:generate protoc --proto_path=.. --go_out=plugins=grpc:../ --go_opt=paths=source_relative rpc/coordinator.proto

package main

import (
	"context"
	"log"
	"net"

	"edgeless.systems/mesh/coordinator/rpc"
	"google.golang.org/grpc"
)

type server struct {
	rpc.UnimplementedCoordinatorServer
}

func (*server) SayHello(c context.Context, r *rpc.HelloRequest) (*rpc.HelloReply, error) {
	return &rpc.HelloReply{Message: "coordinator greets you " + r.GetName()}, nil
}

func main() {
	lis, err := net.Listen("tcp", "localhost:2204")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	rpc.RegisterCoordinatorServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
