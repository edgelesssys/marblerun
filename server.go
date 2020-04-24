package main

import "edgeless.systems/mesh/coordinator/core"

func main() {
	// TODO: parse args

	c := core.NewCore("my_org")
	// creds, _ := credentials.NewServerTLSFromCert()
	// s := grpc.NewServer(grpc.Creds(creds))
	// lis, _ := net.Listen("tcp", "localhost:50051")
	// // error handling omitted
	// s.Serve(lis)

	// lis, err := net.Listen("tcp", "localhost:2204")
	// if err != nil {
	// 	log.Fatalf("failed to listen: %v", err)
	// }
	// s := grpc.NewServer()
	// rpc.RegisterCoordinatorServer(s, &server{})
	// if err := s.Serve(lis); err != nil {
	// 	log.Fatalf("failed to serve: %v", err)
	// }
}
