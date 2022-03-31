// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/nttcom/pola/api/grpc"
)

type server struct {
	pb.UnimplementedPceServiceServer
}

func (s *server) CreateLsp(ctx context.Context, lspData *pb.LspData) (*pb.LspStatus, error) {
	log.Printf("Received: %v", lspData.GetLabels())
	return &pb.LspStatus{IsSuccess: true}, nil
}

func main() {
	port := 50051
	listenPort, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterPceServiceServer(s, &server{})

	fmt.Printf("listening")
	if err := s.Serve(listenPort); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
