// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"

	pb "github.com/nttcom/pola/api/pola/v1"
	"google.golang.org/grpc"
)

type fakePCEServiceClient struct {
	pb.PCEServiceClient

	sessionListResp *pb.GetSessionListResponse
	sessionListErr  error

	deleteSessionReq *pb.DeleteSessionRequest
	deleteSessionErr error

	srPolicyListResp *pb.GetSRPolicyListResponse
	srPolicyListErr  error

	createSRPolicyReq *pb.CreateSRPolicyRequest
	createSRPolicyErr error

	deleteSRPolicyReq *pb.DeleteSRPolicyRequest
	deleteSRPolicyErr error

	tedResp *pb.GetTEDResponse
	tedErr  error
}

func (f *fakePCEServiceClient) GetSessionList(ctx context.Context, in *pb.GetSessionListRequest, opts ...grpc.CallOption) (*pb.GetSessionListResponse, error) {
	return f.sessionListResp, f.sessionListErr
}

func (f *fakePCEServiceClient) DeleteSession(ctx context.Context, in *pb.DeleteSessionRequest, opts ...grpc.CallOption) (*pb.DeleteSessionResponse, error) {
	f.deleteSessionReq = in
	if f.deleteSessionErr != nil {
		return nil, f.deleteSessionErr
	}
	return &pb.DeleteSessionResponse{}, nil
}

func (f *fakePCEServiceClient) GetSRPolicyList(ctx context.Context, in *pb.GetSRPolicyListRequest, opts ...grpc.CallOption) (*pb.GetSRPolicyListResponse, error) {
	return f.srPolicyListResp, f.srPolicyListErr
}

func (f *fakePCEServiceClient) CreateSRPolicy(ctx context.Context, in *pb.CreateSRPolicyRequest, opts ...grpc.CallOption) (*pb.CreateSRPolicyResponse, error) {
	f.createSRPolicyReq = in
	if f.createSRPolicyErr != nil {
		return nil, f.createSRPolicyErr
	}
	return &pb.CreateSRPolicyResponse{IsSuccess: true}, nil
}

func (f *fakePCEServiceClient) DeleteSRPolicy(ctx context.Context, in *pb.DeleteSRPolicyRequest, opts ...grpc.CallOption) (*pb.DeleteSRPolicyResponse, error) {
	f.deleteSRPolicyReq = in
	if f.deleteSRPolicyErr != nil {
		return nil, f.deleteSRPolicyErr
	}
	return &pb.DeleteSRPolicyResponse{IsSuccess: true}, nil
}

func (f *fakePCEServiceClient) GetTED(ctx context.Context, in *pb.GetTEDRequest, opts ...grpc.CallOption) (*pb.GetTEDResponse, error) {
	return f.tedResp, f.tedErr
}
