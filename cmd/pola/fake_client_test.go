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

	srPolicyListReq  *pb.GetSRPolicyListRequest
	srPolicyListResp *pb.GetSRPolicyListResponse
	srPolicyListErr  error

	createSRPolicyReq *pb.CreateSRPolicyRequest
	createSRPolicyErr error

	deleteSRPolicyReq *pb.DeleteSRPolicyRequest
	deleteSRPolicyErr error

	tedResp *pb.GetTEDResponse
	tedErr  error
}

func (f *fakePCEServiceClient) GetSessionList(_ context.Context, _ *pb.GetSessionListRequest, _ ...grpc.CallOption) (*pb.GetSessionListResponse, error) {
	return f.sessionListResp, f.sessionListErr
}

func (f *fakePCEServiceClient) DeleteSession(_ context.Context, in *pb.DeleteSessionRequest, _ ...grpc.CallOption) (*pb.DeleteSessionResponse, error) {
	f.deleteSessionReq = in
	if f.deleteSessionErr != nil {
		return nil, f.deleteSessionErr
	}
	return &pb.DeleteSessionResponse{}, nil
}

func (f *fakePCEServiceClient) GetSRPolicyList(_ context.Context, in *pb.GetSRPolicyListRequest, _ ...grpc.CallOption) (*pb.GetSRPolicyListResponse, error) {
	f.srPolicyListReq = in
	return f.srPolicyListResp, f.srPolicyListErr
}

func (f *fakePCEServiceClient) CreateSRPolicy(_ context.Context, in *pb.CreateSRPolicyRequest, _ ...grpc.CallOption) (*pb.CreateSRPolicyResponse, error) {
	f.createSRPolicyReq = in
	if f.createSRPolicyErr != nil {
		return nil, f.createSRPolicyErr
	}
	return &pb.CreateSRPolicyResponse{IsSuccess: true}, nil
}

func (f *fakePCEServiceClient) DeleteSRPolicy(_ context.Context, in *pb.DeleteSRPolicyRequest, _ ...grpc.CallOption) (*pb.DeleteSRPolicyResponse, error) {
	f.deleteSRPolicyReq = in
	if f.deleteSRPolicyErr != nil {
		return nil, f.deleteSRPolicyErr
	}
	return &pb.DeleteSRPolicyResponse{IsSuccess: true}, nil
}

func (f *fakePCEServiceClient) GetTED(_ context.Context, _ *pb.GetTEDRequest, _ ...grpc.CallOption) (*pb.GetTEDResponse, error) {
	return f.tedResp, f.tedErr
}
