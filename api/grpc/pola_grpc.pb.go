// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.23.4
// source: pola.proto

package grpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	PceService_CreateSRPolicy_FullMethodName                 = "/pb.PceService/CreateSRPolicy"
	PceService_CreateSRPolicyWithoutLinkState_FullMethodName = "/pb.PceService/CreateSRPolicyWithoutLinkState"
	PceService_DeleteSRPolicy_FullMethodName                 = "/pb.PceService/DeleteSRPolicy"
	PceService_DeleteSRPolicyWithoutLinkState_FullMethodName = "/pb.PceService/DeleteSRPolicyWithoutLinkState"
	PceService_GetSessionList_FullMethodName                 = "/pb.PceService/GetSessionList"
	PceService_GetSRPolicyList_FullMethodName                = "/pb.PceService/GetSRPolicyList"
	PceService_GetTed_FullMethodName                         = "/pb.PceService/GetTed"
	PceService_DeleteSession_FullMethodName                  = "/pb.PceService/DeleteSession"
)

// PceServiceClient is the client API for PceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PceServiceClient interface {
	CreateSRPolicy(ctx context.Context, in *CreateSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error)
	CreateSRPolicyWithoutLinkState(ctx context.Context, in *CreateSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error)
	DeleteSRPolicy(ctx context.Context, in *DeleteSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error)
	DeleteSRPolicyWithoutLinkState(ctx context.Context, in *DeleteSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error)
	GetSessionList(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*SessionList, error)
	GetSRPolicyList(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*SRPolicyList, error)
	GetTed(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*Ted, error)
	DeleteSession(ctx context.Context, in *Session, opts ...grpc.CallOption) (*RequestStatus, error)
}

type pceServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPceServiceClient(cc grpc.ClientConnInterface) PceServiceClient {
	return &pceServiceClient{cc}
}

func (c *pceServiceClient) CreateSRPolicy(ctx context.Context, in *CreateSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error) {
	out := new(RequestStatus)
	err := c.cc.Invoke(ctx, PceService_CreateSRPolicy_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) CreateSRPolicyWithoutLinkState(ctx context.Context, in *CreateSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error) {
	out := new(RequestStatus)
	err := c.cc.Invoke(ctx, PceService_CreateSRPolicyWithoutLinkState_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) DeleteSRPolicy(ctx context.Context, in *DeleteSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error) {
	out := new(RequestStatus)
	err := c.cc.Invoke(ctx, PceService_DeleteSRPolicy_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) DeleteSRPolicyWithoutLinkState(ctx context.Context, in *DeleteSRPolicyInput, opts ...grpc.CallOption) (*RequestStatus, error) {
	out := new(RequestStatus)
	err := c.cc.Invoke(ctx, PceService_DeleteSRPolicyWithoutLinkState_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) GetSessionList(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*SessionList, error) {
	out := new(SessionList)
	err := c.cc.Invoke(ctx, PceService_GetSessionList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) GetSRPolicyList(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*SRPolicyList, error) {
	out := new(SRPolicyList)
	err := c.cc.Invoke(ctx, PceService_GetSRPolicyList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) GetTed(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*Ted, error) {
	out := new(Ted)
	err := c.cc.Invoke(ctx, PceService_GetTed_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) DeleteSession(ctx context.Context, in *Session, opts ...grpc.CallOption) (*RequestStatus, error) {
	out := new(RequestStatus)
	err := c.cc.Invoke(ctx, PceService_DeleteSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PceServiceServer is the server API for PceService service.
// All implementations must embed UnimplementedPceServiceServer
// for forward compatibility
type PceServiceServer interface {
	CreateSRPolicy(context.Context, *CreateSRPolicyInput) (*RequestStatus, error)
	CreateSRPolicyWithoutLinkState(context.Context, *CreateSRPolicyInput) (*RequestStatus, error)
	DeleteSRPolicy(context.Context, *DeleteSRPolicyInput) (*RequestStatus, error)
	DeleteSRPolicyWithoutLinkState(context.Context, *DeleteSRPolicyInput) (*RequestStatus, error)
	GetSessionList(context.Context, *emptypb.Empty) (*SessionList, error)
	GetSRPolicyList(context.Context, *emptypb.Empty) (*SRPolicyList, error)
	GetTed(context.Context, *emptypb.Empty) (*Ted, error)
	DeleteSession(context.Context, *Session) (*RequestStatus, error)
	mustEmbedUnimplementedPceServiceServer()
}

// UnimplementedPceServiceServer must be embedded to have forward compatible implementations.
type UnimplementedPceServiceServer struct {
}

func (UnimplementedPceServiceServer) CreateSRPolicy(context.Context, *CreateSRPolicyInput) (*RequestStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSRPolicy not implemented")
}
func (UnimplementedPceServiceServer) CreateSRPolicyWithoutLinkState(context.Context, *CreateSRPolicyInput) (*RequestStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSRPolicyWithoutLinkState not implemented")
}
func (UnimplementedPceServiceServer) DeleteSRPolicy(context.Context, *DeleteSRPolicyInput) (*RequestStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteSRPolicy not implemented")
}
func (UnimplementedPceServiceServer) DeleteSRPolicyWithoutLinkState(context.Context, *DeleteSRPolicyInput) (*RequestStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteSRPolicyWithoutLinkState not implemented")
}
func (UnimplementedPceServiceServer) GetSessionList(context.Context, *emptypb.Empty) (*SessionList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSessionList not implemented")
}
func (UnimplementedPceServiceServer) GetSRPolicyList(context.Context, *emptypb.Empty) (*SRPolicyList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSRPolicyList not implemented")
}
func (UnimplementedPceServiceServer) GetTed(context.Context, *emptypb.Empty) (*Ted, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTed not implemented")
}
func (UnimplementedPceServiceServer) DeleteSession(context.Context, *Session) (*RequestStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteSession not implemented")
}
func (UnimplementedPceServiceServer) mustEmbedUnimplementedPceServiceServer() {}

// UnsafePceServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PceServiceServer will
// result in compilation errors.
type UnsafePceServiceServer interface {
	mustEmbedUnimplementedPceServiceServer()
}

func RegisterPceServiceServer(s grpc.ServiceRegistrar, srv PceServiceServer) {
	s.RegisterService(&PceService_ServiceDesc, srv)
}

func _PceService_CreateSRPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSRPolicyInput)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).CreateSRPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_CreateSRPolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).CreateSRPolicy(ctx, req.(*CreateSRPolicyInput))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_CreateSRPolicyWithoutLinkState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSRPolicyInput)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).CreateSRPolicyWithoutLinkState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_CreateSRPolicyWithoutLinkState_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).CreateSRPolicyWithoutLinkState(ctx, req.(*CreateSRPolicyInput))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_DeleteSRPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteSRPolicyInput)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).DeleteSRPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_DeleteSRPolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).DeleteSRPolicy(ctx, req.(*DeleteSRPolicyInput))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_DeleteSRPolicyWithoutLinkState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteSRPolicyInput)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).DeleteSRPolicyWithoutLinkState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_DeleteSRPolicyWithoutLinkState_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).DeleteSRPolicyWithoutLinkState(ctx, req.(*DeleteSRPolicyInput))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_GetSessionList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).GetSessionList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_GetSessionList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).GetSessionList(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_GetSRPolicyList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).GetSRPolicyList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_GetSRPolicyList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).GetSRPolicyList(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_GetTed_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).GetTed(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_GetTed_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).GetTed(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_DeleteSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Session)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).DeleteSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PceService_DeleteSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).DeleteSession(ctx, req.(*Session))
	}
	return interceptor(ctx, in, info, handler)
}

// PceService_ServiceDesc is the grpc.ServiceDesc for PceService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PceService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "pb.PceService",
	HandlerType: (*PceServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateSRPolicy",
			Handler:    _PceService_CreateSRPolicy_Handler,
		},
		{
			MethodName: "CreateSRPolicyWithoutLinkState",
			Handler:    _PceService_CreateSRPolicyWithoutLinkState_Handler,
		},
		{
			MethodName: "DeleteSRPolicy",
			Handler:    _PceService_DeleteSRPolicy_Handler,
		},
		{
			MethodName: "DeleteSRPolicyWithoutLinkState",
			Handler:    _PceService_DeleteSRPolicyWithoutLinkState_Handler,
		},
		{
			MethodName: "GetSessionList",
			Handler:    _PceService_GetSessionList_Handler,
		},
		{
			MethodName: "GetSRPolicyList",
			Handler:    _PceService_GetSRPolicyList_Handler,
		},
		{
			MethodName: "GetTed",
			Handler:    _PceService_GetTed_Handler,
		},
		{
			MethodName: "DeleteSession",
			Handler:    _PceService_DeleteSession_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pola.proto",
}
