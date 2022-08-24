// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package grpc

import (
	context "context"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// PceServiceClient is the client API for PceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PceServiceClient interface {
	CreateLsp(ctx context.Context, in *LspData, opts ...grpc.CallOption) (*LspStatus, error)
	GetPeerAddrList(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*PeerAddrList, error)
	GetLspList(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*LspList, error)
	GetTed(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*Ted, error)
}

type pceServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPceServiceClient(cc grpc.ClientConnInterface) PceServiceClient {
	return &pceServiceClient{cc}
}

func (c *pceServiceClient) CreateLsp(ctx context.Context, in *LspData, opts ...grpc.CallOption) (*LspStatus, error) {
	out := new(LspStatus)
	err := c.cc.Invoke(ctx, "/pb.PceService/CreateLsp", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) GetPeerAddrList(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*PeerAddrList, error) {
	out := new(PeerAddrList)
	err := c.cc.Invoke(ctx, "/pb.PceService/GetPeerAddrList", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) GetLspList(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*LspList, error) {
	out := new(LspList)
	err := c.cc.Invoke(ctx, "/pb.PceService/GetLspList", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pceServiceClient) GetTed(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*Ted, error) {
	out := new(Ted)
	err := c.cc.Invoke(ctx, "/pb.PceService/GetTed", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PceServiceServer is the server API for PceService service.
// All implementations should embed UnimplementedPceServiceServer
// for forward compatibility
type PceServiceServer interface {
	CreateLsp(context.Context, *LspData) (*LspStatus, error)
	GetPeerAddrList(context.Context, *empty.Empty) (*PeerAddrList, error)
	GetLspList(context.Context, *empty.Empty) (*LspList, error)
	GetTed(context.Context, *empty.Empty) (*Ted, error)
}

// UnimplementedPceServiceServer should be embedded to have forward compatible implementations.
type UnimplementedPceServiceServer struct {
}

func (UnimplementedPceServiceServer) CreateLsp(context.Context, *LspData) (*LspStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateLsp not implemented")
}
func (UnimplementedPceServiceServer) GetPeerAddrList(context.Context, *empty.Empty) (*PeerAddrList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerAddrList not implemented")
}
func (UnimplementedPceServiceServer) GetLspList(context.Context, *empty.Empty) (*LspList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLspList not implemented")
}
func (UnimplementedPceServiceServer) GetTed(context.Context, *empty.Empty) (*Ted, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTed not implemented")
}

// UnsafePceServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PceServiceServer will
// result in compilation errors.
type UnsafePceServiceServer interface {
	mustEmbedUnimplementedPceServiceServer()
}

func RegisterPceServiceServer(s grpc.ServiceRegistrar, srv PceServiceServer) {
	s.RegisterService(&PceService_ServiceDesc, srv)
}

func _PceService_CreateLsp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LspData)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).CreateLsp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.PceService/CreateLsp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).CreateLsp(ctx, req.(*LspData))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_GetPeerAddrList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).GetPeerAddrList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.PceService/GetPeerAddrList",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).GetPeerAddrList(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_GetLspList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).GetLspList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.PceService/GetLspList",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).GetLspList(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PceService_GetTed_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PceServiceServer).GetTed(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.PceService/GetTed",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PceServiceServer).GetTed(ctx, req.(*empty.Empty))
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
			MethodName: "CreateLsp",
			Handler:    _PceService_CreateLsp_Handler,
		},
		{
			MethodName: "GetPeerAddrList",
			Handler:    _PceService_GetPeerAddrList_Handler,
		},
		{
			MethodName: "GetLspList",
			Handler:    _PceService_GetLspList_Handler,
		},
		{
			MethodName: "GetTed",
			Handler:    _PceService_GetTed_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pola.proto",
}