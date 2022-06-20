// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
)

type lspInfo struct {
	peerAddr net.IP //TODO: Change to ("loopback addr" or "router name")
	name     string
	path     []uint32
	srcAddr  net.IP
	dstAddr  net.IP
}

func getPeerAddrList(client pb.PceServiceClient) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := client.GetPeerAddrList(ctx, &empty)
	if err != nil {
		return nil, errors.New("Could not get Peer Address.\n")
	}
	var peerAddrList []net.IP
	for _, peerAddr := range ret.GetPeerAddrs() {
		peerAddrList = append(peerAddrList, net.IP(peerAddr))
	}
	return peerAddrList, nil
}

func getlspList(client pb.PceServiceClient) ([]lspInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := client.GetLspList(ctx, &empty)
	if err != nil {
		return nil, errors.New("Could not get Lsp List.\n")
	}
	lspList := []lspInfo{}
	for _, lsp := range ret.GetLsps() {
		tmp := lspInfo{
			name:     lsp.PolicyName,
			peerAddr: net.IP(lsp.GetPcepSessionAddr()),
			srcAddr:  net.IP(lsp.GetSrcAddr()),
			dstAddr:  net.IP(lsp.GetDstAddr()),
		}
		if len(lsp.GetLabels()) != 0 {
			for _, label := range lsp.GetLabels() {
				tmp.path = append(tmp.path, label.GetSid())
			}
		}
		lspList = append(lspList, tmp)
	}
	return lspList, nil
}

func createLsp(client pb.PceServiceClient, lspData *pb.LspData) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateLsp(ctx, lspData)
	if err != nil {
		return err
	}
	return nil
}
