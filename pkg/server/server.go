// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	grpc "google.golang.org/grpc"

	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/pkg/packet/pcep"
)

// TODO: 引数やconfファイルで上書きできるようにする
const PCEPORT = "4189"
const PCEADDR = "10.100.0.252"

type lsp struct {
	peerAddr     net.IP // 後々 router ID, router name などに変更したい
	plspId       uint32
	name         string
	pcrptMessage pcep.PCRptMessage
}

type Server struct {
	sessionList []*Session
	lspList     []lsp
	pb.UnimplementedPceServiceServer
}

func NewPce() error {
	s := &Server{}
	// PCEP の Listen を開始する
	go s.Listen()
	// gRPC の Listen を開始する
	go s.grpcListen()
	// sessionList の表示
	for {
		s.printSessionList()
		s.printLspList()
		time.Sleep(10 * time.Second)
	}
}

func (s *Server) Listen() error {
	// PCEP の listen を行う
	// PCEPPORT = "4189" 宛の SYN は全て accept
	var listenInfo strings.Builder
	listenInfo.WriteString(PCEADDR)
	listenInfo.WriteString(":")
	listenInfo.WriteString(PCEPORT)
	fmt.Printf("[server] PCE Listen: %s\n", listenInfo.String())
	listener, err := net.Listen("tcp", listenInfo.String())
	if err != nil {
		return err
	}

	defer listener.Close()
	sessionId := uint8(1)
	for {
		// PCEPPORT = "4189" へ SYN が来るたびに Accept
		session := NewSession(sessionId)

		fmt.Printf("%#v\n", s)
		session.tcpConn, err = listener.Accept()
		if err != nil {
			return err
		}
		fmt.Printf("[server] PCEP Session Accept\n")
		strPeerAddr := session.tcpConn.RemoteAddr().String()
		sessionAddr := net.ParseIP(strings.Split(strPeerAddr, ":")[0])
		session.peerAddr = sessionAddr
		s.sessionList = append(s.sessionList, session)
		go func() {
			session.Established()
			s.removeSession(session.sessionId)
		}()
		sessionId += 1
	}
}

func (s *Server) grpcListen() error {
	port := 50051
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()

	pb.RegisterPceServiceServer(grpcServer, s)
	fmt.Printf("[gRPC] Listen start\n")
	if err := grpcServer.Serve(grpcListener); err != nil {
		log.Fatalf("[gRPC] Failed to serve: %v", err)
	}
	return nil
}

// grpc関連 一旦置いとく
func (s *Server) CreateLsp(ctx context.Context, lspData *pb.LspData) (*pb.LspStatus, error) {
	fmt.Printf("[gRPC] Get request\n")
	pcepPeerAddr := net.IP(lspData.GetPcepSessionAddr())
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr.Equal(pcepPeerAddr) {
			fmt.Printf("%#v\n", pcepSession)
			if !pcepSession.isSynced {
				break
			}
			labels := []pcep.Label{}
			for _, receivedLsp := range lspData.GetLabels() {
				pcepLabel := pcep.Label{
					Sid:    receivedLsp.GetSid(),
					LoAddr: receivedLsp.GetLoAddr(),
				}
				labels = append(labels, pcepLabel)
			}
			pcepSession.SendPCInitiate(lspData.GetPolicyName(), labels, lspData.GetColor(), uint32(100), lspData.GetSrcAddr(), lspData.GetDstAddr())
			return &pb.LspStatus{IsSuccess: true}, nil
		}
	}
	return &pb.LspStatus{IsSuccess: false}, nil
}

func (s *Server) printSessionList() {
	fmt.Printf("pcepSessionList --------\n")
	fmt.Printf("|\n")
	for _, pcepSession := range s.sessionList {
		fmt.Printf("|  sessionAddr: %s\n", pcepSession.peerAddr.String())
	}
	fmt.Printf("|\n")
	fmt.Printf("------------------------\n")
}

func (s *Server) printLspList() {
	fmt.Printf("printLspList ************\n")
	fmt.Printf("*\n")
	for _, lsp := range s.lspList {
		fmt.Printf("|- LSP Owner address %s\n", lsp.peerAddr.String())
		fmt.Printf("|  LSP Name %s\n", lsp.name)
		fmt.Printf("|  PLSP-ID %d\n", lsp.plspId)
		fmt.Printf("|  lspObject %#v\n", lsp.pcrptMessage)
	}
	fmt.Printf("*\n")
	fmt.Printf("*************************\n")
}

func (s *Server) removeSession(sessionId uint8) {
	for i, v := range s.sessionList {
		if v.sessionId == sessionId {
			s.sessionList[i] = s.sessionList[len(s.sessionList)-1]
			s.sessionList = s.sessionList[:len(s.sessionList)-1]
			break
		}
	}
}

// func removeLsp(lspList []lsp, e lsp) []lsp {
// 	// lspList から name, PLSP-ID, sessionAddr が一致するものを削除する
// 	result := []lsp{}
// 	for _, lsp := range lspList {
// 		if lsp.name == e.name && lsp.plspId == e.plspId && lsp.peerAddr.Equal(e.peerAddr) {
// 			continue
// 		}
// 		result = append(result, lsp)
// 	}
// 	return result
// }
