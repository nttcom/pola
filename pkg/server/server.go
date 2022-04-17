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

type Lsp struct {
	peerAddr     net.IP // 後々 router ID, router name などに変更したい
	plspId       uint32
	name         string
	pcrptMessage pcep.PCRptMessage
}

type Server struct {
	sessionList []*Session
	lspList     []Lsp
	pb.UnimplementedPceServiceServer
}

type PceOptions struct {
	PcepAddr string
	PcepPort string
}

func NewPce(o *PceOptions) error {
	s := &Server{}
	lspChan := make(chan Lsp)
	// PCEP の Listen を開始する
	go func() {
		if err := s.Listen(o.PcepAddr, o.PcepPort, lspChan); err != nil {
			fmt.Printf("PCEP listen Error\n")
		}

	}()
	// gRPC の Listen を開始する
	go func() {
		if err := s.grpcListen(); err != nil {
			fmt.Printf("gRPC listen Error\n")
		}

	}()
	ticker := time.NewTicker(time.Duration(10) * time.Second)
	defer ticker.Stop()
	// sessionList の表示
	for {
		select {

		case lsp := <-lspChan:
			// 更新用に旧 LSP 情報を削除する
			s.removeLsp(lsp)
			s.lspList = append(s.lspList, lsp)
		case <-ticker.C:
			s.printSessionList()
			s.printLspList()
		}

	}
}

func (s *Server) Listen(address string, port string, lspChan chan Lsp) error {
	// PCEP の listen を行う
	var listenInfo strings.Builder
	listenInfo.WriteString(address)
	listenInfo.WriteString(":")
	listenInfo.WriteString(port)
	fmt.Printf("[server] PCE Listen: %s\n", listenInfo.String())
	listener, err := net.Listen("tcp", listenInfo.String())
	if err != nil {
		return err
	}

	defer listener.Close()
	sessionId := uint8(1)
	for {
		session := NewSession(sessionId, lspChan)

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
			if err := pcepSession.SendPCInitiate(lspData.GetPolicyName(), labels, lspData.GetColor(), uint32(100), lspData.GetSrcAddr(), lspData.GetDstAddr()); err != nil {
				return &pb.LspStatus{IsSuccess: false}, err
			}
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
		fmt.Printf("*- LSP Owner address %s\n", lsp.peerAddr.String())
		fmt.Printf("*  LSP Name %s\n", lsp.name)
		fmt.Printf("*  PLSP-ID %d\n", lsp.plspId)
		fmt.Printf("*  lspObject %#v\n", lsp.pcrptMessage)
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

func (s *Server) removeLsp(e Lsp) {
	// lspList から name, PLSP-ID, sessionAddr が一致するものを削除する
	for i, v := range s.lspList {
		if v.name == e.name && v.plspId == e.plspId && v.peerAddr.Equal(e.peerAddr) {
			s.lspList[i] = s.lspList[len(s.lspList)-1]
			s.lspList = s.lspList[:len(s.lspList)-1]
			break
		}
	}
}
