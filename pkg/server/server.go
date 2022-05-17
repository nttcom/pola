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

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/pkg/packet/pcep"
)

type Lsp struct {
	peerAddr net.IP //TODO: Change to ("loopback addr" or "router name")
	plspId   uint32
	name     string
	path     []uint32
	srcAddr  net.IP
	dstAddr  net.IP
}

func (lsp Lsp) PrintPath() {
	fmt.Printf("Path: ")

	if len(lsp.path) == 0 {
		fmt.Printf("None \n")
	}
	for i, label := range lsp.path {
		fmt.Printf("%d ", label)
		if i == len(lsp.path)-1 {
			fmt.Printf("\n")
		} else {
			fmt.Printf("-> ")
		}
	}
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
	// Start PCEP listen
	go func() {
		if err := s.Listen(o.PcepAddr, o.PcepPort, lspChan); err != nil {
			fmt.Printf("PCEP listen Error\n")
		}

	}()
	// Start gRPC listen
	go func() {
		if err := s.grpcListen(); err != nil {
			fmt.Printf("gRPC listen Error\n")
		}

	}()
	ticker := time.NewTicker(time.Duration(10) * time.Second)
	defer ticker.Stop()
	// Display sessionList
	for {
		select {
		case lsp := <-lspChan:
			// Overwrite LSP
			s.removeLsp(lsp)
			s.lspList = append(s.lspList, lsp)
		case <-ticker.C:
			s.printSessionList()
			s.printLspList()
		}
	}
}

func (s *Server) Listen(address string, port string, lspChan chan Lsp) error {
	// listen PCEP
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
			s.removeSession(session)
		}()
		sessionId += 1
	}
}

func (s *Server) grpcListen() error {
	port := 50051
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("[gRPC] failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()

	pb.RegisterPceServiceServer(grpcServer, s)
	fmt.Printf("[gRPC] Listen start\n")
	if err := grpcServer.Serve(grpcListener); err != nil {
		log.Fatalf("[gRPC] Failed to serve: %v", err)
	}
	return nil
}

func (s *Server) CreateLsp(ctx context.Context, lspData *pb.LspData) (*pb.LspStatus, error) {
	fmt.Printf("[gRPC] Get request\n")
	pcepPeerAddr := net.IP(lspData.GetPcepSessionAddr())
	if pcepSession := s.getSession(pcepPeerAddr); pcepSession != nil {
		labels := []pcep.Label{}
		for _, receivedLsp := range lspData.GetLabels() {
			pcepLabel := pcep.Label{
				Sid:    receivedLsp.GetSid(),
				LoAddr: receivedLsp.GetLoAddr(),
			}
			labels = append(labels, pcepLabel)
		}
		if plspId := s.getPlspId(lspData); plspId != 0 {
			fmt.Printf("plspId check : %d\n\n", plspId)
			if err := pcepSession.SendPCUpdate(lspData.GetPolicyName(), plspId, labels); err != nil {
				return &pb.LspStatus{IsSuccess: false}, err
			}
		} else {
			if err := pcepSession.SendPCInitiate(lspData.GetPolicyName(), labels, lspData.GetColor(), uint32(100), lspData.GetSrcAddr(), lspData.GetDstAddr()); err != nil {
				return &pb.LspStatus{IsSuccess: false}, err
			}
		}
		return &pb.LspStatus{IsSuccess: true}, nil
	}
	return &pb.LspStatus{IsSuccess: false}, nil
}

func (s *Server) GetPeerAddrList(context.Context, *empty.Empty) (*pb.PeerAddrList, error) {
	fmt.Printf("[gRPC] Get request\n")
	var ret pb.PeerAddrList
	for _, pcepSession := range s.sessionList {
		ret.PeerAddrs = append(ret.PeerAddrs, []byte(pcepSession.peerAddr))
	}
	return &ret, nil
}

func (s *Server) GetLspList(context.Context, *empty.Empty) (*pb.LspList, error) {
	fmt.Printf("[gRPC] Get request\n")
	var ret pb.LspList
	for _, lsp := range s.lspList {
		lspData := &pb.LspData{
			PcepSessionAddr: []byte(lsp.peerAddr),
			Labels:          []*pb.Label{},
			PolicyName:      lsp.name,
			SrcAddr:         []byte(lsp.srcAddr),
			DstAddr:         []byte(lsp.dstAddr),
		}
		for _, sid := range lsp.path {
			label := pb.Label{
				Sid: sid,
			}
			lspData.Labels = append(lspData.Labels, &label)
		}
		ret.Lsps = append(ret.Lsps, lspData)
	}
	return &ret, nil
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
		fmt.Printf("*- LSP Owner address: %s\n", lsp.peerAddr.String())
		fmt.Printf("*  LSP Name: %s\n", lsp.name)
		fmt.Printf("*  PLSP-ID: %d\n", lsp.plspId)
		fmt.Printf("*  ")
		lsp.PrintPath()
		fmt.Printf("*  SrcAddr: %s\n", lsp.srcAddr.String())
		fmt.Printf("*  DstAddr: %s\n", lsp.dstAddr.String())
		fmt.Printf("*\n")
	}
	fmt.Printf("*************************\n")
}

func (s *Server) removeSession(session *Session) {
	// Remove Session List
	for i, v := range s.sessionList {
		if v.sessionId == session.sessionId {
			s.sessionList[i] = s.sessionList[len(s.sessionList)-1]
			s.sessionList = s.sessionList[:len(s.sessionList)-1]
			break
		}
	}
	// Remove Lsp List
	newLspList := []Lsp{}
	for _, v := range s.lspList {
		if !v.peerAddr.Equal(session.peerAddr) {
			newLspList = append(newLspList, v)
		}
	}
	s.lspList = newLspList
}

func (s *Server) getPlspId(lspData *pb.LspData) uint32 {
	for _, v := range s.lspList {
		if v.name == lspData.GetPolicyName() && v.peerAddr.Equal(net.IP(lspData.GetPcepSessionAddr())) {
			return v.plspId
		}
	}
	// If LSP name is not in the lapList, returns PLSP-ID: 0
	return 0
}

func (s *Server) removeLsp(e Lsp) {
	// Deletes a LSP with name, PLSP-ID, and sessionAddr matching from lspList
	for i, v := range s.lspList {
		if v.name == e.name && v.plspId == e.plspId && v.peerAddr.Equal(e.peerAddr) {
			s.lspList[i] = s.lspList[len(s.lspList)-1]
			s.lspList = s.lspList[:len(s.lspList)-1]
			break
		}
	}
}

func (s *Server) getSession(peerAddr net.IP) *Session {
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr.Equal(peerAddr) {
			if !pcepSession.isSynced {
				break
			}
			return pcepSession
		}
	}
	return nil
}
