// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net"
	"strings"

	"go.uber.org/zap"
	grpc "google.golang.org/grpc"

	pb "github.com/nttcom/pola/api/grpc"

	"github.com/nttcom/pola/internal/pkg/table"
)

type Lsp struct {
	peerAddr   net.IP //TODO: Change to ("loopback addr" or "router name")
	plspId     uint32
	name       string
	path       []uint32
	srcAddr    net.IP
	dstAddr    net.IP
	color      uint32
	preference uint32
}

type Server struct {
	sessionList []*Session
	lspList     []Lsp
	ted         *table.LsTed
	logger      *zap.Logger
}

type PceOptions struct {
	PcepAddr  string
	PcepPort  string
	GrpcAddr  string
	GrpcPort  string
	TedEnable bool
}

func NewPce(o *PceOptions, logger *zap.Logger, tedElemsChan chan []table.TedElem) ServerError {
	var s *Server
	if o.TedEnable {
		s = &Server{
			ted: &table.LsTed{
				Id:    1,
				Nodes: map[uint32]map[string]*table.LsNode{},
			},
		}

		// Update Ted
		go func() {
			for {
				tedElems := <-tedElemsChan
				s.ted = &table.LsTed{
					Id:    s.ted.Id,
					Nodes: map[uint32]map[string]*table.LsNode{},
				}

				for _, tedElem := range tedElems {
					tedElem.UpdateTed(s.ted)
				}
				logger.Info("Update TED")
			}
		}()
	} else {
		s = &Server{
			ted: nil,
		}
	}

	s.logger = logger
	lspChan := make(chan Lsp)
	errChan := make(chan ServerError)
	// Start PCEP listen
	go func() {
		if err := s.Listen(o.PcepAddr, o.PcepPort, lspChan); err != nil {
			errChan <- ServerError{
				Server: "pcep",
				Error:  err,
			}
		}
	}()
	// Start gRPC listen
	go func() {
		grpcServer := grpc.NewServer()
		apiServer := NewAPIServer(s, grpcServer)
		if err := apiServer.Serve(o.GrpcAddr, o.GrpcPort); err != nil {
			errChan <- ServerError{
				Server: "grpc",
				Error:  err,
			}
		}
	}()

	for {
		select {
		case lsp := <-lspChan:
			// Overwrite LSP
			s.removeLsp(lsp)
			s.lspList = append(s.lspList, lsp)
		case serverError := <-errChan:
			return serverError
		}
	}
}

func (s *Server) Listen(address string, port string, lspChan chan Lsp) error {
	var listenInfo strings.Builder
	listenInfo.WriteString(address)
	listenInfo.WriteString(":")
	listenInfo.WriteString(port)
	s.logger.Info("PCEP listen", zap.String("listenInfo", listenInfo.String()))
	listener, err := net.Listen("tcp", listenInfo.String())
	if err != nil {
		return err
	}

	defer listener.Close()
	sessionId := uint8(1)
	for {
		session := NewSession(sessionId, lspChan, s.logger)
		session.tcpConn, err = listener.Accept()
		if err != nil {
			return err
		}
		strPeerAddr := session.tcpConn.RemoteAddr().String()
		sessionAddr := net.ParseIP(strings.Split(strPeerAddr, ":")[0])
		session.peerAddr = sessionAddr
		s.sessionList = append(s.sessionList, session)
		go func() {
			session.Established()
			s.closeSession(session)
			s.logger.Info("Close PCEP session", zap.String("session", session.peerAddr.String()))
		}()
		sessionId += 1
	}
}

func (s *Server) closeSession(session *Session) {
	session.tcpConn.Close()

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

func (s *Server) getPlspId(lspData *pb.SrPolicy) uint32 {
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
