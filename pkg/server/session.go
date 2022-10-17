// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net"
	"time"

	"github.com/nttcom/pola/pkg/packet/pcep"

	"go.uber.org/zap"
)

const KEEPALIVE uint8 = 30

type Session struct {
	sessionId uint8
	peerAddr  net.IP
	tcpConn   net.Conn
	isSynced  bool
	srpIdHead uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	lspChan   chan Lsp
	logger    *zap.Logger
}

func (s *Session) Close() {
	s.tcpConn.Close()
}

func NewSession(sessionId uint8, lspChan chan Lsp, logger *zap.Logger) *Session {
	s := &Session{
		sessionId: sessionId,
		isSynced:  false,
		srpIdHead: uint32(1),
		lspChan:   lspChan,
		logger:    logger,
	}
	return s
}

func (s *Session) Established() {
	defer s.Close()
	if err := s.Open(); err != nil {
		s.logger.Panic("PCEP OPEN error", zap.Error(err))
	}
	if err := s.SendKeepalive(); err != nil {
		s.logger.Panic("Keepalive error", zap.Error(err))
	}

	close := make(chan bool)
	go func() {
		if err := s.ReceivePcepMessage(); err != nil {
			s.logger.Info("Receive PCEP error", zap.String("session", s.peerAddr.String()))
		}
		close <- true
	}()

	ticker := time.NewTicker(time.Duration(KEEPALIVE) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-close:
			return
		case <-ticker.C: // pass KEEPALIVE seconds
			if err := s.SendKeepalive(); err != nil {
				s.logger.Panic("Keepalive error", zap.Error(err))
			}
		}
	}
}

func (s *Session) Open() error {
	if err := s.ReadOpen(); err != nil {
		return err
	}
	if err := s.SendOpen(); err != nil {
		return err
	}
	return nil
}

func (s *Session) ReadOpen() error {
	// Parse CommonHeader
	headerBuf := make([]uint8, pcep.COMMON_HEADER_LENGTH)
	if _, err := s.tcpConn.Read(headerBuf); err != nil {
		return err
	}

	var commonHeader pcep.CommonHeader
	commonHeader.DecodeFromBytes(headerBuf)
	// CommonHeader Validation
	if commonHeader.Version != 1 {
		s.logger.Panic("PCEP version mismatch", zap.Uint8("version", commonHeader.Version))
	}
	if commonHeader.MessageType != pcep.MT_OPEN {
		s.logger.Panic("This peer has not been opened.", zap.Uint8("commonObjectHeader.MessageType", commonHeader.MessageType), zap.String("session", s.peerAddr.String()))
	}

	// Parse objectClass
	objectClassBuf := make([]uint8, commonHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
	if _, err := s.tcpConn.Read(objectClassBuf); err != nil {
		return err
	}

	var commonObjectHeader pcep.CommonObjectHeader
	commonObjectHeader.DecodeFromBytes(objectClassBuf)
	if commonObjectHeader.ObjectClass != pcep.OC_OPEN {
		s.logger.Panic("Unsupported ObjectClass", zap.Uint8("commonObjectHeader.ObjectClass", commonObjectHeader.ObjectClass), zap.String("session", s.peerAddr.String()))
	}
	if commonObjectHeader.ObjectType != 1 {
		s.logger.Panic("Unsupported ObjectType", zap.Uint8("commonObjectHeader.ObjectType", commonObjectHeader.ObjectType), zap.String("session", s.peerAddr.String()))
	}

	var openObject pcep.OpenObject
	openObject.DecodeFromBytes(objectClassBuf)
	return nil
}

func (s *Session) SendOpen() error {
	openMessage := pcep.NewOpenMessage(s.sessionId, KEEPALIVE)
	byteOpenMessage := openMessage.Serialize()

	s.logger.Info("Send Open", zap.String("session", s.peerAddr.String()))
	if _, err := s.tcpConn.Write(byteOpenMessage); err != nil {
		s.logger.Info("Open send error", zap.String("session", s.peerAddr.String()))
		return err
	}
	return nil
}

func (s *Session) SendKeepalive() error {
	keepaliveMessage := pcep.NewKeepaliveMessage()
	byteKeepaliveMessage := keepaliveMessage.Serialize()

	s.logger.Info("Send Keepalive", zap.String("session", s.peerAddr.String()))
	if _, err := s.tcpConn.Write(byteKeepaliveMessage); err != nil {
		s.logger.Info("Keepalive send error", zap.String("session", s.peerAddr.String()))
		return err
	}
	return nil
}

func (s *Session) ReceivePcepMessage() error {
	for {
		byteCommonHeader := make([]uint8, pcep.COMMON_HEADER_LENGTH)
		if _, err := s.tcpConn.Read(byteCommonHeader); err != nil {
			return err
		}
		var commonHeader pcep.CommonHeader
		commonHeader.DecodeFromBytes(byteCommonHeader)

		switch commonHeader.MessageType {
		case pcep.MT_KEEPALIVE:
			s.logger.Info("Received Keepalive", zap.String("session", s.peerAddr.String()))
		case pcep.MT_REPORT:
			s.logger.Info("Received PCRpt", zap.String("session", s.peerAddr.String()))
			bytePcrptObject := make([]uint8, commonHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
			if _, err := s.tcpConn.Read(bytePcrptObject); err != nil {
				return err
			}
			var pcrptMessage pcep.PCRptMessage
			if err := pcrptMessage.DecodeFromBytes(bytePcrptObject); err != nil {
				return err
			}
			if pcrptMessage.LspObject.SFlag {
				// During LSP state synchronization (RFC8231 5.6)
				s.logger.Info("Synchronize LSP information", zap.String("session", s.peerAddr.String()), zap.Uint32("plspId", pcrptMessage.LspObject.PlspId), zap.Any("Message", pcrptMessage))
				go RegisterLsp(s.lspChan, s.peerAddr, pcrptMessage)
			} else if !pcrptMessage.LspObject.SFlag {
				if pcrptMessage.LspObject.PlspId == 0 {
					// End of synchronization (RFC8231 5.6)
					s.logger.Info("Finish PCRpt State Synchronization", zap.String("session", s.peerAddr.String()))
					s.isSynced = true
				} else if pcrptMessage.SrpObject.SrpId != 0 {
					// Response to PCInitiate/PCUpdate (RFC8231 7.2)
					s.logger.Info("Finish Transaction", zap.String("session", s.peerAddr.String()), zap.Uint32("srpId", pcrptMessage.SrpObject.SrpId))
					go RegisterLsp(s.lspChan, s.peerAddr, pcrptMessage)
				}
				// TODO: Need to implementation of PCUpdate for Passive stateful PCE
			}
		case pcep.MT_ERROR:
			s.logger.Info("Received PCErr", zap.String("session", s.peerAddr.String()))
			// TODO: Display error details
		case pcep.MT_CLOSE:
			s.logger.Info("Received Close", zap.String("session", s.peerAddr.String()))
			// Close session if get Close Message
			return nil

		default:
			s.logger.Info("Received Unsupported MessageType", zap.String("session", s.peerAddr.String()), zap.Uint8("MessageType", commonHeader.MessageType))
		}
	}
}

func (s *Session) SendPCInitiate(policyName string, labels []pcep.Label, color uint32, preference uint32, srcIPv4 []uint8, dstIPv4 []uint8) error {
	pcinitiateMessage, err := pcep.NewPCInitiateMessage(s.srpIdHead, policyName, labels, color, preference, srcIPv4, dstIPv4)
	if err != nil {
		return err
	}
	bytePCInitiateMessage, err := pcinitiateMessage.Serialize()
	if err != nil {
		return err
	}
	labelsJson := []map[string]interface{}{}
	for _, l := range labels {
		labelJson := map[string]interface{}{
			"Sid":    l.Sid,
			"LoAddr": net.IP(l.LoAddr).String(),
		}
		labelsJson = append(labelsJson, labelJson)
	}
	s.logger.Info("Send PCInitiate", zap.String("session", s.peerAddr.String()), zap.Uint32("srpId", s.srpIdHead), zap.String("policyName", policyName), zap.Any("labels", labelsJson), zap.Uint32("color", color), zap.Uint32("preference", preference), zap.String("srcIPv4", net.IP(srcIPv4).String()), zap.Any("dstIPv4", net.IP(dstIPv4).String()))
	if _, err := s.tcpConn.Write(bytePCInitiateMessage); err != nil {
		return err
	}
	s.srpIdHead += 1
	return nil
}

func (s *Session) SendPCUpdate(policyName string, plspId uint32, labels []pcep.Label) error {
	pcupdateMessage, err := pcep.NewPCUpdMessage(s.srpIdHead, policyName, plspId, labels)
	if err != nil {
		return err
	}
	bytePCUpdMessage, err := pcupdateMessage.Serialize()
	if err != nil {
		return err
	}

	s.logger.Info("Send PCUpdate", zap.String("session", s.peerAddr.String()))
	if _, err := s.tcpConn.Write(bytePCUpdMessage); err != nil {
		s.logger.Info("PCUpdate send error", zap.String("session", s.peerAddr.String()))
		return err
	}
	s.srpIdHead += 1
	return nil
}

func RegisterLsp(lspChan chan Lsp, peerAddr net.IP, pcrptMessage pcep.PCRptMessage) {
	lspStruct := Lsp{
		peerAddr: peerAddr,
		plspId:   pcrptMessage.LspObject.PlspId,
		name:     pcrptMessage.LspObject.Name,
		path:     pcrptMessage.EroObject.GetSidList(),
		srcAddr:  pcrptMessage.LspObject.SrcAddr,
		dstAddr:  pcrptMessage.LspObject.DstAddr,
	}
	lspChan <- lspStruct
}
