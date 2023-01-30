// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/pkg/packet/pcep"

	"go.uber.org/zap"
)

const KEEPALIVE uint8 = 30

type Session struct {
	sessionId  uint8
	peerAddr   netip.Addr
	tcpConn    *net.TCPConn
	isSynced   bool
	srpIdHead  uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	srPolicies []table.SRPolicy
	logger     *zap.Logger
	pccType    pcep.PccType
}

func NewSession(sessionId uint8, logger *zap.Logger) *Session {
	s := &Session{
		sessionId: sessionId,
		isSynced:  false,
		srpIdHead: uint32(1),
		logger:    logger,
		pccType:   pcep.RFC_COMPLIANT,
	}
	return s
}

func (s *Session) Established() {
	if err := s.Open(); err != nil {
		s.logger.Info("PCEP OPEN error", zap.String("session", s.peerAddr.String()), zap.Error(err))
		return
	}
	s.logger.Info("PCEP session established")

	if err := s.SendKeepalive(); err != nil {
		s.logger.Info("Keepalive send error", zap.String("session", s.peerAddr.String()), zap.Error(err))
		return
	}

	closeChan := make(chan bool)
	defer close(closeChan)
	go func() {
		if err := s.ReceivePcepMessage(); err != nil {
			s.logger.Info("Receive PCEP error", zap.String("session", s.peerAddr.String()))
		}
		closeChan <- true
	}()

	ticker := time.NewTicker(time.Duration(KEEPALIVE) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C: // pass KEEPALIVE seconds
			if err := s.SendKeepalive(); err != nil {
				s.logger.Info("Keepalive send error", zap.String("session", s.peerAddr.String()), zap.Error(err))
			}
		}
	}
}

func (s *Session) Open() error {
	if err := s.ReceiveOpen(); err != nil {
		return err
	}

	if err := s.SendOpen(); err != nil {
		return err
	}
	return nil
}

func (s *Session) ReceiveOpen() error {
	// Parse CommonHeader
	byteOpenHeader := make([]uint8, pcep.COMMON_HEADER_LENGTH)
	if _, err := s.tcpConn.Read(byteOpenHeader); err != nil {
		return err
	}

	var openHeader pcep.CommonHeader
	openHeader.DecodeFromBytes(byteOpenHeader)
	// CommonHeader Validation
	if openHeader.Version != 1 {
		return fmt.Errorf("PCEP version mismatch (receive version: %d)", openHeader.Version)
	}
	if openHeader.MessageType != pcep.MT_OPEN {
		return fmt.Errorf("this peer has not been opened (messageType: %d)", openHeader.MessageType)
	}

	s.logger.Info("Receive Open", zap.String("session", s.peerAddr.String()))

	// Parse objectClass
	byteOpenObject := make([]uint8, openHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
	if _, err := s.tcpConn.Read(byteOpenObject); err != nil {
		return err
	}

	var openMessage pcep.OpenMessage
	if err := openMessage.DecodeFromBytes(byteOpenObject); err != nil {
		return err
	}

	// TODO: Parse OPEN Object

	// pccType detection
	// * FRRouting cannot be detected from the open message, so it is treated as an RFC compliant
	for _, openObjTlv := range openMessage.OpenObject.Tlvs {
		if openObjTlv.Type != pcep.TLV_ASSOC_TYPE_LIST {
			continue
		}
		for i, v := 0, openObjTlv.Value; i < int(openObjTlv.Length)/2; i++ { //
			if binary.BigEndian.Uint16(v) == uint16(20) { // Cisco specific Assoc-Type
				s.pccType = pcep.CISCO_LEGACY
				break
			} else if binary.BigEndian.Uint16(v) == uint16(65505) { // Juniper specific Assoc-Type
				s.pccType = pcep.JUNIPER_LEGACY
				break
			}
			v = v[2:]
		}
	}
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
			bytePcrptMessageBody := make([]uint8, commonHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
			if _, err := s.tcpConn.Read(bytePcrptMessageBody); err != nil {
				return err
			}
			pcrptMessage := pcep.NewPCRptMessage()
			if err := pcrptMessage.DecodeFromBytes(bytePcrptMessageBody); err != nil {
				return err
			}
			if pcrptMessage.LspObject.SFlag {
				// During LSP state synchronization (RFC8231 5.6)
				srPolicy := pcrptMessage.ToSRPolicy(s.pccType)
				s.logger.Info("Synchronize SR Policy information", zap.String("session", s.peerAddr.String()), zap.Any("SRPolicy", srPolicy), zap.Any("Message", pcrptMessage))
				go s.RegisterSRPolicy(srPolicy)
			} else if !pcrptMessage.LspObject.SFlag {
				if pcrptMessage.LspObject.PlspId == 0 {
					// End of synchronization (RFC8231 5.6)
					s.logger.Info("Finish PCRpt state synchronization", zap.String("session", s.peerAddr.String()))
					s.isSynced = true
				} else if pcrptMessage.SrpObject.SrpId != 0 {
					// Response to PCInitiate/PCUpdate (RFC8231 7.2)
					srPolicy := pcrptMessage.ToSRPolicy(s.pccType)
					s.logger.Info("Finish Stateful PCE request", zap.String("session", s.peerAddr.String()), zap.Uint32("srpId", pcrptMessage.SrpObject.SrpId))
					go s.RegisterSRPolicy(srPolicy)
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
			s.logger.Info("Received unsupported MessageType", zap.String("session", s.peerAddr.String()), zap.Uint8("MessageType", commonHeader.MessageType))
		}
	}
}

func (s *Session) SendPCInitiate(srPolicy table.SRPolicy) error {

	pcinitiateMessage, err := pcep.NewPCInitiateMessage(s.srpIdHead, srPolicy.Name, srPolicy.SegmentList, srPolicy.Color, srPolicy.Preference, srPolicy.SrcAddr, srPolicy.DstAddr, pcep.VendorSpecific(s.pccType))
	if err != nil {
		return err
	}
	bytePCInitiateMessage, err := pcinitiateMessage.Serialize()
	if err != nil {
		return err
	}

	s.logger.Info("Send PCInitiate", zap.String("session", s.peerAddr.String()), zap.Uint32("srpId", s.srpIdHead), zap.Any("srPolicy", srPolicy))
	if _, err := s.tcpConn.Write(bytePCInitiateMessage); err != nil {
		return err
	}
	s.srpIdHead += 1
	return nil
}

func (s *Session) SendPCUpdate(srPolicy table.SRPolicy) error {
	pcupdateMessage, err := pcep.NewPCUpdMessage(s.srpIdHead, srPolicy.Name, srPolicy.PlspId, srPolicy.SegmentList)
	if err != nil {
		return err
	}
	bytePCUpdMessage, err := pcupdateMessage.Serialize()
	if err != nil {
		return err
	}

	s.logger.Info("Send PCUpdate", zap.String("session", s.peerAddr.String()), zap.Uint32("srpId", pcupdateMessage.SrpObject.SrpId), zap.Any("srPolicy", srPolicy))
	if _, err := s.tcpConn.Write(bytePCUpdMessage); err != nil {
		s.logger.Info("PCUpdate send error", zap.String("session", s.peerAddr.String()))
		return err
	}
	s.srpIdHead += 1
	return nil
}

func (s *Session) RegisterSRPolicy(srPolicy table.SRPolicy) {
	s.DeleteSRPolicy(srPolicy.PlspId)
	s.srPolicies = append(s.srPolicies, srPolicy)
}

func (s *Session) DeleteSRPolicy(plspId uint32) {
	for i, v := range s.srPolicies {
		if plspId == v.PlspId {
			s.srPolicies[i] = s.srPolicies[len(s.srPolicies)-1]
			s.srPolicies = s.srPolicies[:len(s.srPolicies)-1]
			break
		}
	}
}

// return (PLSP-ID, true) if SR Policy is registerd, otherwise return (0, false)
func (s *Session) SearchSRPolicyPlspId(color uint32, endpoint netip.Addr) (uint32, bool) {
	for _, v := range s.srPolicies {
		if color == v.Color && endpoint == v.DstAddr {
			return v.PlspId, true
		}
	}
	return 0, false
}
