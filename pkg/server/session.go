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
	ss := &Session{
		sessionId: sessionId,
		isSynced:  false,
		srpIdHead: uint32(1),
		logger:    logger,
		pccType:   pcep.RFC_COMPLIANT,
	}
	return ss
}

func (ss *Session) Established() {
	if err := ss.Open(); err != nil {
		ss.logger.Info("PCEP OPEN error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
		return
	}
	ss.logger.Info("PCEP session established")

	if err := ss.SendKeepalive(); err != nil {
		ss.logger.Info("Keepalive send error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
		return
	}

	closeChan := make(chan bool)
	defer close(closeChan)
	go func() {
		if err := ss.ReceivePcepMessage(); err != nil {
			ss.logger.Info("Receive PCEP error", zap.String("session", ss.peerAddr.String()))
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
			if err := ss.SendKeepalive(); err != nil {
				ss.logger.Info("Keepalive send error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
			}
		}
	}
}

func (ss *Session) Open() error {
	if err := ss.ReceiveOpen(); err != nil {
		return err
	}

	if err := ss.SendOpen(); err != nil {
		return err
	}
	return nil
}

func (ss *Session) ReceiveOpen() error {
	// Parse CommonHeader
	byteOpenHeader := make([]uint8, pcep.COMMON_HEADER_LENGTH)
	if _, err := ss.tcpConn.Read(byteOpenHeader); err != nil {
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

	ss.logger.Info("Receive Open", zap.String("session", ss.peerAddr.String()))

	// Parse objectClass
	byteOpenObject := make([]uint8, openHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
	if _, err := ss.tcpConn.Read(byteOpenObject); err != nil {
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
				ss.pccType = pcep.CISCO_LEGACY
				break
			} else if binary.BigEndian.Uint16(v) == uint16(65505) { // Juniper specific Assoc-Type
				ss.pccType = pcep.JUNIPER_LEGACY
				break
			}
			v = v[2:]
		}
	}
	return nil
}

func (ss *Session) SendOpen() error {
	openMessage := pcep.NewOpenMessage(ss.sessionId, KEEPALIVE)
	byteOpenMessage := openMessage.Serialize()

	ss.logger.Info("Send Open", zap.String("session", ss.peerAddr.String()))
	if _, err := ss.tcpConn.Write(byteOpenMessage); err != nil {
		ss.logger.Info("Open send error", zap.String("session", ss.peerAddr.String()))
		return err
	}
	return nil
}

func (ss *Session) SendKeepalive() error {
	keepaliveMessage := pcep.NewKeepaliveMessage()
	byteKeepaliveMessage := keepaliveMessage.Serialize()

	ss.logger.Info("Send Keepalive", zap.String("session", ss.peerAddr.String()))
	if _, err := ss.tcpConn.Write(byteKeepaliveMessage); err != nil {
		return err
	}
	return nil
}

func (ss *Session) ReceivePcepMessage() error {
	for {
		byteCommonHeader := make([]uint8, pcep.COMMON_HEADER_LENGTH)
		if _, err := ss.tcpConn.Read(byteCommonHeader); err != nil {
			return err
		}
		var commonHeader pcep.CommonHeader
		commonHeader.DecodeFromBytes(byteCommonHeader)

		switch commonHeader.MessageType {
		case pcep.MT_KEEPALIVE:
			ss.logger.Info("Received Keepalive", zap.String("session", ss.peerAddr.String()))
		case pcep.MT_REPORT:
			ss.logger.Info("Received PCRpt", zap.String("session", ss.peerAddr.String()))
			bytePcrptMessageBody := make([]uint8, commonHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
			if _, err := ss.tcpConn.Read(bytePcrptMessageBody); err != nil {
				return err
			}
			pcrptMessage := pcep.NewPCRptMessage()
			if err := pcrptMessage.DecodeFromBytes(bytePcrptMessageBody); err != nil {
				return err
			}
			if pcrptMessage.LspObject.SFlag {
				// During LSP state synchronization (RFC8231 5.6)
				srPolicy := pcrptMessage.ToSRPolicy(ss.pccType)
				ss.logger.Info("Synchronize SR Policy information", zap.String("session", ss.peerAddr.String()), zap.Any("SRPolicy", srPolicy), zap.Any("Message", pcrptMessage))
				go ss.RegisterSRPolicy(srPolicy)
			} else if !pcrptMessage.LspObject.SFlag {
				if pcrptMessage.LspObject.PlspId == 0 {
					// End of synchronization (RFC8231 5.6)
					ss.logger.Info("Finish PCRpt state synchronization", zap.String("session", ss.peerAddr.String()))
					ss.isSynced = true
				} else if pcrptMessage.SrpObject.SrpId != 0 {
					// Response to PCInitiate/PCUpdate (RFC8231 7.2)
					srPolicy := pcrptMessage.ToSRPolicy(ss.pccType)
					ss.logger.Info("Finish Stateful PCE request", zap.String("session", ss.peerAddr.String()), zap.Uint32("srpId", pcrptMessage.SrpObject.SrpId))
					go ss.RegisterSRPolicy(srPolicy)
				}
				// TODO: Need to implementation of PCUpdate for Passive stateful PCE
			}
		case pcep.MT_ERROR:
			ss.logger.Info("Received PCErr", zap.String("session", ss.peerAddr.String()))
			// TODO: Display error details
		case pcep.MT_CLOSE:
			ss.logger.Info("Received Close", zap.String("session", ss.peerAddr.String()))
			// Close session if get Close Message
			return nil

		default:
			ss.logger.Info("Received unsupported MessageType", zap.String("session", ss.peerAddr.String()), zap.Uint8("MessageType", commonHeader.MessageType))
		}
	}
}

func (ss *Session) SendPCInitiate(srPolicy table.SRPolicy) error {

	pcinitiateMessage, err := pcep.NewPCInitiateMessage(ss.srpIdHead, srPolicy.Name, srPolicy.SegmentList, srPolicy.Color, srPolicy.Preference, srPolicy.SrcAddr, srPolicy.DstAddr, pcep.VendorSpecific(ss.pccType))
	if err != nil {
		return err
	}
	bytePCInitiateMessage, err := pcinitiateMessage.Serialize()
	if err != nil {
		return err
	}

	ss.logger.Info("Send PCInitiate", zap.String("session", ss.peerAddr.String()), zap.Uint32("srpId", ss.srpIdHead), zap.Any("srPolicy", srPolicy))
	if _, err := ss.tcpConn.Write(bytePCInitiateMessage); err != nil {
		return err
	}
	ss.srpIdHead += 1
	return nil
}

func (ss *Session) SendPCUpdate(srPolicy table.SRPolicy) error {
	pcupdateMessage, err := pcep.NewPCUpdMessage(ss.srpIdHead, srPolicy.Name, srPolicy.PlspId, srPolicy.SegmentList)
	if err != nil {
		return err
	}
	bytePCUpdMessage, err := pcupdateMessage.Serialize()
	if err != nil {
		return err
	}

	ss.logger.Info("Send PCUpdate", zap.String("session", ss.peerAddr.String()), zap.Uint32("srpId", pcupdateMessage.SrpObject.SrpId), zap.Any("srPolicy", srPolicy))
	if _, err := ss.tcpConn.Write(bytePCUpdMessage); err != nil {
		ss.logger.Info("PCUpdate send error", zap.String("session", ss.peerAddr.String()))
		return err
	}
	ss.srpIdHead += 1
	return nil
}

func (ss *Session) RegisterSRPolicy(srPolicy table.SRPolicy) {
	ss.DeleteSRPolicy(srPolicy.PlspId)
	ss.srPolicies = append(ss.srPolicies, srPolicy)
}

func (ss *Session) DeleteSRPolicy(plspId uint32) {
	for i, v := range ss.srPolicies {
		if plspId == v.PlspId {
			ss.srPolicies[i] = ss.srPolicies[len(ss.srPolicies)-1]
			ss.srPolicies = ss.srPolicies[:len(ss.srPolicies)-1]
			break
		}
	}
}

// return (PLSP-ID, true) if SR Policy is registerd, otherwise return (0, false)
func (ss *Session) SearchSRPolicyPlspId(color uint32, endpoint netip.Addr) (uint32, bool) {
	for _, v := range ss.srPolicies {
		if color == v.Color && endpoint == v.DstAddr {
			return v.PlspId, true
		}
	}
	return 0, false
}
