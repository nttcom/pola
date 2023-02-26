// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/pkg/packet/pcep"

	"go.uber.org/zap"
)

type Session struct {
	sessionId       uint8
	peerAddr        netip.Addr
	tcpConn         *net.TCPConn
	isSynced        bool
	srpIdHead       uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	srPolicies      []table.SRPolicy
	logger          *zap.Logger
	keepAlive       uint8
	pccType         pcep.PccType
	pccCapabilities []pcep.CapabilityInterface
}

func NewSession(sessionId uint8, logger *zap.Logger) *Session {
	return &Session{
		sessionId: sessionId,
		isSynced:  false,
		srpIdHead: uint32(1),
		logger:    logger,
		pccType:   pcep.RFC_COMPLIANT,
	}
}

func (ss *Session) Established() {
	if err := ss.Open(); err != nil {
		ss.logger.Info("PCEP OPEN error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
		return
	}

	ss.logger.Info("PCEP session established")

	// Send the initial keepalive message
	if err := ss.SendKeepalive(); err != nil {
		ss.logger.Info("Keepalive send error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
		return
	}

	done := make(chan struct{})
	defer close(done)

	// Receive PCEP messages in a separate goroutine
	go func() {
		if err := ss.ReceivePcepMessage(); err != nil {
			ss.logger.Info("Receive PCEP Message error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
		}
		done <- struct{}{}
	}()

	ticker := time.NewTicker(time.Duration(ss.keepAlive) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := ss.SendKeepalive(); err != nil {
				ss.logger.Info("Keepalive send error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
			}
		}
	}
}

func (ss *Session) sendPcepMessage(message pcep.Message, logMessage string) error {
	byteMessage, err := message.Serialize()
	if err != nil {
		return err
	}

	ss.logger.Info(logMessage, zap.String("session", ss.peerAddr.String()))
	if _, err = ss.tcpConn.Write(byteMessage); err != nil {
		ss.logger.Info(logMessage+" send error", zap.String("session", ss.peerAddr.String()), zap.Error(err))
		return err
	}
	return nil
}

func (ss *Session) Open() error {
	if err := ss.ReceiveOpen(); err != nil {
		return err
	}

	return ss.SendOpen()
}

func (ss *Session) parseOpenMessage() (*pcep.OpenMessage, error) {
	byteOpenHeader := make([]uint8, pcep.COMMON_HEADER_LENGTH)
	if _, err := ss.tcpConn.Read(byteOpenHeader); err != nil {
		return nil, err
	}

	var openHeader pcep.CommonHeader
	if err := openHeader.DecodeFromBytes(byteOpenHeader); err != nil {
		return nil, err
	}

	if openHeader.Version != 1 {
		return nil, fmt.Errorf("PCEP version mismatch (receive version: %d)", openHeader.Version)
	}
	if openHeader.MessageType != pcep.MT_OPEN {
		return nil, fmt.Errorf("this peer has not been opened (messageType: %d)", openHeader.MessageType)
	}

	byteOpenObject := make([]uint8, openHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
	if _, err := ss.tcpConn.Read(byteOpenObject); err != nil {
		return nil, err
	}

	var openMessage pcep.OpenMessage
	if err := openMessage.DecodeFromBytes(byteOpenObject); err != nil {
		return nil, err
	}

	return &openMessage, nil
}

func (ss *Session) SendOpen() error {
	openMessage, err := pcep.NewOpenMessage(ss.sessionId, ss.keepAlive, ss.pccCapabilities)
	if err != nil {
		return err
	}

	return ss.sendPcepMessage(openMessage, "Send Open")
}

func (ss *Session) ReceiveOpen() error {
	openMessage, err := ss.parseOpenMessage()
	if err != nil {
		return err
	}
	ss.pccCapabilities = append(ss.pccCapabilities, openMessage.OpenObject.Caps...)

	// pccType detection
	// * FRRouting cannot be detected from the open message, so it is treated as an RFC compliant
	ss.pccType = pcep.DeterminePccType(ss.pccCapabilities)
	ss.keepAlive = openMessage.OpenObject.Keepalive
	ss.logger.Info("Receive Open", zap.String("session", ss.peerAddr.String()))
	return nil
}

func (ss *Session) SendKeepalive() error {
	keepaliveMessage, err := pcep.NewKeepaliveMessage()
	if err != nil {
		return err
	}
	return ss.sendPcepMessage(keepaliveMessage, "Send Keepalive")
}

func (ss *Session) ReceivePcepMessage() error {
	for {
		commonHeader, err := ss.readCommonHeader()
		if err != nil {
			return err
		}

		switch commonHeader.MessageType {
		case pcep.MT_KEEPALIVE:
			ss.logger.Info("Received Keepalive", zap.String("session", ss.peerAddr.String()))
		case pcep.MT_REPORT:
			err = ss.handlePCRpt(commonHeader.MessageLength)
			if err != nil {
				return err
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

func (ss *Session) readCommonHeader() (*pcep.CommonHeader, error) {
	commonHeaderBytes := make([]uint8, pcep.COMMON_HEADER_LENGTH)
	if _, err := ss.tcpConn.Read(commonHeaderBytes); err != nil {
		return nil, err
	}

	commonHeader := &pcep.CommonHeader{}
	if err := commonHeader.DecodeFromBytes(commonHeaderBytes); err != nil {
		return nil, err
	}

	return commonHeader, nil
}

func (ss *Session) handlePCRpt(length uint16) error {
	ss.logger.Info("Received PCRpt", zap.String("session", ss.peerAddr.String()))

	messageBodyBytes := make([]uint8, length-pcep.COMMON_HEADER_LENGTH)
	if _, err := ss.tcpConn.Read(messageBodyBytes); err != nil {
		return err
	}

	message := pcep.NewPCRptMessage()
	if err := message.DecodeFromBytes(messageBodyBytes); err != nil {
		return err
	}

	for _, sr := range message.StateReports {
		if sr.LspObject.SFlag {
			srPolicy := sr.ToSRPolicy(ss.pccType)
			ss.logger.Info("Synchronize SR Policy information", zap.String("session", ss.peerAddr.String()), zap.Any("SRPolicy", srPolicy), zap.Any("Message", message))
			go ss.RegisterSRPolicy(srPolicy)
		} else if !sr.LspObject.SFlag {
			switch {
			case sr.LspObject.PlspId == 0:
				ss.logger.Info("Finish PCRpt state synchronization", zap.String("session", ss.peerAddr.String()))
				ss.isSynced = true
			case sr.SrpObject.SrpId != 0:
				srPolicy := sr.ToSRPolicy(ss.pccType)
				ss.logger.Info("Finish Stateful PCE request", zap.String("session", ss.peerAddr.String()), zap.Uint32("srpId", sr.SrpObject.SrpId))
				go ss.RegisterSRPolicy(srPolicy)
			default:
				// TODO: Need to implementation of PCUpdate for Passive stateful PCE
			}
		}
	}

	return nil
}

func (ss *Session) SendPCInitiate(srPolicy table.SRPolicy) error {
	pcinitiateMessage, err := pcep.NewPCInitiateMessage(ss.srpIdHead, srPolicy.Name, srPolicy.SegmentList, srPolicy.Color, srPolicy.Preference, srPolicy.SrcAddr, srPolicy.DstAddr, pcep.VendorSpecific(ss.pccType))
	if err != nil {
		return err
	}
	err = ss.sendPcepMessage(pcinitiateMessage, "Send PCInitiate")
	if err == nil {
		ss.srpIdHead++
	}
	return err
}

func (ss *Session) SendPCUpdate(srPolicy table.SRPolicy) error {
	pcupdateMessage, err := pcep.NewPCUpdMessage(ss.srpIdHead, srPolicy.Name, srPolicy.PlspId, srPolicy.SegmentList)
	if err != nil {
		return err
	}
	err = ss.sendPcepMessage(pcupdateMessage, "Send PCUpdate")
	if err == nil {
		ss.srpIdHead++
	}
	return err
}

func (ss *Session) RegisterSRPolicy(srPolicy table.SRPolicy) {
	ss.DeleteSRPolicy(srPolicy.PlspId)
	ss.srPolicies = append(ss.srPolicies, srPolicy)
}

func (ss *Session) DeleteSRPolicy(plspId uint32) {
	for i, v := range ss.srPolicies {
		if v.PlspId == plspId {
			ss.srPolicies[i] = ss.srPolicies[len(ss.srPolicies)-1]
			ss.srPolicies = ss.srPolicies[:len(ss.srPolicies)-1]
			break
		}
	}
}

// SearchSRPolicyPlspID returns the PLSP-ID of a registered SR Policy, along with a boolean value indicating if it was found.
func (ss *Session) SearchSRPolicyPlspId(color uint32, endpoint netip.Addr) (uint32, bool) {
	for _, v := range ss.srPolicies {
		if v.Color == color && v.DstAddr == endpoint {
			return v.PlspId, true
		}
	}
	return 0, false
}
