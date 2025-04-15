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
	sessionID       uint8
	peerAddr        netip.Addr
	tcpConn         *net.TCPConn
	isSynced        bool
	srpIDHead       uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	srPolicies      []*table.SRPolicy
	logger          *zap.Logger
	keepAlive       uint8
	pccType         pcep.PccType
	pccCapabilities []pcep.CapabilityInterface
}

func NewSession(sessionID uint8, peerAddr netip.Addr, tcpConn *net.TCPConn, logger *zap.Logger) *Session {
	return &Session{
		sessionID: sessionID,
		isSynced:  false,
		srpIDHead: uint32(1),
		logger:    logger.With(zap.String("server", "pcep"), zap.String("session", peerAddr.String())),
		pccType:   pcep.RFCCompliant,
		peerAddr:  peerAddr,
		tcpConn:   tcpConn,
	}
}

func (ss *Session) Established() {
	if err := ss.Open(); err != nil {
		ss.logger.Debug("ERROR! PCEP OPEN", zap.Error(err))
		return
	}
	ss.logger.Debug("PCEP session established")

	// Send the initial keepalive message
	if err := ss.SendKeepalive(); err != nil {
		ss.logger.Debug("ERROR! Send Keepalive Message", zap.Error(err))
		return
	}

	done := make(chan struct{})
	defer close(done)

	// Receive PCEP messages in a separate goroutine
	go func() {
		if err := ss.ReceivePCEPMessage(); err != nil {
			ss.logger.Debug("ERROR! Receive PCEP Message", zap.Error(err))
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
				ss.logger.Debug("ERROR! Send Keepalive Message", zap.Error(err))
				done <- struct{}{}
			}
		}
	}
}

func (ss *Session) sendPCEPMessage(message pcep.Message) error {
	byteMessage, err := message.Serialize()
	if err != nil {
		return err
	}
	if _, err = ss.tcpConn.Write(byteMessage); err != nil {
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
	byteOpenHeader := make([]uint8, pcep.CommonHeaderLength)
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
	if openHeader.MessageType != pcep.MessageTypeOpen {
		return nil, fmt.Errorf("this peer has not been opened (messageType: %s)", openHeader.MessageType.String())
	}

	byteOpenObject := make([]uint8, openHeader.MessageLength-pcep.CommonHeaderLength)
	if _, err := ss.tcpConn.Read(byteOpenObject); err != nil {
		return nil, err
	}

	var openMessage pcep.OpenMessage
	if err := openMessage.DecodeFromBytes(byteOpenObject); err != nil {
		return nil, err
	}

	return &openMessage, nil
}

func (ss *Session) ReceiveOpen() error {
	ss.logger.Debug("Receive Open Message")
	openMessage, err := ss.parseOpenMessage()
	if err != nil {
		return err
	}

	ss.pccCapabilities = pcep.PolaCapability(openMessage.OpenObject.Caps)

	// pccType detection
	// * FRRouting cannot be detected from the open message, so it is treated as an RFC compliant
	ss.pccType = pcep.DeterminePccType(ss.pccCapabilities)
	ss.logger.Debug("Determine PCC Type", zap.Int("pcc-type", int(ss.pccType)))
	ss.keepAlive = openMessage.OpenObject.Keepalive

	return nil
}

func (ss *Session) SendKeepalive() error {
	keepaliveMessage, err := pcep.NewKeepaliveMessage()
	if err != nil {
		return err
	}
	ss.logger.Debug("Send Keepalive Message")
	return ss.sendPCEPMessage(keepaliveMessage)
}

func (ss *Session) SendClose(reason pcep.CloseReason) error {
	closeMessage, err := pcep.NewCloseMessage(reason)
	if err != nil {
		return err
	}
	byteCloseMessage := closeMessage.Serialize()

	ss.logger.Debug("Send Close Message",
		zap.Uint8("reason", uint8(closeMessage.CloseObject.Reason)),
		zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))
	if _, err := ss.tcpConn.Write(byteCloseMessage); err != nil {
		return err
	}
	return nil
}

func (ss *Session) ReceivePCEPMessage() error {
	for {
		commonHeader, err := ss.readCommonHeader()
		if err != nil {
			return err
		}
		// wait TCP reassembly packet
		time.Sleep(10 * time.Millisecond)

		switch commonHeader.MessageType {
		case pcep.MessageTypeKeepalive:
			ss.logger.Debug("Received Keepalive")
		case pcep.MessageTypeReport:
			err = ss.handlePCRpt(commonHeader.MessageLength)
			if err != nil {
				return err
			}
		case pcep.MessageTypeError:
			bytePCErrMessageBody := make([]uint8, commonHeader.MessageLength-pcep.CommonHeaderLength)
			if _, err := ss.tcpConn.Read(bytePCErrMessageBody); err != nil {
				return err
			}
			pcerrMessage := &pcep.PCErrMessage{}
			if err := pcerrMessage.DecodeFromBytes(bytePCErrMessageBody); err != nil {
				return err
			}

			ss.logger.Debug("Received PCErr",
				zap.Uint8("error-Type", pcerrMessage.PCEPErrorObject.ErrorType),
				zap.Uint8("error-value", pcerrMessage.PCEPErrorObject.ErrorValue),
				zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-error-object"))
		case pcep.MessageTypeClose:
			byteCloseMessageBody := make([]uint8, commonHeader.MessageLength-pcep.CommonHeaderLength)
			if _, err := ss.tcpConn.Read(byteCloseMessageBody); err != nil {
				return err
			}
			closeMessage := &pcep.CloseMessage{}
			if err := closeMessage.DecodeFromBytes(byteCloseMessageBody); err != nil {
				return err
			}
			ss.logger.Debug("Received Close",
				zap.String("reason", closeMessage.CloseObject.Reason.String()),
				zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))
			// Close session if get Close Message
			return nil
		default:
			ss.logger.Debug("Received unsupported MessageType",
				zap.String("MessageType", commonHeader.MessageType.String()))
		}
	}
}

func (ss *Session) readCommonHeader() (*pcep.CommonHeader, error) {
	commonHeaderBytes := make([]uint8, pcep.CommonHeaderLength)
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
	ss.logger.Debug("Received PCRpt Message")

	messageBodyBytes := make([]uint8, length-pcep.CommonHeaderLength)
	if _, err := ss.tcpConn.Read(messageBodyBytes); err != nil {
		return err
	}

	message := pcep.NewPCRptMessage()
	if err := message.DecodeFromBytes(messageBodyBytes); err != nil {
		return err
	}

	for _, sr := range message.StateReports {
		// synchronization
		if sr.LSPObject.SFlag {
			ss.logger.Debug("Synchronize SR Policy information", zap.Any("Message", message))
			ss.RegisterSRPolicy(*sr)
		} else if !sr.LSPObject.SFlag {
			switch {
			// finish synchronization
			case sr.LSPObject.PlspID == 0:
				ss.logger.Debug("Finish PCRpt state synchronization")
				ss.isSynced = true
			// response to request from PCE
			case sr.SrpObject.SrpID != 0:
				ss.logger.Debug("Finish Stateful PCE request", zap.Uint32("srpID", sr.SrpObject.SrpID))
				if sr.LSPObject.RFlag {
					ss.DeleteSRPolicy(*sr)
				} else {
					ss.RegisterSRPolicy(*sr)
				}

			default:
				if sr.LSPObject.RFlag {
					ss.DeleteSRPolicy(*sr)
				} else {
					ss.RegisterSRPolicy(*sr)
				}
			}
		}
	}
	return nil
}

func (ss *Session) RequestAllSRPolicyDeleted() error {
	var srPolicy table.SRPolicy
	return ss.SendPCInitiate(srPolicy, true)
}

func (ss *Session) RequestSRPolicyDeleted(srPolicy table.SRPolicy) error {
	return ss.SendPCInitiate(srPolicy, true)
}

func (ss *Session) RequestSRPolicyCreated(srPolicy table.SRPolicy) error {
	return ss.SendPCInitiate(srPolicy, false)
}

func (ss *Session) SendOpen() error {
	openMessage, err := pcep.NewOpenMessage(ss.sessionID, ss.keepAlive, ss.pccCapabilities)
	if err != nil {
		return err
	}
	ss.logger.Debug("Send Open Message")
	return ss.sendPCEPMessage(openMessage)
}

func (ss *Session) SendPCInitiate(srPolicy table.SRPolicy, lspDelete bool) error {
	pcinitiateMessage, err := pcep.NewPCInitiateMessage(ss.srpIDHead, srPolicy.Name, lspDelete, srPolicy.PlspID, srPolicy.SegmentList, srPolicy.Color, srPolicy.Preference, srPolicy.SrcAddr, srPolicy.DstAddr, pcep.VendorSpecific(ss.pccType))
	if err != nil {
		return err
	}
	ss.logger.Debug("Send PCInitiate Message")
	err = ss.sendPCEPMessage(pcinitiateMessage)
	if err == nil {
		ss.srpIDHead++
	}
	return err
}

func (ss *Session) SendPCUpdate(srPolicy table.SRPolicy) error {
	pcupdateMessage, err := pcep.NewPCUpdMessage(ss.srpIDHead, srPolicy.Name, srPolicy.PlspID, srPolicy.SegmentList)
	if err != nil {
		return err
	}
	ss.logger.Debug("Send Update Message")
	err = ss.sendPCEPMessage(pcupdateMessage)
	if err == nil {
		ss.srpIDHead++
	}
	return err
}

func (ss *Session) RegisterSRPolicy(sr pcep.StateReport) {
	var color uint32 = 0      // Default color value (RFC does not specify a default)
	var preference uint32 = 0 // Default preference value (RFC does not specify a default)

	if ss.pccType == pcep.CiscoLegacy {
		// In Cisco legacy mode, get color and preference from Vendor Information Object
		color = sr.VendorInformationObject.Color()
		preference = sr.VendorInformationObject.Preference()
	} else {
		// TODO: Move hasColorCapability to Session struct
		hasColorCapability := false
		for _, cap := range ss.pccCapabilities {
			if statefulCap, ok := cap.(*pcep.StatefulPCECapability); ok {
				if statefulCap.ColorCapability {
					hasColorCapability = true
					break
				}
			}
		}

		// SR Policy Association color takes precedence over LSP Object Color TLV
		// Ref: https://datatracker.ietf.org/doc/draft-ietf-pce-pcep-color/12/ Section 2
		if sr.AssociationObject.Color() != 0 {
			color = sr.AssociationObject.Color()
		} else if hasColorCapability {
			color = sr.LSPObject.Color()
		}

		preference = sr.AssociationObject.Preference()
	}

	lspID := sr.LSPObject.LSPID

	var state table.PolicyState
	switch sr.LSPObject.OFlag {
	case uint8(0x00):
		state = table.PolicyDown
	case uint8(0x01):
		state = table.PolicyUp
	case uint8(0x02):
		state = table.PolicyActive
	default:
		state = table.PolicyUnknown
	}

	if p, ok := ss.SearchSRPolicy(sr.LSPObject.PlspID); ok {
		// update
		// If the LSP ID is old, it is not the latest data update.
		if p.LSPID <= lspID {
			p.Update(
				table.PolicyDiff{
					Name:        &sr.LSPObject.Name,
					Color:       &color,
					Preference:  &preference,
					SegmentList: sr.EroObject.ToSegmentList(),
					LSPID:       lspID,
					State:       state,
				},
			)
		}
	} else {
		// create
		var src, dst netip.Addr
		if src = sr.LSPObject.SrcAddr; !src.IsValid() {
			src = sr.AssociationObject.AssocSrc
		}
		if dst = sr.LSPObject.DstAddr; !dst.IsValid() {
			dst = sr.AssociationObject.Endpoint()
		}
		p := table.NewSRPolicy(
			sr.LSPObject.PlspID,
			sr.LSPObject.Name,
			sr.EroObject.ToSegmentList(),
			src,
			dst,
			color,
			preference,
			lspID,
			state,
		)
		ss.srPolicies = append(ss.srPolicies, p)
	}
}

func (ss *Session) DeleteSRPolicy(sr pcep.StateReport) {
	lspID := sr.LSPObject.LSPID
	for i, v := range ss.srPolicies {
		// If the LSP ID is old, it is not the latest data update.
		if v.PlspID == sr.LSPObject.PlspID && v.LSPID <= lspID {
			ss.srPolicies[i] = ss.srPolicies[len(ss.srPolicies)-1]
			ss.srPolicies = ss.srPolicies[:len(ss.srPolicies)-1]
			break
		}
	}
}

func (ss *Session) SearchSRPolicy(plspID uint32) (*table.SRPolicy, bool) {
	for _, v := range ss.srPolicies {
		if v.PlspID == plspID {
			return v, true
		}
	}
	return nil, false
}

// SearchPlspID returns the PLSP-ID of a registered SR Policy, along with a boolean value indicating if it was found.
func (ss *Session) SearchPlspID(color uint32, endpoint netip.Addr) (uint32, bool) {
	for _, v := range ss.srPolicies {
		if v.Color == color && v.DstAddr == endpoint {
			return v.PlspID, true
		}
	}
	return 0, false
}
