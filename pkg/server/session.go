// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/nttcom/pola/pkg/packet/pcep"
)

const KEEPALIVE uint8 = 30

type Session struct {
	sessionId uint8
	peerAddr  net.IP
	tcpConn   net.Conn
	isSynced  bool
	srpIdHead uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	lspChan   chan Lsp
}

func (s *Session) Close() {
	s.tcpConn.Close()
}

func NewSession(sessionId uint8, lspChan chan Lsp) *Session {
	s := &Session{
		sessionId: sessionId,
		isSynced:  false,
		srpIdHead: uint32(1),
		lspChan:   lspChan,
	}

	return s
}

func (s *Session) Established() {
	defer s.Close()

	if err := s.Open(); err != nil {
		fmt.Printf("pcep open error")
		log.Fatal(nil)
	}
	if err := s.SendKeepalive(); err != nil {
		fmt.Printf("[session] Keepalive error\n")
		log.Fatal(nil)
	}

	close := make(chan bool)
	go func() {
		if err := s.ReceivePcepMessage(); err != nil {
			fmt.Printf("Receive PCEP error\n")
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
				fmt.Printf("[session] Keepalive error\n")
				log.Fatal(nil)
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
	if err := commonHeader.DecodeFromBytes(headerBuf); err != nil {
		return err
	}

	// CommonHeader Validation
	if commonHeader.Version != 1 {
		log.Panicf("PCEP version mismatch: %#v", commonHeader.Version)
	}
	if commonHeader.MessageType != pcep.MT_OPEN {
		log.Panicf("Message Type is : %#v, This peer has not been opened.", commonHeader.MessageType)
	}

	fmt.Printf("[session] Receive Open\n")

	// Parse objectClass
	objectClassBuf := make([]uint8, commonHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)

	if _, err := s.tcpConn.Read(objectClassBuf); err != nil {
		return err
	}
	var commonObjectHeader pcep.CommonObjectHeader
	if err := commonObjectHeader.DecodeFromBytes(objectClassBuf); err != nil {
		return err
	}

	if commonObjectHeader.ObjectClass != pcep.OC_OPEN {
		log.Panicf("ObjectClass %#v is not Open", commonObjectHeader.ObjectClass)
	}

	if commonObjectHeader.ObjectType != 1 {
		log.Panicf("Unimplemented objectType: %#v", commonObjectHeader.ObjectType)
	}

	var openObject pcep.OpenObject
	if err := openObject.DecodeFromBytes(objectClassBuf); err != nil {
		return err
	}
	return nil
}

func (s *Session) SendOpen() error {
	openMessage := pcep.NewOpenMessage(s.sessionId, KEEPALIVE)

	byteOpenMessage, err := openMessage.Serialize()
	if err != nil {
		fmt.Printf("Open Seliarize Error")
		return err
	}

	fmt.Printf("Send Open\n")
	if _, err := s.tcpConn.Write(byteOpenMessage); err != nil {
		fmt.Printf("Open error\n")
		return err
	}
	return nil
}

func (s *Session) SendKeepalive() error {
	keepaliveMessage := pcep.NewKeepaliveMessage()

	byteKeepaliveMessage, err := keepaliveMessage.Serialize()
	if err != nil {
		fmt.Printf("Keepalive Seliarize Error")
		return err
	}

	fmt.Printf("Send Keepalive\n")
	if _, err := s.tcpConn.Write(byteKeepaliveMessage); err != nil {
		fmt.Printf("Keepalive error\n")
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
		if err := commonHeader.DecodeFromBytes(byteCommonHeader); err != nil {
			return err
		}

		switch commonHeader.MessageType {
		case pcep.MT_KEEPALIVE:
			fmt.Printf("Received Keepalive\n")
		case pcep.MT_REPORT:
			fmt.Printf("Received PCRpt\n")
			bytePcrptObject := make([]uint8, commonHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
			if _, err := s.tcpConn.Read(bytePcrptObject); err != nil {
				return err
			}
			var pcrptMessage pcep.PCRptMessage
			fmt.Printf(" Start Parse PCRpt\n")
			if err := pcrptMessage.DecodeFromBytes(bytePcrptObject); err != nil {
				return err
			}
			if pcrptMessage.LspObject.SFlag {
				// During LSP state synchronization (RFC8231 5.6)
				fmt.Printf("  Synchronize LSP information for PLSP-ID: %v\n", pcrptMessage.LspObject.PlspId)
				go RegisterLsp(s.lspChan, s.peerAddr, pcrptMessage)
			} else if !pcrptMessage.LspObject.SFlag {
				if pcrptMessage.LspObject.PlspId == 0 {
					// End of synchronization (RFC8231 5.6)
					fmt.Printf("  Finish PCRpt State Synchronization\n")
					s.isSynced = true
				} else if pcrptMessage.SrpObject.SrpId != 0 {
					// Response to PCInitiate/PCUpdate (RFC8231 7.2)
					fmt.Printf("  Finish Transaction SRP ID: %v\n", pcrptMessage.SrpObject.SrpId)
					go RegisterLsp(s.lspChan, s.peerAddr, pcrptMessage)
				}
				// TODO: Need to implementation of PCUpdate for Passive stateful PCE
			}
		case pcep.MT_ERROR:
			fmt.Printf("Received PCErr\n")
			// TODO: Display error details
		case pcep.MT_CLOSE:
			fmt.Printf("Received Close\n")
			// Close session if get Close Message
			return nil

		default:
			fmt.Printf("Received Unimplemented Message-Type: %v\n", commonHeader.MessageType)
			// TODO: Logging and discard this packet
		}
	}
}

func (s *Session) SendPCInitiate(policyName string, labels []pcep.Label, color uint32, preference uint32, srcIPv4 []uint8, dstIPv4 []uint8) error {
	pcinitiateMessage := pcep.NewPCInitiateMessage(s.srpIdHead, policyName, labels, color, preference, srcIPv4, dstIPv4)

	bytePCInitiateMessage, err := pcinitiateMessage.Serialize()
	if err != nil {
		fmt.Printf("PCInitiate Seliarize Error")
		return err
	}

	fmt.Printf("Send PCInitiate\n")
	if _, err := s.tcpConn.Write(bytePCInitiateMessage); err != nil {
		fmt.Printf("PCInitiate error\n")
		return err
	}
	s.srpIdHead += 1
	return nil
}

func (s *Session) SendPCUpdate(policyName string, plspId uint32, labels []pcep.Label) error {
	pcupdateMessage := pcep.NewPCUpdMessage(s.srpIdHead, policyName, plspId, labels)

	bytePCUpdMessage, err := pcupdateMessage.Serialize()
	if err != nil {
		fmt.Printf("PCUpdate Seliarize Error")
		return err
	}

	fmt.Printf("Send PCUpdate\n")
	if _, err := s.tcpConn.Write(bytePCUpdMessage); err != nil {
		fmt.Printf("PCUpdate Send Error\n")
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
