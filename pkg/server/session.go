package server

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/nttcom/pola/pkg/packet/pcep"
)

const KEEPALIVE uint8 = 30

// type lsp struct {
// 	peerAddr    net.IP // 後々 router ID, router name などに変更したい
// 	plspId      uint32
// 	name        string
// 	pcrptObject pcep.PcrptObject
// }

type Session struct {
	sessionId uint8
	peerAddr  net.IP
	tcpConn   net.Conn
	isSynced  bool
	srpIdHead uint32
	lspChan   chan Lsp
}

func (s *Session) Close() {
	// セッション情報の削除も入れたい
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

	if err := Open(s.tcpConn, s.sessionId); err != nil {
		fmt.Printf("pcep open error")
		log.Fatal(nil)
	}
	if err := SendKeepAlive(s.tcpConn); err != nil {
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
		case <-ticker.C: // KEEPALIVE time 経過した場合
			if err := SendKeepAlive(s.tcpConn); err != nil {
				fmt.Printf("[session] Keepalive error\n")
				log.Fatal(nil)
			}
			fmt.Printf("[session] Show Session state\n")
			fmt.Printf("[session] Session => %#v\n", s)
		}
	}
}

/* pcep の interactive な動作を行う関数定義 */
func Open(conn net.Conn, sessionID uint8) error {
	if err := ReadOpen(conn); err != nil {
		return err
	}
	if err := SendOpen(conn, sessionID); err != nil {
		return err
	}
	return nil
}

func ReadOpen(conn net.Conn) error {
	// Parse CommonHeader
	headerBuf := make([]uint8, pcep.COMMON_HEADER_LENGTH)

	if _, err := conn.Read(headerBuf); err != nil {
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

	if _, err := conn.Read(objectClassBuf); err != nil {
		return err
	}
	var commonObjectHeader pcep.CommonObjectHeader
	if err := commonObjectHeader.DecodeFromBytes(objectClassBuf); err != nil {
		return err
	}
	// first get が open object でない場合は破棄
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

func SendOpen(conn net.Conn, sessionID uint8) error {
	// NewTLVsとかにしたい
	pcepTLVs := []pcep.Tlv{
		{
			Type:   pcep.TLV_STATEFUL_PCE_CAPABILITY,
			Length: pcep.TLV_STATEFUL_PCE_CAPABILITY_LENGTH,
			Value:  []uint8{0x00, 0x00, 0x00, 0x05},
		},
		{
			Type:   pcep.TLV_SR_PCE_CAPABILITY,
			Length: pcep.TLV_SR_PCE_CAPABILITY_LENGTH,
			Value:  []uint8{0x00, 0x00, 0x00, 0x0a},
		},
		{
			Type:   pcep.TLV_ASSOC_TYPE_LIST,
			Length: pcep.TLV_ASSOC_TYPE_LIST_LENGTH,
			Value:  []uint8{0x00, 0x14},
		},
	}
	/* open object の作成 */
	openObject := pcep.NewOpenObject(sessionID, KEEPALIVE, pcepTLVs)
	byteOpenObject, err := openObject.Serialize()
	if err != nil {
		return err
	}
	openHeaderLength := openObject.GetByteLength() + pcep.COMMON_HEADER_LENGTH
	openHeader := pcep.NewCommonHeader(pcep.MT_OPEN, openHeaderLength)
	byteOpenHeader, err := openHeader.Serialize()
	if err != nil {
		return err
	}
	byteOpenMessage := append(byteOpenHeader, byteOpenObject...)

	fmt.Printf("[session] Send Open\n")
	if _, err := conn.Write(byteOpenMessage); err != nil {
		return err
	}

	return nil
}

func SendKeepAlive(conn net.Conn) error {
	keepAliveHeader := pcep.NewCommonHeader(pcep.MT_KEEPALIVE, pcep.COMMON_HEADER_LENGTH)
	byteKeepAliveHeader, err := keepAliveHeader.Serialize()
	if err != nil {
		return err
	}
	fmt.Printf("[session] Send KeepAlive\n")
	if _, err := conn.Write(byteKeepAliveHeader); err != nil {
		return err
	}

	return nil
}

func (s *Session) ReceivePcepMessage() error {
	// latestSrpId := uint32(1) // 0x00000000 and 0xFFFFFFFF are reserved.
	for {
		// pcep common header を取得
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
			fmt.Printf("[PCEP] Received KeepAlive\n")
		case pcep.MT_REPORT:
			fmt.Printf("[PCEP] Received PCRpt\n")
			bytePcrptObject := make([]uint8, commonHeader.MessageLength-pcep.COMMON_HEADER_LENGTH)
			if _, err := s.tcpConn.Read(bytePcrptObject); err != nil {
				return err
			}
			var pcrptMessage pcep.PCRptMessage
			if err := pcrptMessage.DecodeFromBytes(bytePcrptObject); err != nil {
				return err
			}
			if pcrptMessage.LspObject.SFlag {
				// Sync 中処理
				// LSP を登録する
				fmt.Printf("  Synchronize LSP information for PLSP-ID: %v\n", pcrptMessage.LspObject.PlspId)
				go RegisterLsp(s.lspChan, s.peerAddr, pcrptMessage)
			} else if !pcrptMessage.LspObject.SFlag {
				if pcrptMessage.LspObject.PlspId == 0 {
					//sync 終了
					fmt.Printf(" Finish PCRpt State Synchronization\n")
					s.isSynced = true
				} else if pcrptMessage.SrpObject.SrpId != 0 {
					// PCInitiate / PCUpdate に対する応答
					fmt.Printf(" Finish Transaction SRP ID: %v\n", pcrptMessage.SrpObject.SrpId)
					go RegisterLsp(s.lspChan, s.peerAddr, pcrptMessage)
				}
				// TODO: Passive stateful PCE 用の PCUpdateを準備する必要あり
			}
		case pcep.MT_ERROR:
			fmt.Printf("[PCEP] Received PCErr\n")
			// TODO: エラー内容の表示
		case pcep.MT_CLOSE:
			fmt.Printf("[PCEP] Received Close\n")
			// receive を中断する
			// error　処理ではない気がする
			// err := fmt.Errorf("PCEP session Close")
			// return err
			return nil

		default:
			fmt.Printf("[PCEP] Received Unimplemented Message-Type: %v\n", commonHeader.MessageType)
			// TODO: このパケットを記録して捨てる
		}
	}
}

func (s *Session) SendPCInitiate(policyName string, labels []pcep.Label, color uint32, preference uint32, srcIPv4 []uint8, dstIPv4 []uint8) error {
	fmt.Printf(" *********************Start PCInitiate \n")
	pcinitiateMessage := pcep.NewPCInitiateMessage(s.srpIdHead, policyName, labels, color, preference, srcIPv4, dstIPv4)

	bytePCInitiateMessage, err := pcinitiateMessage.Serialize()
	if err != nil {
		fmt.Printf("initiate error")
		return err
	}

	fmt.Printf("******************** [PCEP] Send Initiate\n")
	if _, err := s.tcpConn.Write(bytePCInitiateMessage); err != nil {
		fmt.Printf("[session] PCInitiate error\n")
		return err
	}
	s.srpIdHead += 1
	return nil
}

func (s *Session) SendPCUpdate(policyName string, plspId uint32, labels []pcep.Label) error {
	// PLSP ID も入りそう
	fmt.Printf(" *********************Start PCUpdate \n")
	pcupdateMessage := pcep.NewPCUpdMessage(s.srpIdHead, policyName, plspId, labels)

	bytePCUpdMessage, err := pcupdateMessage.Serialize()
	if err != nil {
		fmt.Printf("[session] PCUpdate Seliarize Error")
		return err
	}

	fmt.Printf("******************** [PCEP] Send PCUpdate\n")
	if _, err := s.tcpConn.Write(bytePCUpdMessage); err != nil {
		fmt.Printf("[session] PCUpdate Send Error\n")
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
		//後々これは消したい
		pcrptMessage: pcrptMessage,
	}

	lspChan <- lspStruct
}
