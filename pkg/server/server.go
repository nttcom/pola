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
	"sync"
	"time"

	grpc "google.golang.org/grpc"

	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/pkg/packet/pcep"
)

// TODO: 引数やconfファイルで上書きできるようにする
const PCEPPORT = "4189"
const PCEPADDR = "10.100.0.252"
const KEEPALIVE = 30

type lsp struct {
	sessionAddr net.IP // 後々 router ID, router name などに変更したい
	plspId      uint32
	name        string
	pcrptObject pcep.PcrptObjects
}

type pcepSession struct {
	pcepSessionAddr net.IP
	tcpConn         net.Conn
	isSynced        bool
}

func (s *pcepSession) close() {
	s.tcpConn.Close()
}

type Server struct {
	pcepSessionList []pcepSession
	lspList         []lsp
	pb.UnimplementedPceServiceServer
}

func NewPce() error {
	s := &Server{}
	// PCEP の Listen を開始する
	go s.pcepListen()
	// gRPC の Listen を開始する
	go s.grpcListen()
	// sessionList の表示
	for {
		s.printSessionList()
		s.printLspList()
		time.Sleep(10 * time.Second)
	}
	return nil
}

func (s *Server) CreateLsp(ctx context.Context, lspData *pb.LspData) (*pb.LspStatus, error) {
	fmt.Printf("[gRPC] get request\n")
	pcepServer := pcep.NewServer()
	pcepSessionAddr := net.IP(lspData.GetPcepSessionAddr())
	for _, pcepSession := range s.pcepSessionList {
		if pcepSession.pcepSessionAddr.Equal(pcepSessionAddr) {
			fmt.Printf("%#v\n", pcepSession)
			if !pcepSession.isSynced {
				break
			}
			pcepServer.SendPCInitiate(pcepSession.tcpConn, lspData)
			return &pb.LspStatus{IsSuccess: true}, nil
		}
	}
	return &pb.LspStatus{IsSuccess: false}, nil
}

func (s *Server) pcepListen() error {
	// PCEP の listen を行う
	// PCEPPORT = "4189" 宛の SYN は全て accept
	var listenInfo strings.Builder
	listenInfo.WriteString(PCEPADDR)
	listenInfo.WriteString(":")
	listenInfo.WriteString(PCEPPORT)
	fmt.Printf("[TCP] Listen: %s\n", listenInfo.String())
	pcepListener, err := net.Listen("tcp", listenInfo.String())
	if err != nil {
		return err
	}

	defer pcepListener.Close()
	for {
		// PCEPPORT = "4189" へ SYN が来るたびに Accept
		pcepSession := &pcepSession{isSynced: false}

		fmt.Printf("%#v\n", s)
		pcepSession.tcpConn, err = pcepListener.Accept()
		if err != nil {
			return err
		}
		fmt.Printf("accept!\n")
		go s.pcepSessionAccept(pcepSession)
	}
}

func (s *Server) pcepSessionAccept(pcepSession *pcepSession) {
	// 各 session の管理はこの部分で行う
	// この関数の終了時に保管された LSP などの情報を削除(pcepSessionClose で)
	// PCEP 用の TCP SYN が送られてきたら accept して sessionList へ保存
	fmt.Printf("[TCP] Accept: %v\n", pcepSession.tcpConn.RemoteAddr())
	strTcpAddr := pcepSession.tcpConn.RemoteAddr().String()
	sessionAddr := net.ParseIP(strings.Split(strTcpAddr, ":")[0])
	pcepSession.pcepSessionAddr = sessionAddr
	s.pcepSessionList = append(s.pcepSessionList, *pcepSession)
	defer s.pcepSessionClose(pcepSession)

	pcepServer := pcep.NewServer()
	// pcep open message を送受信する
	if err := pcepOpen(pcepSession.tcpConn, pcepServer); err != nil {
		fmt.Printf("pcep open error")
		log.Fatal(nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		s.receivePcep(sessionAddr, pcepServer)
		cancel()
	}()
	// 一方的に keepalive を送り続けるスレッド(loop)
	wg.Add(1)
	go func() {
		defer wg.Done()

		pcepKeepalive(ctx, pcepSession.tcpConn, pcepServer)
		fmt.Printf("End keepalive goroutine\n")
	}()
	wg.Wait()
	fmt.Printf("End session with %s\n", pcepSession.pcepSessionAddr.String())
}

func (s *Server) pcepSessionClose(pcepSession *pcepSession) {
	pcepSession.close()
	//ToDo: pcepSessionList から対象の要素を削除
	s.pcepSessionList = removeSession(s.pcepSessionList, *pcepSession)
}

func (s *Server) grpcListen() error {
	port := 50051
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()

	pb.RegisterPceServiceServer(grpcServer, s)
	fmt.Printf("gRPC listen start\n")
	if err := grpcServer.Serve(grpcListener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
	return nil
}

func (s *Server) printSessionList() {
	fmt.Printf("pcepSessionList --------\n")
	fmt.Printf("|\n")
	for _, pcepSession := range s.pcepSessionList {
		fmt.Printf("|  sessionAddr: %s\n", pcepSession.pcepSessionAddr.String())
	}
	fmt.Printf("|\n")
	fmt.Printf("------------------------\n")
}

func (s *Server) printLspList() {
	fmt.Printf("printLspList ************\n")
	fmt.Printf("*\n")
	for _, lsp := range s.lspList {
		fmt.Printf("|- LSP Owner address %s\n", lsp.sessionAddr.String())
		fmt.Printf("|  LSP Name %s\n", lsp.name)
		fmt.Printf("|  PLSP-ID %d\n", lsp.plspId)
		fmt.Printf("|  lspObject %#v\n", lsp.pcrptObject)
	}
	fmt.Printf("*\n")
	fmt.Printf("*************************\n")
}

/* pcep の interactive な動作を行う関数定義*/
func pcepOpen(conn net.Conn, pcepSvr *pcep.Server) error {
	sessionID, err := pcepSvr.ReadOpen(conn)
	if err != nil {
		return err
	}
	if err := pcepSvr.SendOpen(conn, sessionID); err != nil {
		return err
	}
	return nil
}

func (s *Server) receivePcep(sessionAddr net.IP, pcepSvr *pcep.Server) {
	// 経路計算の要求パケットがあったときにこの関数で返している
	// latestSrpId := uint32(1) // 0x00000000 and 0xFFFFFFFF are reserved.
	for true {
		// TODO: msg=にして、message Type, messageLength, reportをまとめる
		// var report *pcep.PcrptObjects
		report := &pcep.PcrptObjects{}
		var pcepSession *pcepSession
		for i := 0; i < len(s.pcepSessionList); i++ {
			if s.pcepSessionList[i].pcepSessionAddr.Equal(sessionAddr) {
				pcepSession = &s.pcepSessionList[i]
			}
		}

		messageType, messageLength := pcepSvr.ReadPcepHeader(pcepSession.tcpConn)
		switch messageType {
		case pcep.MT_KEEPALIVE:
			fmt.Printf("[PCEP] Received KeepAlive\n")
		case pcep.MT_REPORT:
			// PCrpt: PCCが持つlspの情報を送ってくる
			fmt.Printf("[PCEP] Received PCRpt\n")
			pcepSvr.ReadPcrpt(pcepSession.tcpConn, messageLength, report)
			if report.LspObject.PlspId == 0 && !report.LspObject.SFlag {
				//sync 終了
				fmt.Printf(" Finish PCRpt State Synchronization\n")
				pcepSession.isSynced = true
				fmt.Printf(" %#v\n", pcepSession)
				fmt.Printf("Session info: %#v\n", s.pcepSessionList)
			} else if !report.LspObject.SFlag && report.SrpObject.SrpId != 0 {
				// report.LspObject.SFlag == 0 かつ report.LspObject.PlspId != 0 かつ report.SrpObject.SrpId == initiate SRP-ID の場合、
				// PCUpd/PCinitiate に対する応答用 report になる
				// ToDo: report.SrpObject.SrpId != 0 => report.SrpObject.SrpId == initiate SRP-ID に変更する
				fmt.Printf(" Finish Transaction SRP ID: %v\n", report.SrpObject.SrpId)
				// 複数の pcep message が含まれている時?
				lspData := lsp{
					sessionAddr: pcepSession.pcepSessionAddr,
					plspId:      report.LspObject.PlspId,
					name:        report.LspObject.Name,
					pcrptObject: *report,
				}

				s.lspList = removeLsp(s.lspList, lspData)
				s.lspList = append(s.lspList, lspData)
			} else if report.LspObject.SFlag {
				fmt.Printf("  Synchronize LSP information for PLSP-ID: %v\n", report.LspObject.PlspId)
				// 複数の pcep message が含まれている時?
				lspData := lsp{
					sessionAddr: pcepSession.pcepSessionAddr,
					plspId:      report.LspObject.PlspId,
					name:        report.LspObject.Name,
					pcrptObject: *report,
				}

				s.lspList = removeLsp(s.lspList, lspData)
				s.lspList = append(s.lspList, lspData)
			}
			// TODO: elseでsync処理を追加
		case pcep.MT_ERROR:
			fmt.Printf("[PCEP] Received PCErr\n")
			// TODO: エラー内容の表示
		case pcep.MT_CLOSE:
			fmt.Printf("[PCEP] Received Close\n")
			// receive を中断する
			return
		default:
			fmt.Printf("[PCEP] Received Unimplemented Message-Type: %v\n", messageType)
			// TODO: このパケットを記録して捨てる
		}
	}
}

func pcepKeepalive(ctx context.Context, conn net.Conn, pcepSvr *pcep.Server) {
	ticker := time.NewTicker(KEEPALIVE * time.Second)
	defer ticker.Stop()

	if err := pcepSvr.SendKeepAlive(conn); err != nil {
		fmt.Printf("Keepalive error")
		log.Fatal(nil)
	}
	for {
		select {
		case <-ctx.Done():
			// 中断通知が来た
			println("Finish keepAlive goroutine\n")
			return
		case <-ticker.C:
			if err := pcepSvr.SendKeepAlive(conn); err != nil {
				fmt.Printf("Keepalive error")
				log.Fatal(nil)
			}
		}

	}
}

func removeSession(sessionList []pcepSession, e pcepSession) []pcepSession {
	result := []pcepSession{}
	for _, v := range sessionList {
		if !v.pcepSessionAddr.Equal(e.pcepSessionAddr) {
			result = append(result, v)
		}
	}
	return result
}

func removeLsp(lspList []lsp, e lsp) []lsp {
	// lspList から name, PLSP-ID, sessionAddr が一致するものを削除する
	result := []lsp{}
	for _, lsp := range lspList {
		if lsp.name == e.name && lsp.plspId == e.plspId && lsp.sessionAddr.Equal(e.sessionAddr) {
			continue
		}
		result = append(result, lsp)
	}
	return result
}
