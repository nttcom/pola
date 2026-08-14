// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/nttcom/pola/pkg/cspf"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"

	"go.uber.org/zap"
)

const (
	defaultSRPolicyIntentTTL           = 60 * time.Second
	defaultSRPolicyIntentSweepInterval = 10 * time.Second

	// Unrecognized-message rate limit defined by RFC 5440 §6.9.
	defaultMaxUnknownMsgs   = 5
	defaultUnknownMsgWindow = 1 * time.Minute

	pcepErrorTypeCapabilityNotSupported uint8 = 2
	pcepErrorValueUnassigned            uint8 = 0

	// Maximum time to wait for a peer response when Keepalive is unavailable.
	defaultDeadTimer = 120 * time.Second

	// RFC 5440 recommends a DeadTimer of at least 4x the Keepalive interval.
	deadTimerKeepaliveMultiplier = 4
)

// pcepConn abstracts the transport used by Session, allowing tests to inject
// a fake connection.
type pcepConn interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadDeadline(t time.Time) error
}

type Session struct {
	sessionID               uint8
	peerAddr                netip.Addr
	tcpConn                 pcepConn
	sendMu                  sync.Mutex
	stateMu                 sync.RWMutex // guards isSynced and advertisedCapabilities.
	isSynced                bool
	srpIDMu                 sync.Mutex   // guards SRP-ID allocation and intent registration.
	srpIDHead               uint32       // 0x00000000 and 0xFFFFFFFF are reserved.
	srpIDMax                uint32       // upper bound for SRP-ID allocation.
	srPoliciesMu            sync.RWMutex // guards srPolicies.
	srPolicies              []*table.SRPolicy
	srPolicyIntentsMu       sync.Mutex
	srPolicyIntents         map[uint32]srPolicyIntent
	srPolicyIntentTTL       time.Duration
	sweepInterval           time.Duration
	sweepMu                 sync.Mutex
	sweepStop               chan struct{}
	sweepDone               chan struct{}
	unknownMsgMu            sync.Mutex // guards unknownMsgCount and unknownMsgWindowStart.
	unknownMsgCount         uint32
	unknownMsgWindowStart   time.Time
	maxUnknownMsgs          uint32
	unknownMsgWindow        time.Duration
	logger                  *zap.Logger
	keepAlive               uint8
	pccType                 pcep.PccType
	advertisedCapabilities  []pcep.CapabilityInterface // Capabilities Pola advertises to the PCC.
	receivedPccCapabilities []pcep.CapabilityInterface // Capabilities received from the PCC.
	ted                     *table.LsTED
	asn                     uint32
}

// srPolicyIntent stores policy information not reported by PCEP.
type srPolicyIntent struct {
	polType   table.PolicyType
	metric    table.MetricType
	expiresAt time.Time
}

// rememberSRPolicyIntent records the intent for an SRP-ID.
// SRP-ID 0 is reserved for unsolicited PCRpt messages and is ignored.
func (ss *Session) rememberSRPolicyIntent(srpID uint32, polType table.PolicyType, metric table.MetricType) {
	if srpID == 0 {
		return
	}
	ss.srPolicyIntentsMu.Lock()
	defer ss.srPolicyIntentsMu.Unlock()
	if ss.srPolicyIntents == nil {
		ss.srPolicyIntents = make(map[uint32]srPolicyIntent)
	}
	ss.srPolicyIntents[srpID] = srPolicyIntent{polType: polType, metric: metric, expiresAt: time.Now().Add(ss.srPolicyIntentTTL)}
}

func (ss *Session) srPolicyIntentExists(srpID uint32) bool {
	ss.srPolicyIntentsMu.Lock()
	defer ss.srPolicyIntentsMu.Unlock()
	_, ok := ss.srPolicyIntents[srpID]
	return ok
}

// sweepExpiredSRPolicyIntents removes expired intents.
func (ss *Session) sweepExpiredSRPolicyIntents() {
	now := time.Now()
	ss.srPolicyIntentsMu.Lock()
	defer ss.srPolicyIntentsMu.Unlock()
	for srpID, intent := range ss.srPolicyIntents {
		if now.After(intent.expiresAt) {
			delete(ss.srPolicyIntents, srpID)
		}
	}
}

// startIntentSweep starts the intent sweeper. It is idempotent.
func (ss *Session) startIntentSweep() {
	ss.sweepMu.Lock()
	defer ss.sweepMu.Unlock()

	if ss.sweepStop != nil {
		return
	}

	ss.sweepStop = make(chan struct{})
	ss.sweepDone = make(chan struct{})
	go ss.runIntentSweep(ss.sweepStop, ss.sweepDone)
}

func (ss *Session) runIntentSweep(stop, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(ss.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ss.sweepExpiredSRPolicyIntents()
		}
	}
}

func (ss *Session) stopIntentSweep() {
	ss.sweepMu.Lock()
	if ss.sweepStop == nil {
		ss.sweepMu.Unlock()
		return
	}

	stop := ss.sweepStop
	done := ss.sweepDone
	ss.sweepStop = nil
	ss.sweepDone = nil
	ss.sweepMu.Unlock()

	close(stop)
	<-done
}

// takeSRPolicyIntent returns and removes the intent for srpID.
// SRP-ID 0 never consumes an intent.
func (ss *Session) takeSRPolicyIntent(srpID uint32) (srPolicyIntent, bool) {
	if srpID == 0 {
		return srPolicyIntent{}, false
	}
	ss.srPolicyIntentsMu.Lock()
	defer ss.srPolicyIntentsMu.Unlock()
	intent, ok := ss.srPolicyIntents[srpID]
	delete(ss.srPolicyIntents, srpID)
	return intent, ok
}

// forgetSRPolicyIntent discards an intent that will no longer be consumed.
func (ss *Session) forgetSRPolicyIntent(srpID uint32) {
	if srpID == 0 {
		return
	}
	ss.srPolicyIntentsMu.Lock()
	defer ss.srPolicyIntentsMu.Unlock()
	delete(ss.srPolicyIntents, srpID)
}

// clearSRPolicyIntents discards all remembered intents when the session ends.
func (ss *Session) clearSRPolicyIntents() {
	ss.srPolicyIntentsMu.Lock()
	defer ss.srPolicyIntentsMu.Unlock()
	ss.srPolicyIntents = nil
}

func NewSession(sessionID uint8, peerAddr netip.Addr, tcpConn pcepConn, logger *zap.Logger, ted *table.LsTED, asn uint32) *Session {
	return &Session{
		sessionID:         sessionID,
		isSynced:          false,
		srpIDHead:         uint32(1),
		srpIDMax:          math.MaxUint32,
		srPolicyIntentTTL: defaultSRPolicyIntentTTL,
		sweepInterval:     defaultSRPolicyIntentSweepInterval,
		maxUnknownMsgs:    defaultMaxUnknownMsgs,
		unknownMsgWindow:  defaultUnknownMsgWindow,
		logger:            logger.With(zap.String("server", "pcep"), zap.String("session", peerAddr.String())),
		pccType:           pcep.RFCCompliant,
		peerAddr:          peerAddr,
		tcpConn:           tcpConn,
		ted:               ted,
		asn:               asn,
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

	ss.startIntentSweep()
	defer ss.stopIntentSweep()

	done := make(chan struct{}, 1)

	// Receive PCEP messages in a separate goroutine
	go func() {
		if err := ss.ReceivePCEPMessage(); err != nil {
			ss.logger.Debug("ERROR! Receive PCEP Message", zap.Error(err))
		}
		done <- struct{}{}
	}()

	// Keepalive == 0 means no periodic Keepalive is required.
	if ss.keepAlive == 0 {
		<-done
		return
	}

	ticker := time.NewTicker(time.Duration(ss.keepAlive) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := ss.SendKeepalive(); err != nil {
				ss.logger.Debug("ERROR! Send Keepalive Message", zap.Error(err))
				return
			}
		}
	}
}

// sendPCEPMessage serializes and writes a PCEP message.
func (ss *Session) sendPCEPMessage(message pcep.Message) error {
	byteMessage, err := message.Serialize()
	if err != nil {
		return err
	}

	ss.sendMu.Lock()
	defer ss.sendMu.Unlock()

	_, err = ss.tcpConn.Write(byteMessage)
	return err
}

func (ss *Session) Open() error {
	if err := ss.ReceiveOpen(); err != nil {
		return err
	}

	return ss.SendOpen()
}

// readDeadline returns the maximum time a read may block.
// It follows RFC 5440's DeadTimer guidance based on the negotiated Keepalive.
func (ss *Session) readDeadline() time.Duration {
	if ss.keepAlive == 0 {
		return defaultDeadTimer
	}
	return deadTimerKeepaliveMultiplier * time.Duration(ss.keepAlive) * time.Second
}

// readFull reads exactly len(buf) bytes with a read deadline.
func (ss *Session) readFull(buf []uint8) error {
	if err := ss.tcpConn.SetReadDeadline(time.Now().Add(ss.readDeadline())); err != nil {
		return err
	}
	_, err := io.ReadFull(ss.tcpConn, buf)
	return err
}

func (ss *Session) parseOpenMessage() (*pcep.OpenMessage, error) {
	byteOpenHeader := make([]uint8, pcep.CommonHeaderLength)
	if err := ss.readFull(byteOpenHeader); err != nil {
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
	if err := ss.readFull(byteOpenObject); err != nil {
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

	ss.receivedPccCapabilities = slices.Clone(openMessage.OpenObject.Caps)
	ss.setAdvertisedCapabilities(pcep.PolaCapability(openMessage.OpenObject.Caps))

	// pccType detection
	// * FRRouting cannot be detected from the open message, so it is treated as an RFC compliant
	ss.pccType = pcep.DeterminePccType(ss.receivedPccCapabilities)
	ss.logger.Debug("Determine PCC Type", zap.Int("pcc-type", int(ss.pccType)))
	ss.keepAlive = openMessage.OpenObject.Keepalive

	return nil
}

func (ss *Session) SendKeepalive() error {
	keepaliveMessage := pcep.NewKeepaliveMessage()
	ss.logger.Debug("Send Keepalive Message")
	return ss.sendPCEPMessage(keepaliveMessage)
}

func (ss *Session) SendClose(reason pcep.CloseReason) error {
	closeMessage := pcep.NewCloseMessage(reason)

	ss.logger.Debug("Send Close Message",
		zap.Uint8("reason", uint8(closeMessage.CloseObject.Reason)),
		zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))
	return ss.sendPCEPMessage(closeMessage)
}

// SendPCErr sends a PCErr message with the given error type and value.
func (ss *Session) SendPCErr(errorType, errorValue uint8) error {
	pcerrMessage := pcep.NewPCErrMessage(errorType, errorValue, nil)

	ss.logger.Debug("Send PCErr Message",
		zap.Uint8("error-Type", errorType),
		zap.Uint8("error-value", errorValue),
		zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-error-object"))
	return ss.sendPCEPMessage(pcerrMessage)
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
			if err := ss.handlePCRpt(commonHeader.MessageLength); err != nil {
				return err
			}
		case pcep.MessageTypeError:
			if err := ss.receivePCErr(commonHeader.MessageLength); err != nil {
				return err
			}
		case pcep.MessageTypeClose:
			return ss.receiveClose(commonHeader.MessageLength)
		default:
			if err := ss.handleUnsupportedMessage(commonHeader); err != nil {
				return err
			}
		}
	}
}

func (ss *Session) receivePCErr(messageLength uint16) error {
	bytePCErrMessageBody, err := ss.readMessageBody(messageLength)
	if err != nil {
		return err
	}
	pcerrMessage := &pcep.PCErrMessage{}
	if err := pcerrMessage.DecodeFromBytes(bytePCErrMessageBody); err != nil {
		return err
	}
	ss.handlePCErr(pcerrMessage)
	return nil
}

func (ss *Session) receiveClose(messageLength uint16) error {
	byteCloseMessageBody, err := ss.readMessageBody(messageLength)
	if err != nil {
		return err
	}
	closeMessage := &pcep.CloseMessage{}
	if err := closeMessage.DecodeFromBytes(byteCloseMessageBody); err != nil {
		return err
	}
	ss.logger.Debug("Received Close",
		zap.String("reason", closeMessage.CloseObject.Reason.String()),
		zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))
	return nil
}

func (ss *Session) handleUnsupportedMessage(commonHeader *pcep.CommonHeader) error {
	if _, err := ss.readMessageBody(commonHeader.MessageLength); err != nil {
		return err
	}
	ss.logger.Debug("Received unsupported MessageType",
		zap.String("MessageType", commonHeader.MessageType.String()))

	if err := ss.SendPCErr(pcepErrorTypeCapabilityNotSupported, pcepErrorValueUnassigned); err != nil {
		ss.logger.Debug("ERROR! Send PCErr Message", zap.Error(err))
	}

	if ss.recordUnknownMessage() {
		if err := ss.SendClose(pcep.CloseReasonTooManyUnrecognizedPCEPMessages); err != nil {
			ss.logger.Debug("ERROR! Send Close Message", zap.Error(err))
		}
		return fmt.Errorf("too many unrecognized PCEP messages received within %s", ss.unknownMsgWindow)
	}
	return nil
}

func (ss *Session) readCommonHeader() (*pcep.CommonHeader, error) {
	commonHeaderBytes := make([]uint8, pcep.CommonHeaderLength)
	if err := ss.readFull(commonHeaderBytes); err != nil {
		return nil, err
	}

	commonHeader := &pcep.CommonHeader{}
	if err := commonHeader.DecodeFromBytes(commonHeaderBytes); err != nil {
		return nil, err
	}

	return commonHeader, nil
}

// readMessageBody reads the body following the common header.
func (ss *Session) readMessageBody(messageLength uint16) ([]uint8, error) {
	body := make([]uint8, messageLength-pcep.CommonHeaderLength)
	if err := ss.readFull(body); err != nil {
		return nil, err
	}
	return body, nil
}

// recordUnknownMessage counts unrecognized messages and reports whether the
// rate limit has been reached.
func (ss *Session) recordUnknownMessage() bool {
	ss.unknownMsgMu.Lock()
	defer ss.unknownMsgMu.Unlock()

	now := time.Now()
	if now.Sub(ss.unknownMsgWindowStart) > ss.unknownMsgWindow {
		ss.unknownMsgWindowStart = now
		ss.unknownMsgCount = 0
	}
	ss.unknownMsgCount++

	return ss.unknownMsgCount > ss.maxUnknownMsgs
}

// handlePCErr logs the error and forgets intents for the reported SRP-IDs.
func (ss *Session) handlePCErr(pcerrMessage *pcep.PCErrMessage) {
	srpIDs := pcerrMessage.SRPIDs()
	for _, errObj := range pcerrMessage.Errors {
		ss.logger.Debug("Received PCErr",
			zap.Uint8("error-Type", errObj.ErrorType),
			zap.Uint8("error-value", errObj.ErrorValue),
			zap.Uint32s("srp-ids", srpIDs),
			zap.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-error-object"))
	}
	for _, srpID := range srpIDs {
		ss.forgetSRPolicyIntent(srpID)
	}
}

func (ss *Session) handlePCRpt(length uint16) error {
	ss.logger.Debug("Received PCRpt Message")

	messageBodyBytes, err := ss.readMessageBody(length)
	if err != nil {
		return err
	}

	message := pcep.NewPCRptMessage()
	if err := message.DecodeFromBytes(messageBodyBytes); err != nil {
		return err
	}

	for _, sr := range message.StateReports {
		if err := ss.handleStateReport(sr, message); err != nil {
			ss.logger.Warn("Failed to handle state report",
				zap.Uint32("plspID", sr.LSPObject.PlspID), zap.Error(err))
		}
	}

	return nil
}

func (ss *Session) handleStateReport(sr *pcep.StateReport, message *pcep.PCRptMessage) error {
	if sr.LSPObject.SFlag {
		return ss.handleSynchronization(sr, message)
	}

	switch {
	case sr.LSPObject.PlspID == 0:
		ss.handleFinishSynchronization()
		return nil
	case sr.SrpObject.SrpID != 0:
		return ss.handleStatefulPCERequest(sr)
	default:
		return ss.handleSRPolicyWithPLSPID(sr)
	}
}

// Synchronization (S-Flag)
func (ss *Session) handleSynchronization(sr *pcep.StateReport, message *pcep.PCRptMessage) error {
	ss.logger.Debug("Synchronize SR Policy information", zap.Any("Message", message))
	if err := ss.RegisterSRPolicy(*sr); err != nil {
		ss.logger.Error("Failed to register SR Policy during synchronization", zap.Error(err), zap.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}
	return nil
}

// Finish synchronization (PlspID == 0)
func (ss *Session) handleFinishSynchronization() {
	ss.logger.Debug("Finish PCRpt state synchronization")
	ss.setSynced()
}

// IsSynced reports whether the session has finished PCRpt state synchronization.
func (ss *Session) IsSynced() bool {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()
	return ss.isSynced
}

func (ss *Session) setSynced() {
	ss.stateMu.Lock()
	defer ss.stateMu.Unlock()
	ss.isSynced = true
}

// AdvertisedCapabilities returns a snapshot of the capabilities Pola advertises to the PCC.
func (ss *Session) AdvertisedCapabilities() []pcep.CapabilityInterface {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()
	return slices.Clone(ss.advertisedCapabilities)
}

func (ss *Session) setAdvertisedCapabilities(caps []pcep.CapabilityInterface) {
	ss.stateMu.Lock()
	defer ss.stateMu.Unlock()
	ss.advertisedCapabilities = caps
}

// Response to request from PCE (SrpID != 0)
func (ss *Session) handleStatefulPCERequest(sr *pcep.StateReport) error {
	ss.logger.Debug("Finish Stateful PCE request", zap.Uint32("srpID", sr.SrpObject.SrpID))
	if sr.LSPObject.RFlag {
		ss.DeleteSRPolicy(*sr)
	} else if err := ss.RegisterSRPolicy(*sr); err != nil {
		ss.logger.Error("Failed to register SR Policy for Stateful PCE request", zap.Error(err), zap.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}
	return nil
}

// Receive SR Policy with PLSP-ID
func (ss *Session) handleSRPolicyWithPLSPID(sr *pcep.StateReport) error {
	ss.logger.Debug("Received SR Policy", zap.Uint32("plspID", sr.LSPObject.PlspID))

	// Skip path computation for removed SR Policies or when no TED is available.
	if sr.LSPObject.RFlag || ss.ted == nil {
		return ss.handleReportedSRPolicy(sr)
	}

	computedSegmentList, err := ss.computePathFromTED(*sr)
	if err != nil {
		ss.logger.Error("Failed to compute path from TED", zap.Error(err))
		return err
	}
	eroObject, err := createEroFromSegmentList(computedSegmentList)
	if err != nil {
		ss.logger.Error("Failed to create ERO from computed segment list", zap.Error(err))
		return err
	}
	sr.EroObject = eroObject

	if err := ss.RegisterSRPolicy(*sr); err != nil {
		ss.logger.Error("Failed to register SR Policy", zap.Error(err), zap.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		ss.logger.Warn("SR Policy not found after registration", zap.Uint32("plspID", sr.LSPObject.PlspID))
		return fmt.Errorf("SR Policy %d not found after registration", sr.LSPObject.PlspID)
	}

	if err := ss.SendPCUpdate(*policy); err != nil {
		ss.logger.Error("Failed to send PC update", zap.Uint32("plspID", sr.LSPObject.PlspID), zap.Error(err))
		return err
	}
	return nil
}

// Register (or delete) an SR Policy exactly as reported by the PCC
func (ss *Session) handleReportedSRPolicy(sr *pcep.StateReport) error {
	if sr.LSPObject.RFlag {
		ss.DeleteSRPolicy(*sr)
	} else if err := ss.RegisterSRPolicy(*sr); err != nil {
		ss.logger.Error("Failed to register reported SR Policy", zap.Error(err), zap.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}
	return nil
}

func (ss *Session) computePathFromTED(sr pcep.StateReport) ([]table.Segment, error) {
	if ss.ted == nil {
		return nil, errors.New("TED not available")
	}

	srcRouterID, dstRouterID, err := ss.extractSrcDstRouterIDs(sr)
	if err != nil {
		return nil, fmt.Errorf("failed to extract router IDs: %w", err)
	}

	metricType := ss.selectMetricType(sr)

	ss.logger.Debug("Computed CSPF parameters",
		zap.String("srcRouterID", srcRouterID),
		zap.String("dstRouterID", dstRouterID),
		zap.String("metricType", metricType.String()))

	segmentList, err := cspf.CSPF(srcRouterID, dstRouterID, metricType, ss.ted)
	if err != nil {
		return nil, fmt.Errorf("CSPF computation failed: %w", err)
	}

	return segmentList, nil
}

func (ss *Session) extractSrcDstRouterIDs(sr pcep.StateReport) (string, string, error) {
	var srcAddr, dstAddr netip.Addr

	if sr.LSPObject.SrcAddr.IsValid() {
		srcAddr = sr.LSPObject.SrcAddr
	}
	if sr.LSPObject.DstAddr.IsValid() {
		dstAddr = sr.LSPObject.DstAddr
	}

	if !srcAddr.IsValid() || !dstAddr.IsValid() {
		return "", "", errors.New("could not extract valid source and destination addresses")
	}

	addrIndex := buildAddressRouterIDIndex(ss.ted)

	srcRouterID, err := ss.findRouterIDFromAddress(addrIndex, srcAddr)
	if err != nil {
		return "", "", fmt.Errorf("cannot find source router ID for %s: %w", srcAddr, err)
	}

	dstRouterID, err := ss.findRouterIDFromAddress(addrIndex, dstAddr)
	if err != nil {
		return "", "", fmt.Errorf("cannot find destination router ID for %s: %w", dstAddr, err)
	}

	return srcRouterID, dstRouterID, nil
}

func (ss *Session) findRouterIDFromAddress(addrIndex map[netip.Addr]string, addr netip.Addr) (string, error) {
	if node, ok := tedNode(ss.ted, addr.String()); ok {
		return node.RouterID, nil
	}
	if routerID, ok := addrIndex[addr]; ok {
		return routerID, nil
	}
	return "", fmt.Errorf("address %s not found in TED", addr)
}

// selectMetricType maps the PCEP METRIC object's T field to the internal MetricType.
// T=1, 2, and 3 correspond to IGP metric, TE metric, and hop count, respectively.
func (ss *Session) selectMetricType(sr pcep.StateReport) table.MetricType {
	if len(sr.MetricObjects) > 0 {
		switch sr.MetricObjects[0].MetricType {
		case 1:
			return table.IGPMetric
		case 2:
			return table.TEMetric
		case 3:
			return table.HopcountMetric
		default:
			ss.logger.Warn("unsupported METRIC type, falling back to TE", zap.Int("metricType", int(sr.MetricObjects[0].MetricType)))
			return table.TEMetric
		}
	}

	switch ss.pccType {
	case pcep.CiscoLegacy:
		return table.TEMetric
	case pcep.JuniperLegacy:
		return table.IGPMetric
	default:
		return table.TEMetric
	}
}

func createEroFromSegmentList(segmentList []table.Segment) (*pcep.EroObject, error) {
	eroObject := &pcep.EroObject{
		ObjectType:    pcep.ObjectTypeEROExplicitRoute,
		EroSubobjects: make([]pcep.EroSubobject, 0),
	}

	for _, segment := range segmentList {
		switch seg := segment.(type) {
		case table.SegmentSRMPLS:
			subobj, err := pcep.NewSREroSubobject(seg)
			if err != nil {
				return nil, fmt.Errorf("failed to build SR-MPLS ERO subobject: %w", err)
			}
			eroObject.EroSubobjects = append(eroObject.EroSubobjects, subobj)
		case table.SegmentSRv6:
			subobj, err := pcep.NewSRv6EroSubobject(seg)
			if err != nil {
				return nil, fmt.Errorf("failed to build SRv6 ERO subobject: %w", err)
			}
			eroObject.EroSubobjects = append(eroObject.EroSubobjects, subobj)
		}
	}

	return eroObject, nil
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
	openMessage := pcep.NewOpenMessage(ss.sessionID, ss.keepAlive, ss.AdvertisedCapabilities())
	ss.logger.Debug("Send Open Message")
	return ss.sendPCEPMessage(openMessage)
}

// nextUnusedSRPID returns an unused SRP-ID, wrapping at max.
// It returns an error if all non-reserved IDs are in use.
func nextUnusedSRPID(head, max uint32, used func(uint32) bool) (srpID uint32, nextHead uint32, err error) {
	capacity := max - 1 // valid range is [1, max-1]; 0 and max are reserved.
	for attempts := uint32(0); attempts < capacity; attempts++ {
		if head == 0 || head >= max {
			head = 1
		}
		candidate := head
		head++
		if !used(candidate) {
			return candidate, head, nil
		}
	}
	return 0, head, errors.New("no SRP-ID available: all SRP-IDs are in use")
}

// allocateSRPID allocates an unused SRP-ID and records its intent.
// In-use IDs are skipped on wraparound.
func (ss *Session) allocateSRPID(polType table.PolicyType, metric table.MetricType) (uint32, error) {
	ss.srpIDMu.Lock()
	defer ss.srpIDMu.Unlock()

	srpID, nextHead, err := nextUnusedSRPID(ss.srpIDHead, ss.srpIDMax, ss.srPolicyIntentExists)
	if err != nil {
		return 0, err
	}
	ss.srpIDHead = nextHead
	ss.rememberSRPolicyIntent(srpID, polType, metric)
	return srpID, nil
}

func (ss *Session) SendPCInitiate(srPolicy table.SRPolicy, lspDelete bool) error {
	srpID, err := ss.allocateSRPID(srPolicy.Type, srPolicy.Metric)
	if err != nil {
		return err
	}

	pcinitiateMessage, err := pcep.NewPCInitiateMessage(srpID, srPolicy.Name, lspDelete, srPolicy.PlspID, srPolicy.SegmentList, srPolicy.Color, srPolicy.Preference, srPolicy.SrcAddr, srPolicy.DstAddr, pcep.VendorSpecific(ss.pccType), pcep.OriginatorASN(ss.asn))
	if err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return err
	}
	ss.logger.Debug("Send PCInitiate Message")
	if err := ss.sendPCEPMessage(pcinitiateMessage); err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return err
	}
	return nil
}

func (ss *Session) SendPCUpdate(srPolicy table.SRPolicy) error {
	srpID, err := ss.allocateSRPID(srPolicy.Type, srPolicy.Metric)
	if err != nil {
		return err
	}

	pcupdateMessage, err := pcep.NewPCUpdMessage(srpID, srPolicy.Name, srPolicy.PlspID, srPolicy.SegmentList)
	if err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return err
	}
	ss.logger.Debug("Send Update Message")
	if err := ss.sendPCEPMessage(pcupdateMessage); err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return err
	}
	return nil
}

func (ss *Session) RegisterSRPolicy(sr pcep.StateReport) error {
	// Resolve color and preference for this SR Policy
	color, preference := ss.resolveColorPreference(&sr)

	// Determine the policy state based on O-Flag
	state := resolvePolicyState(sr.LSPObject.OFlag)

	// Validate Segment List
	segmentList, err := validateSegmentList(sr)
	if err != nil {
		return err
	}

	// Update existing policy or create a new one
	return ss.updateOrCreatePolicy(sr, segmentList, color, preference, state)
}

// resolveColorPreference returns the color and preference for the SR Policy
func (ss *Session) resolveColorPreference(sr *pcep.StateReport) (uint32, uint32) {
	var color, preference uint32

	if ss.pccType == pcep.CiscoLegacy {
		// Cisco legacy mode: get color and preference from Vendor Information Object
		color = sr.VendorInformationObject.Color()
		preference = sr.VendorInformationObject.Preference()
	} else {
		// Check if PCC supports color capability
		hasColor := false
		for _, cap := range ss.receivedPccCapabilities {
			if c, ok := cap.(*pcep.StatefulPCECapability); ok && c.ColorCapability {
				hasColor = true
				break
			}
		}

		// SR Policy Association color takes precedence
		if c := sr.AssociationObject.Color(); c != 0 {
			color = c
		} else if hasColor {
			color = sr.LSPObject.Color()
		}

		preference = sr.AssociationObject.Preference()
	}

	return color, preference
}

// resolvePolicyState converts O-Flag to internal PolicyState
func resolvePolicyState(oflag uint8) table.PolicyState {
	switch oflag {
	case 0x00:
		return table.PolicyDown
	case 0x01:
		return table.PolicyUp
	case 0x02:
		return table.PolicyActive
	default:
		return table.PolicyUnknown
	}
}

// validateSegmentList checks if the Segment List exists and is non-empty
func validateSegmentList(sr pcep.StateReport) ([]table.Segment, error) {
	if sr.EroObject == nil {
		return nil, fmt.Errorf("EroObject is nil for PlspID %d", sr.LSPObject.PlspID)
	}
	list := sr.EroObject.ToSegmentList()
	if len(list) == 0 {
		return nil, fmt.Errorf("SegmentList is empty for PlspID %d", sr.LSPObject.PlspID)
	}
	return list, nil
}

// updateOrCreatePolicy updates an existing SR Policy or creates a new one
func (ss *Session) updateOrCreatePolicy(sr pcep.StateReport, segmentList []table.Segment, color, preference uint32, state table.PolicyState) error {
	lspID := sr.LSPObject.LSPID

	ss.srPoliciesMu.Lock()
	defer ss.srPoliciesMu.Unlock()

	if p, ok := ss.searchSRPolicyLocked(sr.LSPObject.PlspID); ok {
		// Update existing policy if LSPID is new or equal
		if p.LSPID <= lspID {
			p.Update(table.PolicyDiff{
				Name:        &sr.LSPObject.Name,
				Color:       &color,
				Preference:  &preference,
				SegmentList: segmentList,
				LSPID:       lspID,
				State:       state,
			})
			if intent, ok := ss.takeSRPolicyIntent(sr.SrpObject.SrpID); ok {
				p.Type = intent.polType
				p.Metric = intent.metric
			}
		}
		return nil
	}

	// Create a new SR Policy
	src := sr.LSPObject.SrcAddr
	if !src.IsValid() {
		src = sr.AssociationObject.AssocSrc
	}
	if !src.IsValid() {
		return fmt.Errorf("invalid source address for PlspID %d", sr.LSPObject.PlspID)
	}

	dst := sr.LSPObject.DstAddr
	if !dst.IsValid() {
		dst = sr.AssociationObject.Endpoint()
	}
	if !dst.IsValid() {
		return fmt.Errorf("invalid destination address for PlspID %d", sr.LSPObject.PlspID)
	}

	p := table.NewSRPolicy(sr.LSPObject.PlspID, sr.LSPObject.Name, segmentList, src, dst, color, preference, lspID, state)
	if intent, ok := ss.takeSRPolicyIntent(sr.SrpObject.SrpID); ok {
		p.Type = intent.polType
		p.Metric = intent.metric
	}
	ss.srPolicies = append(ss.srPolicies, p)
	return nil
}

func (ss *Session) DeleteSRPolicy(sr pcep.StateReport) {
	lspID := sr.LSPObject.LSPID

	ss.srPoliciesMu.Lock()
	defer ss.srPoliciesMu.Unlock()

	for i, v := range ss.srPolicies {
		// If the LSP ID is old, it is not the latest data update.
		if v.PlspID == sr.LSPObject.PlspID && v.LSPID <= lspID {
			ss.forgetSRPolicyIntent(sr.SrpObject.SrpID)
			ss.srPolicies[i] = ss.srPolicies[len(ss.srPolicies)-1]
			ss.srPolicies = ss.srPolicies[:len(ss.srPolicies)-1]
			break
		}
	}
}

// searchSRPolicyLocked searches srPolicies without locking.
func (ss *Session) searchSRPolicyLocked(plspID uint32) (*table.SRPolicy, bool) {
	for _, v := range ss.srPolicies {
		if v.PlspID == plspID {
			return v, true
		}
	}
	return nil, false
}

func (ss *Session) SearchSRPolicy(plspID uint32) (*table.SRPolicy, bool) {
	ss.srPoliciesMu.RLock()
	defer ss.srPoliciesMu.RUnlock()
	return ss.searchSRPolicyLocked(plspID)
}

// SearchPlspID returns the PLSP-ID of a registered SR Policy, along with a boolean value indicating if it was found.
func (ss *Session) SearchPlspID(color uint32, endpoint netip.Addr) (uint32, bool) {
	ss.srPoliciesMu.RLock()
	defer ss.srPoliciesMu.RUnlock()
	for _, v := range ss.srPolicies {
		if v.Color == color && v.DstAddr == endpoint {
			return v.PlspID, true
		}
	}
	return 0, false
}

// SRPolicies returns a snapshot of the registered SR Policies.
func (ss *Session) SRPolicies() []*table.SRPolicy {
	ss.srPoliciesMu.RLock()
	defer ss.srPoliciesMu.RUnlock()
	policies := make([]*table.SRPolicy, len(ss.srPolicies))
	for i, p := range ss.srPolicies {
		clone := *p
		clone.SegmentList = slices.Clone(p.SegmentList)
		for j, seg := range clone.SegmentList {
			if srv6, ok := seg.(table.SegmentSRv6); ok {
				srv6.Structure = slices.Clone(srv6.Structure)
				clone.SegmentList[j] = srv6
			}
		}
		policies[i] = &clone
	}
	return policies
}
