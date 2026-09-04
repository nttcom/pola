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
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nttcom/pola/pkg/cspf"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"

	"github.com/nttcom/pola/pkg/logger"
)

const (
	defaultSRPolicyIntentTTL           = 60 * time.Second
	defaultSRPolicyIntentSweepInterval = 10 * time.Second

	// Unrecognized-message rate limit defined by RFC 5440 §6.9.
	defaultMaxUnknownMsgs   = 5
	defaultUnknownMsgWindow = 1 * time.Minute

	// RFC 5440 §6.2: OpenWait and KeepWait have a fixed value of 1 minute.
	openWaitTimer = 1 * time.Minute
	keepWaitTimer = 1 * time.Minute

	// RFC 5440 §7.3 RECOMMENDED Keepalive frequency.
	defaultLocalKeepalive uint8 = 30

	// Keepalive is set below the advertised DeadTimer per RFC 5440 §7.3.
	// The divisor is a Pola safety margin, not an RFC requirement.
	localDeadTimerKeepaliveDivisor = 4
)

// PCEP error codes.
const (
	// Session establishment (RFC 5440 §7.15).
	pcepErrorTypeSessionEstablishmentFailure  uint8 = 1
	pcepErrorValueInvalidOpenMessage          uint8 = 1
	pcepErrorValueOpenWaitTimerExpired        uint8 = 2
	pcepErrorValueUnacceptableNonNegotiable   uint8 = 3
	pcepErrorValueUnacceptableNegotiable      uint8 = 4
	pcepErrorValueSecondOpenStillUnacceptable uint8 = 5
	pcepErrorValueUnacceptableProposal        uint8 = 6
	pcepErrorValueKeepWaitTimerExpired        uint8 = 7
	pcepErrorTypeCapabilityNotSupported       uint8 = 2
	pcepErrorTypeSecondSessionAttempt         uint8 = 9
	pcepErrorValueSecondSessionAttempt        uint8 = 1
	pcepErrorValueUnassigned                  uint8 = 0

	// Reception of an invalid object (RFC 5440 §7.15).
	pcepErrorTypeInvalidObject    uint8 = 10
	pcepErrorValueMalformedObject uint8 = 11

	// Invalid traffic engineering path setup type (RFC 8408 §8.3).
	pcepErrorTypeInvalidPathSetupType     uint8 = 21
	pcepErrorValueMismatchedPathSetupType uint8 = 2

	// Association Error (RFC 8697 §6.4).
	pcepErrorTypeAssociationError             uint8 = 26
	pcepErrorValueAssociationTypeNotSupported uint8 = 1
)

// acceptedAssocTypes lists Association Types accepted from received messages.
// Legacy vendor-specific types are accepted for interoperability but not advertised.
var acceptedAssocTypes = []pcep.AssocType{
	pcep.AssocTypeSRPolicyAssociation,
	pcep.AssocTypeSRPolicyAssociationCisco,
	pcep.AssocTypeSRPolicyAssociationJuniper,
}

// SessionState represents the PCEP session state (RFC 5440 Appendix A).
type SessionState uint8

// Session states, in the order a session progresses through them.
const (
	SessionStateTCPPending SessionState = iota
	SessionStateOpenWait
	SessionStateKeepWait
	SessionStateUp
)

// SyncState is the LSP-DB synchronization state of RFC 8231 §5.6.
type SyncState uint8

// LSP-DB synchronization states.
const (
	SyncStatePending  SyncState = iota // no PCRpt with the S-flag seen yet
	SyncStateOngoing                   // S-flag reports received, end-of-sync pending
	SyncStateFinished                  // PCRpt with PLSP-ID 0 received
)

// SessionInitiator records which side started the TCP connection.
type SessionInitiator uint8

// Session initiators.
const (
	SessionInitiatorRemote SessionInitiator = iota
	SessionInitiatorLocal
)

// sessionStats holds per-session PCEP message counters (RFC 9826).
type sessionStats struct {
	mu             sync.Mutex
	openSent       uint64
	openRcvd       uint64
	keepaliveSent  uint64
	keepaliveRcvd  uint64
	closeSent      uint64
	closeRcvd      uint64
	pcerrSent      uint64
	pcerrRcvd      uint64
	pcntfRcvd      uint64
	pcreqRcvd      uint64
	pcrepRcvd      uint64
	rptRcvd        uint64
	updSent        uint64
	pcinitiateSent uint64
	unknownRcvd    uint64
	corruptRcvd    uint64
}

func (s *sessionStats) inc(counter *uint64) {
	s.mu.Lock()
	*counter++
	s.mu.Unlock()
}

// SessionStats is a snapshot of per-session PCEP message counters (RFC 9826).
type SessionStats struct {
	OpenSent       uint64
	OpenRcvd       uint64
	KeepaliveSent  uint64
	KeepaliveRcvd  uint64
	CloseSent      uint64
	CloseRcvd      uint64
	PCErrSent      uint64
	PCErrRcvd      uint64
	PCNtfRcvd      uint64
	PCReqRcvd      uint64
	PCRepRcvd      uint64
	RptRcvd        uint64
	UpdSent        uint64
	PCInitiateSent uint64
	UnknownRcvd    uint64
	CorruptRcvd    uint64
}

func (s *sessionStats) snapshot() SessionStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	return SessionStats{
		OpenSent:       s.openSent,
		OpenRcvd:       s.openRcvd,
		KeepaliveSent:  s.keepaliveSent,
		KeepaliveRcvd:  s.keepaliveRcvd,
		CloseSent:      s.closeSent,
		CloseRcvd:      s.closeRcvd,
		PCErrSent:      s.pcerrSent,
		PCErrRcvd:      s.pcerrRcvd,
		PCNtfRcvd:      s.pcntfRcvd,
		PCReqRcvd:      s.pcreqRcvd,
		PCRepRcvd:      s.pcrepRcvd,
		RptRcvd:        s.rptRcvd,
		UpdSent:        s.updSent,
		PCInitiateSent: s.pcinitiateSent,
		UnknownRcvd:    s.unknownRcvd,
		CorruptRcvd:    s.corruptRcvd,
	}
}

// OpenParams contains PCEP session parameters advertised in an OPEN object.
type OpenParams struct {
	SessionID uint8
	Keepalive uint8
	DeadTimer uint8
}

// Session represents a PCEP session with a PCC.
type Session struct {
	peerAddr          netip.Addr
	tcpConn           net.Conn
	sendMu            sync.Mutex
	stateMu           sync.RWMutex
	srpIDMu           sync.Mutex
	srpIDHead         uint32
	srpIDMax          uint32
	srPoliciesMu      sync.RWMutex
	srPolicies        []*table.SRPolicy
	srPolicyIntentsMu sync.Mutex
	srPolicyIntents   map[uint32]srPolicyIntent
	srPolicyIntentTTL time.Duration
	sweepInterval     time.Duration
	sweepMu           sync.Mutex
	sweepStop         chan struct{}
	sweepDone         chan struct{}
	unknownMsgMu      sync.Mutex
	unknownMsgTimes   []time.Time
	maxUnknownMsgs    uint32
	unknownMsgWindow  time.Duration
	logger            *logger.Logger
	state             SessionState

	// Session lifetime timestamps.
	createdAt     time.Time
	establishedAt time.Time

	// syncState is the RFC 8231 LSP-DB synchronization state.
	syncState SyncState

	// initiator records which side started the TCP connection.
	initiator SessionInitiator

	stats sessionStats

	// Session establishment timers of RFC 5440 §6.2.
	openWait time.Duration
	keepWait time.Duration

	localSessionID uint8
	localKeepalive uint8
	localDeadTimer uint8

	keepaliveRangeEnabled bool
	minKeepalive          uint8
	maxKeepalive          uint8
	allowNegotiation      bool

	localOpen *OpenParams
	pccOpen   *OpenParams

	pccType                 pcep.PccType
	advertisedCapabilities  []pcep.CapabilityInterface
	receivedPccCapabilities []pcep.CapabilityInterface
	ted                     *table.LsTED
	asn                     uint32

	// onEstablished is called when the session reaches the established state.
	onEstablished func()
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

// NewSession creates a new PCEP session with the given local Open parameters.
func NewSession(localOpen OpenParams, peerAddr netip.Addr, tcpConn net.Conn, lg *logger.Logger, ted *table.LsTED, asn uint32) *Session {
	return &Session{
		localSessionID:         localOpen.SessionID,
		localKeepalive:         localOpen.Keepalive,
		localDeadTimer:         localOpen.DeadTimer,
		openWait:               openWaitTimer,
		keepWait:               keepWaitTimer,
		createdAt:              time.Now(),
		srpIDHead:              uint32(1),
		srpIDMax:               math.MaxUint32,
		srPolicyIntentTTL:      defaultSRPolicyIntentTTL,
		sweepInterval:          defaultSRPolicyIntentSweepInterval,
		maxUnknownMsgs:         defaultMaxUnknownMsgs,
		unknownMsgWindow:       defaultUnknownMsgWindow,
		logger:                 lg.With(logger.String("server", "pcep"), logger.String("session", peerAddr.String())),
		pccType:                pcep.RFCCompliant,
		peerAddr:               peerAddr,
		tcpConn:                tcpConn,
		ted:                    ted,
		asn:                    asn,
		advertisedCapabilities: pcep.DefaultCapabilities(),
	}
}

// Established runs the PCEP session until it terminates.
func (ss *Session) Established() error {
	if err := ss.Open(); err != nil {
		ss.logger.Debug("ERROR! PCEP session establishment failed", logger.Error(err))
		return err
	}

	if ss.onEstablished != nil {
		ss.onEstablished()
	}

	ss.logger.Debug("PCEP session established")

	ss.startIntentSweep()
	defer ss.stopIntentSweep()

	done := make(chan struct{}, 1)

	go func() {
		if err := ss.ReceivePCEPMessage(); err != nil {
			ss.logger.Debug("ERROR! Receive PCEP Message", logger.Error(err))
		}

		done <- struct{}{}
	}()

	interval := ss.keepaliveInterval()
	if interval == 0 {
		<-done
		return nil
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return nil
		case <-ticker.C:
			if err := ss.SendKeepalive(); err != nil {
				ss.logger.Debug("ERROR! Send Keepalive Message", logger.Error(err))
				return nil
			}
		}
	}
}

func (ss *Session) sendPCEPMessage(message pcep.Message) error {
	byteMessage, err := message.Serialize()
	if err != nil {
		return fmt.Errorf("serialize PCEP message: %w", err)
	}

	ss.sendMu.Lock()
	defer ss.sendMu.Unlock()

	if _, err := ss.tcpConn.Write(byteMessage); err != nil {
		return fmt.Errorf("write PCEP message: %w", err)
	}

	return nil
}

// maxLocalOpenRetries limits resends of Pola's Open after adopting a peer's
// proposed session characteristics. A peer that rejects its own proposal
// cannot provide a convergent next negotiation round.
const maxLocalOpenRetries = 1

// openNegotiation tracks the Open negotiation state, including the independent
// RemoteOK and LocalOK conditions (RFC 5440 Appendix A).
type openNegotiation struct {
	remoteOK          bool
	localOK           bool
	peerOpensRejected int
	localOpenRetries  int
	deadline          time.Time
}

type negotiationVars struct {
	remoteOK, localOK                   bool
	peerOpensRejected, localOpenRetries int
}

func (neg *openNegotiation) vars() negotiationVars {
	return negotiationVars{neg.remoteOK, neg.localOK, neg.peerOpensRejected, neg.localOpenRetries}
}

func (neg *openNegotiation) established() bool {
	return neg.remoteOK && neg.localOK
}

// peerOpened reports whether the peer has sent an Open.
func (neg *openNegotiation) peerOpened() bool {
	return neg.remoteOK || neg.peerOpensRejected > 0
}

func (neg *openNegotiation) state() SessionState {
	switch {
	case neg.established():
		return SessionStateUp
	case neg.peerOpened() && !neg.localOK:
		return SessionStateKeepWait
	default:
		return SessionStateOpenWait
	}
}

// Open establishes the PCEP session (RFC 5440 §6.2).
func (ss *Session) Open() error {
	if err := ss.SendOpen(); err != nil {
		return err
	}

	return ss.negotiateOpen(&openNegotiation{})
}

func (ss *Session) negotiateOpen(neg *openNegotiation) error {
	ss.restartInitializationTimer(neg)

	var stopNegotiationKeepalive func()
	defer func() {
		if stopNegotiationKeepalive != nil {
			stopNegotiationKeepalive()
		}
	}()

	for {
		ss.setState(neg.state())

		if neg.established() {
			return nil
		}

		before := neg.vars()

		messageType, body, err := ss.readNegotiationMessage(neg)
		if err != nil {
			return err
		}

		switch messageType {
		case pcep.MessageTypeOpen:
			err = ss.handlePeerOpen(body, neg)
		case pcep.MessageTypeKeepalive:
			if !neg.peerOpened() {
				ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)
				return errors.New("received a Keepalive before the peer's Open message")
			}

			ss.logger.Debug("Received Keepalive acknowledging Pola's Open")

			neg.localOK = true
		case pcep.MessageTypeError:
			if !neg.peerOpened() {
				ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)
				return errors.New("received a PCErr before the peer's Open message")
			}

			err = ss.handleNegotiationPCErr(body, neg)
		default:
			ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)
			return fmt.Errorf("received %s while establishing the PCEP session", messageType)
		}

		if err != nil {
			return err
		}

		ss.applyNegotiationTransition(neg, before, &stopNegotiationKeepalive)
	}
}

// applyNegotiationTransition updates timers and Keepalive state.
func (ss *Session) applyNegotiationTransition(neg *openNegotiation, before negotiationVars, stopNegotiationKeepalive *func()) {
	after := neg.vars()
	if after != before {
		ss.restartInitializationTimer(neg)
	}

	if !before.remoteOK && after.remoteOK && *stopNegotiationKeepalive == nil {
		*stopNegotiationKeepalive = ss.startNegotiationKeepalive()
	}
}

func (ss *Session) restartInitializationTimer(neg *openNegotiation) {
	timer := ss.openWait
	if neg.state() == SessionStateKeepWait {
		timer = ss.keepWait
	}

	neg.deadline = time.Now().Add(timer)
}

// startNegotiationKeepalive sends Keepalives during Open negotiation.
func (ss *Session) startNegotiationKeepalive() func() {
	interval := ss.keepaliveInterval()
	if interval == 0 {
		return func() {}
	}

	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := ss.SendKeepalive(); err != nil {
					ss.logger.Debug("ERROR! Send Keepalive Message during negotiation", logger.Error(err))
					return
				}
			}
		}
	}()

	return func() {
		close(stop)
		<-done
	}
}

// readNegotiationMessage reads one message before the initialization timer expires.
func (ss *Session) readNegotiationMessage(neg *openNegotiation) (pcep.MessageType, []uint8, error) {
	deadline := neg.deadline

	headerBytes := make([]uint8, pcep.CommonHeaderLength)
	if err := ss.readFullWithDeadline(headerBytes, deadline); err != nil {
		if isDeadlineExceeded(err) {
			return 0, nil, ss.negotiationTimerExpired(neg, "without a message from the peer")
		}

		return 0, nil, err
	}

	var commonHeader pcep.CommonHeader
	if err := commonHeader.DecodeFromBytes(headerBytes); err != nil {
		ss.stats.inc(&ss.stats.corruptRcvd)
		ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)

		return 0, nil, err
	}

	ss.countReceived(commonHeader.MessageType)

	body, err := ss.readMessageBody(commonHeader.MessageLength, deadline)
	if err != nil {
		if isDeadlineExceeded(err) {
			return 0, nil, ss.negotiationTimerExpired(neg, "before the message was complete")
		}

		return 0, nil, err
	}

	return commonHeader.MessageType, body, nil
}

// negotiationTimerExpired reports an initialization timer expiration using
// the error value for the current negotiation state.
func (ss *Session) negotiationTimerExpired(neg *openNegotiation, detail string) error {
	timer, errorValue := "OpenWait", pcepErrorValueOpenWaitTimerExpired
	if neg.state() == SessionStateKeepWait {
		timer, errorValue = "KeepWait", pcepErrorValueKeepWaitTimerExpired
	}

	ss.sendPCErrBestEffort(errorValue)

	return fmt.Errorf("%s timer expired %s", timer, detail)
}

// handlePeerOpen processes an Open received during session establishment.
func (ss *Session) handlePeerOpen(body []uint8, neg *openNegotiation) error {
	openMessage := &pcep.OpenMessage{}
	if err := openMessage.DecodeFromBytes(body); err != nil {
		ss.stats.inc(&ss.stats.corruptRcvd)
		ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)

		return err
	}

	if neg.remoteOK {
		ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)

		return fmt.Errorf("received a further Open (Keepalive=%d, DeadTimer=%d) after the peer's Open was already accepted",
			openMessage.OpenObject.Keepalive, openMessage.OpenObject.Deadtime)
	}

	peerOpen, pccType, caps := ss.decodePeerOpen(openMessage)

	if err := ss.rejectOnEmptyPathSetupTypeList(caps); err != nil {
		return err
	}

	// Refuse the session when the peer has no path setup type in common (RFC 8408 §5).
	if err := ss.rejectOnPathSetupTypeMismatch(caps); err != nil {
		return err
	}

	if ss.acceptableOpen(peerOpen) {
		ss.commitPeerOpen(peerOpen, pccType, caps)

		if err := ss.SendKeepalive(); err != nil {
			return err
		}

		neg.remoteOK = true

		return nil
	}

	if neg.peerOpensRejected > 0 {
		ss.sendPCErrBestEffort(pcepErrorValueSecondOpenStillUnacceptable)

		return fmt.Errorf("peer's second Open still advertises unacceptable session characteristics (Keepalive=%d, DeadTimer=%d)",
			peerOpen.Keepalive, peerOpen.DeadTimer)
	}

	if !ss.allowNegotiation {
		ss.sendPCErrBestEffort(pcepErrorValueUnacceptableNonNegotiable)

		return fmt.Errorf("peer's session characteristics (Keepalive=%d, DeadTimer=%d) are unacceptable and non-negotiable",
			peerOpen.Keepalive, peerOpen.DeadTimer)
	}

	if err := ss.proposeAcceptableOpen(peerOpen); err != nil {
		return err
	}

	neg.peerOpensRejected++

	return nil
}

// decodePeerOpen decodes the peer's Open without committing it to session state.
func (ss *Session) decodePeerOpen(openMessage *pcep.OpenMessage) (OpenParams, pcep.PccType, []pcep.CapabilityInterface) {
	receivedCaps := slices.Clone(openMessage.OpenObject.Caps)

	ss.validateCapabilities(receivedCaps)

	pccType := pcep.DeterminePccType(receivedCaps)
	ss.logger.Debug("Determine PCC Type", logger.Int("pcc-type", int(pccType)))

	peerOpen := OpenParams{
		SessionID: openMessage.OpenObject.Sid,
		Keepalive: openMessage.OpenObject.Keepalive,
		DeadTimer: openMessage.OpenObject.Deadtime,
	}
	if peerOpen.Keepalive == 0 && peerOpen.DeadTimer != 0 {
		ss.logger.Warn("peer advertised Keepalive=0 with a nonzero DeadTimer (RFC 5440 §7.3 SHOULD); ignoring the DeadTimer",
			logger.Uint8("deadtimer", peerOpen.DeadTimer))
	}

	return peerOpen, pccType, receivedCaps
}

// commitPeerOpen publishes an accepted peer Open as session state.
func (ss *Session) commitPeerOpen(peerOpen OpenParams, pccType pcep.PccType, caps []pcep.CapabilityInterface) {
	ss.stateMu.Lock()
	ss.receivedPccCapabilities = caps
	ss.pccType = pccType
	ss.pccOpen = &peerOpen
	ss.stateMu.Unlock()
}

// handleNegotiationPCErr processes a PCErr during session establishment.
// Negotiation continues only for Error 1/4.
func (ss *Session) handleNegotiationPCErr(body []uint8, neg *openNegotiation) error {
	pcerrMessage := &pcep.PCErrMessage{}
	if err := pcerrMessage.DecodeFromBytes(body); err != nil {
		ss.stats.inc(&ss.stats.corruptRcvd)
		ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)

		return fmt.Errorf("received malformed PCErr while establishing the PCEP session: %w", err)
	}

	ss.logger.Debug("Received PCErr while establishing the PCEP session",
		logger.String("errors", formatPCErrErrors(pcerrMessage.Errors)))

	// Error 1/4 may be accompanied by unrelated PCEP-ERROR objects.
	negotiable := slices.ContainsFunc(pcerrMessage.Errors, func(errObj *pcep.ErrorObject) bool {
		return errObj.ErrorType == pcepErrorTypeSessionEstablishmentFailure &&
			errObj.ErrorValue == pcepErrorValueUnacceptableNegotiable
	})
	if !negotiable {
		return fmt.Errorf("peer rejected session establishment (%s)", formatPCErrErrors(pcerrMessage.Errors))
	}

	return ss.adoptProposedOpen(pcerrMessage.Open, neg)
}

func formatPCErrErrors(errObjs []*pcep.ErrorObject) string {
	reasons := make([]string, 0, len(errObjs))
	for _, errObj := range errObjs {
		reasons = append(reasons, fmt.Sprintf("error-type=%d, error-value=%d", errObj.ErrorType, errObj.ErrorValue))
	}

	return strings.Join(reasons, "; ")
}

// adoptProposedOpen adopts the peer's proposed session characteristics and
// re-sends Pola's Open.
func (ss *Session) adoptProposedOpen(proposedOpen *pcep.OpenObject, neg *openNegotiation) error {
	if proposedOpen == nil {
		ss.sendPCErrBestEffort(pcepErrorValueUnacceptableProposal)
		return errors.New("peer rejected Pola's session characteristics without proposing acceptable ones")
	}

	proposed := OpenParams{
		SessionID: proposedOpen.Sid,
		Keepalive: proposedOpen.Keepalive,
		DeadTimer: proposedOpen.Deadtime,
	}

	if neg.localOpenRetries >= maxLocalOpenRetries {
		ss.sendPCErrBestEffort(pcepErrorValueUnacceptableProposal)

		return fmt.Errorf("peer rejected Pola's re-sent Open with a further proposal (Keepalive=%d, DeadTimer=%d)",
			proposed.Keepalive, proposed.DeadTimer)
	}

	if !ss.acceptableOpen(proposed) {
		ss.sendPCErrBestEffort(pcepErrorValueUnacceptableProposal)

		return fmt.Errorf("peer proposed unacceptable session characteristics (Keepalive=%d, DeadTimer=%d)",
			proposed.Keepalive, proposed.DeadTimer)
	}

	ss.stateMu.Lock()
	ss.localKeepalive = proposed.Keepalive
	ss.localDeadTimer = proposed.DeadTimer
	ss.stateMu.Unlock()
	ss.logger.Debug("Adopting peer-proposed session characteristics",
		logger.Uint8("keepalive", proposed.Keepalive), logger.Uint8("deadtimer", proposed.DeadTimer))

	if err := ss.SendOpen(); err != nil {
		return err
	}

	neg.localOpenRetries++
	neg.localOK = false

	return nil
}

func (ss *Session) readDeadline() time.Duration {
	pccOpen, ok := ss.PccOpen()
	if !ok || pccOpen.Keepalive == 0 || pccOpen.DeadTimer == 0 {
		return 0
	}

	return time.Duration(pccOpen.DeadTimer) * time.Second
}

func isDeadlineExceeded(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

func (ss *Session) sendPCErrBestEffort(errorValue uint8) {
	ss.sendTypedPCErrBestEffort(pcepErrorTypeSessionEstablishmentFailure, errorValue)
}

func (ss *Session) sendTypedPCErrBestEffort(errorType, errorValue uint8) {
	if err := ss.SendPCErr(errorType, errorValue); err != nil {
		ss.logger.Debug("ERROR! Send PCErr Message", logger.Error(err))
	}
}

// rejectOnEmptyPathSetupTypeList rejects an empty PST list (RFC 8408 §3).
func (ss *Session) rejectOnEmptyPathSetupTypeList(caps []pcep.CapabilityInterface) error {
	pstCap := firstPathSetupTypeCapability(caps)
	if pstCap == nil || len(pstCap.PathSetupTypeList()) > 0 {
		return nil
	}

	ss.sendTypedPCErrBestEffort(pcepErrorTypeInvalidObject, pcepErrorValueMalformedObject)

	return errors.New("peer advertised a PATH-SETUP-TYPE-CAPABILITY with an empty path setup type list")
}

// rejectOnPathSetupTypeMismatch rejects when no PST is shared with the peer (RFC 8408 §5).
// Peers without the capability are accepted for legacy compatibility.
func (ss *Session) rejectOnPathSetupTypeMismatch(caps []pcep.CapabilityInterface) error {
	peerCap := firstPathSetupTypeCapability(caps)
	localCap := firstPathSetupTypeCapability(ss.AdvertisedCapabilities())

	if peerCap == nil || localCap == nil {
		return nil
	}

	peerPSTs, localPSTs := peerCap.PathSetupTypeList(), localCap.PathSetupTypeList()
	if slices.ContainsFunc(localPSTs, func(pst pcep.Pst) bool { return slices.Contains(peerPSTs, pst) }) {
		return nil
	}

	ss.sendTypedPCErrBestEffort(pcepErrorTypeInvalidPathSetupType, pcepErrorValueMismatchedPathSetupType)

	return fmt.Errorf("peer advertised no path setup type in common with Pola (peer: %v, Pola: %v)", peerPSTs, localPSTs)
}

// validateCapabilities validates peer capabilities and logs known RFC deviations.
func (ss *Session) validateCapabilities(caps []pcep.CapabilityInterface) {
	var hasSRCapability, hasSRv6Capability bool

	for _, capability := range pcep.FlattenCapabilities(caps) {
		switch c := capability.(type) {
		case *pcep.SRPCECapability:
			hasSRCapability = true

			if c.HasInvalidZeroMSD() {
				ss.logger.Warn("peer advertised SR-PCE-CAPABILITY with X=0 and MSD=0 (RFC 8664 §5.1); tolerating as a known deployed-peer deviation")
			}
		case *pcep.SRv6PCECapability:
			hasSRv6Capability = true
		}
	}

	for _, capability := range caps {
		pst, ok := capability.(*pcep.PathSetupTypeCapability)
		if !ok {
			continue
		}

		if pst.HasPathSetupType(pcep.PathSetupTypeSRTE) && !hasSRCapability {
			ss.logger.Warn("peer advertised PST=1 (SR-TE) without an SR-PCE-CAPABILITY sub-TLV (RFC 8664 §4.1.2)")
		}

		if pst.HasPathSetupType(pcep.PathSetupTypeSRv6TE) && !hasSRv6Capability {
			ss.logger.Warn("peer advertised PST=3 (SRv6-TE) without an SRv6-PCE-CAPABILITY sub-TLV (RFC 9603 §4.1.1)")
		}
	}
}

func (ss *Session) readFullWithDeadline(buf []uint8, deadline time.Time) error {
	if err := ss.tcpConn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}

	if _, err := io.ReadFull(ss.tcpConn, buf); err != nil {
		return fmt.Errorf("read PCEP message: %w", err)
	}

	return nil
}

func (ss *Session) messageDeadline() time.Time {
	var deadline time.Time
	if d := ss.readDeadline(); d > 0 {
		deadline = time.Now().Add(d)
	}

	return deadline
}

// validTimerRelationship reports whether Keepalive and DeadTimer are valid.
// DeadTimer is ignored when Keepalive is 0 (RFC 5440 §7.3); otherwise it
// must exceed Keepalive (§6.3).
func validTimerRelationship(open OpenParams) bool {
	if open.Keepalive == 0 {
		return true
	}

	return open.DeadTimer == 0 || open.DeadTimer > open.Keepalive
}

func (ss *Session) acceptableOpen(peerOpen OpenParams) bool {
	if !validTimerRelationship(peerOpen) {
		return false
	}

	if !ss.keepaliveRangeEnabled {
		return true
	}

	return peerOpen.Keepalive >= ss.minKeepalive && peerOpen.Keepalive <= ss.maxKeepalive
}

func (ss *Session) proposedTimers(peerOpen OpenParams) (keepalive, deadTimer uint8) {
	keepalive = peerOpen.Keepalive

	if ss.keepaliveRangeEnabled {
		switch {
		case keepalive < ss.minKeepalive:
			keepalive = ss.minKeepalive
		case keepalive > ss.maxKeepalive:
			keepalive = ss.maxKeepalive
		}
	}

	deadTimer = pcep.DeadTimerFor(keepalive)
	if deadTimer <= keepalive {
		// No 8-bit DeadTimer exceeds keepalive (e.g. keepalive=255), so use 0.
		deadTimer = 0
	}

	return keepalive, deadTimer
}

func (ss *Session) proposeAcceptableOpen(peerOpen OpenParams) error {
	keepalive, deadTimer := ss.proposedTimers(peerOpen)
	openObject := pcep.NewOpenObject(peerOpen.SessionID, keepalive, deadTimer, nil)

	pcerrMessage := pcep.NewPCErrMessageWithOpen(pcepErrorTypeSessionEstablishmentFailure, pcepErrorValueUnacceptableNegotiable, openObject)
	ss.logger.Debug("Send PCErr Message proposing session characteristics",
		logger.Uint8("error-Type", pcepErrorTypeSessionEstablishmentFailure),
		logger.Uint8("error-value", pcepErrorValueUnacceptableNegotiable),
		logger.Uint8("proposed-keepalive", keepalive),
		logger.Uint8("proposed-deadtimer", deadTimer))

	if err := ss.sendPCEPMessage(pcerrMessage); err != nil {
		return err
	}

	ss.stats.inc(&ss.stats.pcerrSent)

	return nil
}

// SendKeepalive sends a PCEP Keepalive message to the peer.
func (ss *Session) SendKeepalive() error {
	keepaliveMessage := pcep.NewKeepaliveMessage()

	ss.logger.Debug("Send Keepalive Message")

	if err := ss.sendPCEPMessage(keepaliveMessage); err != nil {
		return err
	}

	ss.stats.inc(&ss.stats.keepaliveSent)

	return nil
}

// SendClose sends a PCEP Close message with the given reason.
func (ss *Session) SendClose(reason pcep.CloseReason) error {
	closeMessage := pcep.NewCloseMessage(reason)

	ss.logger.Debug("Send Close Message",
		logger.Uint8("reason", uint8(closeMessage.CloseObject.Reason)),
		logger.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))

	if err := ss.sendPCEPMessage(closeMessage); err != nil {
		return err
	}

	ss.stats.inc(&ss.stats.closeSent)

	return nil
}

// SendPCErr sends a PCEP Error message carrying the given Error-Type and Error-value.
func (ss *Session) SendPCErr(errorType, errorValue uint8) error {
	pcerrMessage := pcep.NewPCErrMessage(errorType, errorValue, nil)

	ss.logger.Debug("Send PCErr Message",
		logger.Uint8("error-Type", errorType),
		logger.Uint8("error-value", errorValue),
		logger.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-error-object"))

	if err := ss.sendPCEPMessage(pcerrMessage); err != nil {
		return err
	}

	ss.stats.inc(&ss.stats.pcerrSent)

	return nil
}

// ReceivePCEPMessage reads and dispatches PCEP messages until the session ends.
func (ss *Session) ReceivePCEPMessage() error {
	for {
		done, err := ss.receiveOnePCEPMessage()
		if err != nil {
			if isDeadlineExceeded(err) {
				// DeadTimer expiry terminates the session (RFC 5440 §6.8).
				if closeErr := ss.SendClose(pcep.CloseReasonDeadTimerExpired); closeErr != nil {
					ss.logger.Debug("ERROR! Send Close Message", logger.Error(closeErr))
				}
			}

			return err
		}

		if done {
			return nil
		}
	}
}

func (ss *Session) receiveOnePCEPMessage() (done bool, err error) {
	deadline := ss.messageDeadline()

	commonHeader, err := ss.readCommonHeader(deadline)
	if err != nil {
		return false, err
	}

	ss.countReceived(commonHeader.MessageType)

	switch commonHeader.MessageType {
	case pcep.MessageTypeKeepalive:
		ss.logger.Debug("Received Keepalive")
	case pcep.MessageTypeReport:
		if err := ss.handlePCRpt(commonHeader.MessageLength, deadline); err != nil {
			return false, err
		}
	case pcep.MessageTypeError:
		if err := ss.receivePCErr(commonHeader.MessageLength, deadline); err != nil {
			return false, err
		}
	case pcep.MessageTypeClose:
		return true, ss.receiveClose(commonHeader.MessageLength, deadline)
	case pcep.MessageTypeOpen:
		if err := ss.handleUnexpectedOpen(commonHeader.MessageLength, deadline); err != nil {
			return false, err
		}
	case pcep.MessageTypeNotification:
		if _, err := ss.readMessageBody(commonHeader.MessageLength, deadline); err != nil {
			return false, err
		}

		ss.logger.Debug("Received Notification")
	default:
		if err := ss.handleUnsupportedMessage(commonHeader, deadline); err != nil {
			return false, err
		}
	}

	return false, nil
}

// countReceived updates the RFC 9826 receive counter for a message type.
func (ss *Session) countReceived(mt pcep.MessageType) {
	switch mt {
	case pcep.MessageTypeOpen:
		ss.stats.inc(&ss.stats.openRcvd)
	case pcep.MessageTypeKeepalive:
		ss.stats.inc(&ss.stats.keepaliveRcvd)
	case pcep.MessageTypeReport:
		ss.stats.inc(&ss.stats.rptRcvd)
	case pcep.MessageTypeError:
		ss.stats.inc(&ss.stats.pcerrRcvd)
	case pcep.MessageTypeNotification:
		ss.stats.inc(&ss.stats.pcntfRcvd)
	case pcep.MessageTypeClose:
		ss.stats.inc(&ss.stats.closeRcvd)
	case pcep.MessageTypePcreq:
		ss.stats.inc(&ss.stats.pcreqRcvd)
	case pcep.MessageTypePcrep:
		ss.stats.inc(&ss.stats.pcrepRcvd)
	default:
		ss.stats.inc(&ss.stats.unknownRcvd)
	}
}

func (ss *Session) receivePCErr(messageLength uint16, deadline time.Time) error {
	bytePCErrMessageBody, err := ss.readMessageBody(messageLength, deadline)
	if err != nil {
		return err
	}

	pcerrMessage := &pcep.PCErrMessage{}
	if err := pcerrMessage.DecodeFromBytes(bytePCErrMessageBody); err != nil {
		ss.stats.inc(&ss.stats.corruptRcvd)
		return err
	}

	ss.handlePCErr(pcerrMessage)

	return nil
}

func (ss *Session) receiveClose(messageLength uint16, deadline time.Time) error {
	byteCloseMessageBody, err := ss.readMessageBody(messageLength, deadline)
	if err != nil {
		return err
	}

	closeMessage := &pcep.CloseMessage{}
	if err := closeMessage.DecodeFromBytes(byteCloseMessageBody); err != nil {
		ss.stats.inc(&ss.stats.corruptRcvd)
		return err
	}

	ss.logger.Debug("Received Close",
		logger.String("reason", closeMessage.CloseObject.Reason.String()),
		logger.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#close-object-reason-field"))

	return nil
}

// handleUnexpectedOpen rejects Open received in the Up state, which is not
// defined as an event by RFC 5440 Appendix A.
func (ss *Session) handleUnexpectedOpen(messageLength uint16, deadline time.Time) error {
	if _, err := ss.readMessageBody(messageLength, deadline); err != nil {
		return err
	}

	ss.logger.Debug("Received Open message while session is already Up")
	ss.sendPCErrBestEffort(pcepErrorValueInvalidOpenMessage)

	return nil
}

func (ss *Session) handleUnsupportedMessage(commonHeader *pcep.CommonHeader, deadline time.Time) error {
	if _, err := ss.readMessageBody(commonHeader.MessageLength, deadline); err != nil {
		return err
	}

	ss.logger.Debug("Received unsupported MessageType",
		logger.String("MessageType", commonHeader.MessageType.String()))

	if err := ss.SendPCErr(pcepErrorTypeCapabilityNotSupported, pcepErrorValueUnassigned); err != nil {
		ss.logger.Debug("ERROR! Send PCErr Message", logger.Error(err))
	}

	if ss.recordUnknownMessage() {
		if err := ss.SendClose(pcep.CloseReasonTooManyUnrecognizedPCEPMessages); err != nil {
			ss.logger.Debug("ERROR! Send Close Message", logger.Error(err))
		}

		return fmt.Errorf("too many unrecognized PCEP messages received within %s", ss.unknownMsgWindow)
	}

	return nil
}

func (ss *Session) readCommonHeader(deadline time.Time) (*pcep.CommonHeader, error) {
	commonHeaderBytes := make([]uint8, pcep.CommonHeaderLength)
	if err := ss.readFullWithDeadline(commonHeaderBytes, deadline); err != nil {
		return nil, err
	}

	commonHeader := &pcep.CommonHeader{}
	if err := commonHeader.DecodeFromBytes(commonHeaderBytes); err != nil {
		ss.stats.inc(&ss.stats.corruptRcvd)
		return nil, err
	}

	return commonHeader, nil
}

func (ss *Session) readMessageBody(messageLength uint16, deadline time.Time) ([]uint8, error) {
	body := make([]uint8, messageLength-pcep.CommonHeaderLength)
	if err := ss.readFullWithDeadline(body, deadline); err != nil {
		return nil, err
	}

	return body, nil
}

// recordUnknownMessage records an unrecognized message and reports whether
// the rate limit has been exceeded within unknownMsgWindow.
func (ss *Session) recordUnknownMessage() bool {
	ss.unknownMsgMu.Lock()
	defer ss.unknownMsgMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-ss.unknownMsgWindow)
	ss.unknownMsgTimes = slices.DeleteFunc(ss.unknownMsgTimes, func(t time.Time) bool {
		return !t.After(cutoff)
	})
	ss.unknownMsgTimes = append(ss.unknownMsgTimes, now)

	count := len(ss.unknownMsgTimes)
	if count > math.MaxUint32 {
		return true
	}

	return uint32(count) > ss.maxUnknownMsgs
}

func (ss *Session) handlePCErr(pcerrMessage *pcep.PCErrMessage) {
	srpIDs := pcerrMessage.SRPIDs()
	for _, errObj := range pcerrMessage.Errors {
		ss.logger.Debug("Received PCErr",
			logger.Uint8("error-Type", errObj.ErrorType),
			logger.Uint8("error-value", errObj.ErrorValue),
			logger.Uint32s("srp-ids", srpIDs),
			logger.String("detail", "See https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-error-object"))
	}

	for _, srpID := range srpIDs {
		ss.forgetSRPolicyIntent(srpID)
	}
}

func (ss *Session) handlePCRpt(length uint16, deadline time.Time) error {
	ss.logger.Debug("Received PCRpt Message")

	messageBodyBytes, err := ss.readMessageBody(length, deadline)
	if err != nil {
		return err
	}

	message := pcep.NewPCRptMessage()
	if err := message.DecodeFromBytes(messageBodyBytes); err != nil {
		ss.stats.inc(&ss.stats.corruptRcvd)
		return err
	}

	for _, sr := range message.StateReports {
		if err := ss.handleStateReport(sr, message); err != nil {
			ss.logger.Warn("Failed to handle state report",
				logger.Uint32("plspID", sr.LSPObject.PlspID), logger.Error(err))
		}
	}

	return nil
}

func (ss *Session) handleStateReport(sr *pcep.StateReport, message *pcep.PCRptMessage) error {
	if err := ss.rejectUnsupportedAssocTypes(sr.AssociationObjects); err != nil {
		return err
	}

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

// rejectUnsupportedAssocTypes reports unsupported ASSOCIATION types.
func (ss *Session) rejectUnsupportedAssocTypes(assocs []*pcep.AssociationObject) error {
	for _, assoc := range assocs {
		if assoc == nil || slices.Contains(acceptedAssocTypes, assoc.AssocType) {
			continue
		}

		ss.logger.Warn("Received unsupported ASSOCIATION type",
			logger.String("assocType", assoc.AssocType.StringWithReference()))

		if err := ss.SendPCErr(pcepErrorTypeAssociationError, pcepErrorValueAssociationTypeNotSupported); err != nil {
			return fmt.Errorf("failed to send PCErr for unsupported ASSOCIATION type: %w", err)
		}
	}

	return nil
}

// srPolicyAssociation returns the first accepted ASSOCIATION object.
func srPolicyAssociation(sr *pcep.StateReport) *pcep.AssociationObject {
	for _, assoc := range sr.AssociationObjects {
		if assoc != nil && slices.Contains(acceptedAssocTypes, assoc.AssocType) {
			return assoc
		}
	}

	return nil
}

func (ss *Session) handleSynchronization(sr *pcep.StateReport, message *pcep.PCRptMessage) error {
	ss.setSyncState(SyncStateOngoing)
	ss.logger.Debug("Synchronize SR Policy information", logger.Any("Message", message))

	if err := ss.RegisterSRPolicy(sr); err != nil {
		ss.logger.Error("Failed to register SR Policy during synchronization", logger.Error(err), logger.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}

	return nil
}

func (ss *Session) handleFinishSynchronization() {
	ss.logger.Debug("Finish PCRpt state synchronization")
	ss.setSynced()
}

// IsSynced reports whether the session has finished PCRpt state synchronization.
func (ss *Session) IsSynced() bool {
	return ss.SyncState() == SyncStateFinished
}

func (ss *Session) setSynced() {
	ss.stateMu.Lock()
	defer ss.stateMu.Unlock()

	ss.syncState = SyncStateFinished
}

// State returns the PCEP session state defined by RFC 5440 Appendix A.
func (ss *Session) State() SessionState {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return ss.state
}

func (ss *Session) setState(state SessionState) {
	ss.stateMu.Lock()
	defer ss.stateMu.Unlock()

	ss.state = state
	if state == SessionStateUp && ss.establishedAt.IsZero() {
		ss.establishedAt = time.Now()
	}
}

// CreatedAt returns when the TCP connection was accepted.
func (ss *Session) CreatedAt() time.Time {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return ss.createdAt
}

// EstablishedAt returns when the session reached the Up state.
// It returns the zero time if the session is not established.
func (ss *Session) EstablishedAt() time.Time {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return ss.establishedAt
}

// Initiator returns which side started the TCP connection.
func (ss *Session) Initiator() SessionInitiator {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return ss.initiator
}

// SyncState returns the RFC 8231 LSP-DB synchronization state.
func (ss *Session) SyncState() SyncState {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return ss.syncState
}

func (ss *Session) setSyncState(state SyncState) {
	ss.stateMu.Lock()
	defer ss.stateMu.Unlock()

	if ss.syncState == SyncStateFinished {
		return
	}

	ss.syncState = state
}

// Stats returns a snapshot of the session's RFC 9826 message counters.
func (ss *Session) Stats() SessionStats {
	return ss.stats.snapshot()
}

// Up reports whether the PCEP session is up.
func (ss *Session) Up() bool {
	return ss.State() == SessionStateUp
}

// PccType returns the PCC implementation type detected from the Open handshake.
func (ss *Session) PccType() pcep.PccType {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return ss.pccType
}

// LocalOpen returns the session characteristics Pola advertised.
func (ss *Session) LocalOpen() (OpenParams, bool) {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	if ss.localOpen == nil {
		return OpenParams{}, false
	}

	return *ss.localOpen, true
}

// PccOpen returns the session characteristics the PCC advertised.
func (ss *Session) PccOpen() (OpenParams, bool) {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	if ss.pccOpen == nil {
		return OpenParams{}, false
	}

	return *ss.pccOpen, true
}

func (ss *Session) keepaliveInterval() uint8 {
	localOpen, ok := ss.LocalOpen()
	if !ok {
		return 0
	}

	return effectiveKeepalive(localOpen.Keepalive, localOpen.DeadTimer)
}

// effectiveKeepalive returns the Keepalive interval Pola uses, limited by
// Pola's advertised DeadTimer.
func effectiveKeepalive(localKeepalive, localDeadTimer uint8) uint8 {
	if localKeepalive == 0 || localDeadTimer == 0 {
		return localKeepalive
	}

	limit := localDeadTimer / localDeadTimerKeepaliveDivisor
	if limit == 0 {
		// RFC 5440 §4.2.2: the minimum Keepalive timer value is 1 second.
		limit = 1
	}

	return min(localKeepalive, limit)
}

// sessionSnapshot is a consistent view of session state.
type sessionSnapshot struct {
	state                   SessionState
	pccType                 pcep.PccType
	localOpen               *OpenParams
	pccOpen                 *OpenParams
	initiator               SessionInitiator
	syncState               SyncState
	createdAt               time.Time
	establishedAt           time.Time
	advertisedCapabilities  []pcep.CapabilityInterface
	receivedPccCapabilities []pcep.CapabilityInterface
}

func (ss *Session) snapshot() sessionSnapshot {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return sessionSnapshot{
		state:                   ss.state,
		pccType:                 ss.pccType,
		localOpen:               ss.localOpen,
		pccOpen:                 ss.pccOpen,
		initiator:               ss.initiator,
		syncState:               ss.syncState,
		createdAt:               ss.createdAt,
		establishedAt:           ss.establishedAt,
		advertisedCapabilities:  slices.Clone(ss.advertisedCapabilities),
		receivedPccCapabilities: slices.Clone(ss.receivedPccCapabilities),
	}
}

// keepaliveInterval returns Pola's effective Keepalive interval.
func (snap sessionSnapshot) keepaliveInterval() uint8 {
	if snap.localOpen == nil {
		return 0
	}

	return effectiveKeepalive(snap.localOpen.Keepalive, snap.localOpen.DeadTimer)
}

// readDeadline returns the deadline derived from the peer's DeadTimer.
func (snap sessionSnapshot) readDeadline() time.Duration {
	if snap.pccOpen == nil || snap.pccOpen.Keepalive == 0 || snap.pccOpen.DeadTimer == 0 {
		return 0
	}

	return time.Duration(snap.pccOpen.DeadTimer) * time.Second
}

// ReceivedCapabilities returns a snapshot of the capabilities advertised by the PCC.
func (ss *Session) ReceivedCapabilities() []pcep.CapabilityInterface {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return slices.Clone(ss.receivedPccCapabilities)
}

// AdvertisedCapabilities returns a snapshot of the capabilities Pola advertises to the PCC.
func (ss *Session) AdvertisedCapabilities() []pcep.CapabilityInterface {
	ss.stateMu.RLock()
	defer ss.stateMu.RUnlock()

	return slices.Clone(ss.advertisedCapabilities)
}

// Response to request from PCE (SrpID != 0).
func (ss *Session) handleStatefulPCERequest(sr *pcep.StateReport) error {
	ss.logger.Debug("Finish Stateful PCE request", logger.Uint32("srpID", sr.SrpObject.SrpID))

	if sr.LSPObject.RFlag {
		ss.DeleteSRPolicy(sr)
	} else if err := ss.RegisterSRPolicy(sr); err != nil {
		ss.logger.Error("Failed to register SR Policy for Stateful PCE request", logger.Error(err), logger.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}

	return nil
}

// Receive SR Policy with PLSP-ID.
func (ss *Session) handleSRPolicyWithPLSPID(sr *pcep.StateReport) error {
	ss.logger.Debug("Received SR Policy", logger.Uint32("plspID", sr.LSPObject.PlspID))

	// Skip path computation for removed SR Policies or when no TED is available.
	if sr.LSPObject.RFlag || ss.ted == nil {
		return ss.handleReportedSRPolicy(sr)
	}

	computedSegmentList, err := ss.computePathFromTED(sr)
	if err != nil {
		ss.logger.Error("Failed to compute path from TED", logger.Error(err))
		return err
	}

	eroObject, err := createEroFromSegmentList(computedSegmentList)
	if err != nil {
		ss.logger.Error("Failed to create ERO from computed segment list", logger.Error(err))
		return err
	}

	sr.EroObject = eroObject

	if err := ss.RegisterSRPolicy(sr); err != nil {
		ss.logger.Error("Failed to register SR Policy", logger.Error(err), logger.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		ss.logger.Warn("SR Policy not found after registration", logger.Uint32("plspID", sr.LSPObject.PlspID))
		return fmt.Errorf("SR Policy %d not found after registration", sr.LSPObject.PlspID)
	}

	if err := ss.SendPCUpdate(*policy); err != nil {
		ss.logger.Error("Failed to send PC update", logger.Uint32("plspID", sr.LSPObject.PlspID), logger.Error(err))
		return err
	}

	return nil
}

// Register (or delete) an SR Policy exactly as reported by the PCC.
func (ss *Session) handleReportedSRPolicy(sr *pcep.StateReport) error {
	if sr.LSPObject.RFlag {
		ss.DeleteSRPolicy(sr)
	} else if err := ss.RegisterSRPolicy(sr); err != nil {
		ss.logger.Error("Failed to register reported SR Policy", logger.Error(err), logger.Uint32("plspID", sr.LSPObject.PlspID))
		return err
	}

	return nil
}

func (ss *Session) computePathFromTED(sr *pcep.StateReport) ([]table.Segment, error) {
	if ss.ted == nil {
		return nil, errors.New("TED not available")
	}

	srcRouterID, dstRouterID, err := ss.extractSrcDstRouterIDs(sr)
	if err != nil {
		return nil, fmt.Errorf("failed to extract router IDs: %w", err)
	}

	metricType := ss.selectMetricType(sr)

	ss.logger.Debug("Computed CSPF parameters",
		logger.String("srcRouterID", srcRouterID),
		logger.String("dstRouterID", dstRouterID),
		logger.String("metricType", metricType.String()))

	segmentList, err := cspf.CSPF(srcRouterID, dstRouterID, metricType, ss.ted)
	if err != nil {
		return nil, fmt.Errorf("CSPF computation failed: %w", err)
	}

	return segmentList, nil
}

func (ss *Session) extractSrcDstRouterIDs(sr *pcep.StateReport) (srcRouterID, dstRouterID string, err error) {
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

	addrIndex := ss.ted.AddressRouterIDIndex()

	srcRouterID, err = ss.findRouterIDFromAddress(addrIndex, srcAddr)
	if err != nil {
		return "", "", fmt.Errorf("cannot find source router ID for %s: %w", srcAddr, err)
	}

	dstRouterID, err = ss.findRouterIDFromAddress(addrIndex, dstAddr)
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
func (ss *Session) selectMetricType(sr *pcep.StateReport) table.MetricType {
	if len(sr.MetricObjects) > 0 {
		switch sr.MetricObjects[0].MetricType {
		case 1:
			return table.IGPMetric
		case 2:
			return table.TEMetric
		case 3:
			return table.HopcountMetric
		default:
			ss.logger.Warn("unsupported METRIC type, falling back to TE", logger.Int("metricType", int(sr.MetricObjects[0].MetricType)))
			return table.TEMetric
		}
	}

	// Only Juniper legacy PCCs default to IGP metric; Cisco legacy and
	// RFC-compliant PCCs both default to TE metric.
	if ss.pccType == pcep.JuniperLegacy {
		return table.IGPMetric
	}

	return table.TEMetric
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

type sidDepthCapability interface {
	MaxSIDs() (maxSIDs uint8, ok bool)
}

// firstSIDDepthCapability returns the first matching capability.
// Later capabilities are ignored per RFC 8664 §5.1 and RFC 9603 §5.1.
func firstSIDDepthCapability(caps []pcep.CapabilityInterface, pst pcep.Pst) sidDepthCapability {
	for _, capability := range caps {
		switch c := capability.(type) {
		case *pcep.SRPCECapability:
			if pst == pcep.PathSetupTypeSRTE {
				return c
			}
		case *pcep.SRv6PCECapability:
			if pst == pcep.PathSetupTypeSRv6TE {
				return c
			}
		}
	}

	return nil
}

// firstPathSetupTypeCapability returns the first PATH-SETUP-TYPE-CAPABILITY.
// Later instances are ignored per RFC 8408 §3.
func firstPathSetupTypeCapability(caps []pcep.CapabilityInterface) *pcep.PathSetupTypeCapability {
	for _, capability := range caps {
		if pstCap, ok := capability.(*pcep.PathSetupTypeCapability); ok {
			return pstCap
		}
	}

	return nil
}

// peerSupportsPST reports whether the peer supports the given path setup type.
// PATH-SETUP-TYPE-CAPABILITY is authoritative (RFC 8408 §5); otherwise,
// legacy SR-CAPABILITY-TLV implies PSTs 0 and 1 (RFC 8664 Appendix A), and
// no PST information is treated as permissive for legacy compatibility.
func peerSupportsPST(caps []pcep.CapabilityInterface, pst pcep.Pst) bool {
	if pstCap := firstPathSetupTypeCapability(caps); pstCap != nil {
		return pstCap.HasPathSetupType(pst)
	}

	if firstSIDDepthCapability(caps, pcep.PathSetupTypeSRTE) != nil {
		return pst == pcep.PathSetupTypeRSVPTE || pst == pcep.PathSetupTypeSRTE
	}

	return true
}

// peerMaxSIDs returns the advertised SID depth for the given path setup type.
// PATH-SETUP-TYPE-CAPABILITY takes precedence over the legacy top-level
// capability (RFC 8408 §3, RFC 8664 Appendix A). An unlisted PST is ignored
// (RFC 8664 §5.1, RFC 9603 §5.1).
func peerMaxSIDs(caps []pcep.CapabilityInterface, pst pcep.Pst) (maxSIDs uint8, ok bool) {
	if pstCap := firstPathSetupTypeCapability(caps); pstCap != nil {
		if !pstCap.HasPathSetupType(pst) {
			return 0, false
		}

		if sub := firstSIDDepthCapability(pstCap.SubCapabilities(), pst); sub != nil {
			return sub.MaxSIDs()
		}

		return 0, false
	}

	if topLevel := firstSIDDepthCapability(caps, pst); topLevel != nil {
		return topLevel.MaxSIDs()
	}

	return 0, false
}

// validatePathSetupTypeForPeer rejects segment lists with unsupported path setup types.
func (ss *Session) validatePathSetupTypeForPeer(segmentList []table.Segment) error {
	pst, ok := pcep.PathSetupTypeForSegments(segmentList)
	if !ok {
		// An empty or unknown segment list is caught when the message is built.
		return nil
	}

	if !peerSupportsPST(ss.ReceivedCapabilities(), pst) {
		return fmt.Errorf("the PCC did not advertise the path setup type this segment list requires: %s", pst)
	}

	return nil
}

// validateSegmentListForPeer rejects segment lists unsupported by the peer.
func (ss *Session) validateSegmentListForPeer(segmentList []table.Segment) error {
	if err := ss.validatePathSetupTypeForPeer(segmentList); err != nil {
		return err
	}

	pst, ok := pcep.PathSetupTypeForSegments(segmentList)
	if !ok {
		return nil
	}

	if maxSIDs, ok := peerMaxSIDs(ss.ReceivedCapabilities(), pst); ok && len(segmentList) > int(maxSIDs) {
		return fmt.Errorf("segment list has %d SIDs, exceeding the maximum SID depth of %d advertised by the PCC", len(segmentList), maxSIDs)
	}

	return nil
}

// RequestAllSRPolicyDeleted requests deletion of all SR Policies for this session.
func (ss *Session) RequestAllSRPolicyDeleted() error {
	var srPolicy table.SRPolicy
	return ss.SendPCInitiate(srPolicy, true)
}

// RequestSRPolicyDeleted requests deletion of the given SR Policy.
func (ss *Session) RequestSRPolicyDeleted(srPolicy table.SRPolicy) error {
	return ss.SendPCInitiate(srPolicy, true)
}

// RequestSRPolicyCreated requests creation of the given SR Policy.
func (ss *Session) RequestSRPolicyCreated(srPolicy table.SRPolicy) error {
	return ss.SendPCInitiate(srPolicy, false)
}

// SendOpen sends a PCEP Open message to the peer.
func (ss *Session) SendOpen() error {
	ss.stateMu.RLock()
	sessionID, keepalive, deadTimer := ss.localSessionID, ss.localKeepalive, ss.localDeadTimer
	ss.stateMu.RUnlock()

	openMessage := pcep.NewOpenMessage(sessionID, keepalive, deadTimer, ss.AdvertisedCapabilities())
	ss.logger.Debug("Send Open Message")

	if err := ss.sendPCEPMessage(openMessage); err != nil {
		return err
	}

	ss.stateMu.Lock()
	ss.localOpen = &OpenParams{
		SessionID: openMessage.OpenObject.Sid,
		Keepalive: openMessage.OpenObject.Keepalive,
		DeadTimer: openMessage.OpenObject.Deadtime,
	}
	ss.stateMu.Unlock()
	ss.stats.inc(&ss.stats.openSent)

	return nil
}

// nextUnusedSRPID returns an unused SRP-ID, wrapping at limit.
// It returns an error if all non-reserved IDs are in use.
func nextUnusedSRPID(
	head, limit uint32,
	used func(uint32) bool,
) (srpID, nextHead uint32, err error) {
	capacity := limit - 1 // valid range is [1, limit-1]; 0 and limit are reserved.
	for range capacity {
		if head == 0 || head >= limit {
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

// SendPCInitiate sends a PCEP PC-Initiate message to request creation or deletion of an SR Policy.
func (ss *Session) SendPCInitiate(srPolicy table.SRPolicy, lspDelete bool) error {
	// Deletion imposes no SID, so only the path setup type is checked.
	validate, action := ss.validateSegmentListForPeer, "instantiate"
	if lspDelete {
		validate, action = ss.validatePathSetupTypeForPeer, "delete"
	}

	if err := validate(srPolicy.SegmentList); err != nil {
		return fmt.Errorf("cannot %s SR policy %q: %w", action, srPolicy.Name, err)
	}

	srpID, err := ss.allocateSRPID(srPolicy.Type, srPolicy.Metric)
	if err != nil {
		return err
	}

	var pcinitiateMessage *pcep.PCInitiateMessage
	if lspDelete {
		pcinitiateMessage, err = pcep.NewPCInitiateDeleteMessage(srpID, srPolicy)
	} else {
		pcinitiateMessage, err = pcep.NewPCInitiateMessage(srpID, srPolicy, pcep.VendorSpecific(ss.pccType), pcep.OriginatorASN(ss.asn))
	}

	if err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return fmt.Errorf("build PC-Initiate message for SR policy %q: %w", srPolicy.Name, err)
	}

	ss.logger.Debug("Send PCInitiate Message")

	if err := ss.sendPCEPMessage(pcinitiateMessage); err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return err
	}

	ss.stats.inc(&ss.stats.pcinitiateSent)

	return nil
}

// SendPCUpdate sends a PCEP PC-Update message to update an existing SR Policy.
func (ss *Session) SendPCUpdate(srPolicy table.SRPolicy) error {
	if err := ss.validateSegmentListForPeer(srPolicy.SegmentList); err != nil {
		return fmt.Errorf("cannot update SR policy %q: %w", srPolicy.Name, err)
	}

	srpID, err := ss.allocateSRPID(srPolicy.Type, srPolicy.Metric)
	if err != nil {
		return err
	}

	pcupdateMessage, err := pcep.NewPCUpdMessage(srpID, srPolicy)
	if err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return fmt.Errorf("build PC-Update message for SR policy %q: %w", srPolicy.Name, err)
	}

	ss.logger.Debug("Send Update Message")

	if err := ss.sendPCEPMessage(pcupdateMessage); err != nil {
		ss.forgetSRPolicyIntent(srpID)
		return err
	}

	ss.stats.inc(&ss.stats.updSent)

	return nil
}

// RegisterSRPolicy registers an SR Policy from a PCEP state report.
func (ss *Session) RegisterSRPolicy(sr *pcep.StateReport) error {
	color, preference := ss.resolveColorPreference(sr)
	state := resolvePolicyState(sr.LSPObject.OFlag)

	segmentList, err := validateSegmentList(sr)
	if err != nil {
		return err
	}

	return ss.updateOrCreatePolicy(sr, segmentList, color, preference, state)
}

// resolveColorPreference returns the color and preference for the SR Policy.
func (ss *Session) resolveColorPreference(sr *pcep.StateReport) (color, preference uint32) {
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

		var assocColor uint32
		if assoc := srPolicyAssociation(sr); assoc != nil {
			assocColor = assoc.Color()
			preference = assoc.Preference()
		}

		// SR Policy Association color takes precedence
		switch {
		case assocColor != 0:
			color = assocColor
		case hasColor:
			color = sr.LSPObject.Color()
		}
	}

	return color, preference
}

// resolvePolicyState converts O-Flag to internal PolicyState.
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

// validateSegmentList checks if the Segment List exists and is non-empty.
func validateSegmentList(sr *pcep.StateReport) ([]table.Segment, error) {
	if sr.EroObject == nil {
		return nil, fmt.Errorf("EroObject is nil for PlspID %d", sr.LSPObject.PlspID)
	}

	list := sr.EroObject.ToSegmentList()
	if len(list) == 0 {
		return nil, fmt.Errorf("SegmentList is empty for PlspID %d", sr.LSPObject.PlspID)
	}

	return list, nil
}

// updateOrCreatePolicy updates an existing SR Policy or creates a new one.
func (ss *Session) updateOrCreatePolicy(sr *pcep.StateReport, segmentList []table.Segment, color, preference uint32, state table.PolicyState) error {
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

	assoc := srPolicyAssociation(sr)

	src := sr.LSPObject.SrcAddr
	if !src.IsValid() && assoc != nil {
		src = assoc.AssocSrc
	}

	if !src.IsValid() {
		return fmt.Errorf("invalid source address for PlspID %d", sr.LSPObject.PlspID)
	}

	dst := sr.LSPObject.DstAddr
	if !dst.IsValid() && assoc != nil {
		dst = assoc.Endpoint()
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

// DeleteSRPolicy deletes an SR Policy from the session.
func (ss *Session) DeleteSRPolicy(sr *pcep.StateReport) {
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

// SearchSRPolicy searches for an SR Policy by PLSP-ID.
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
