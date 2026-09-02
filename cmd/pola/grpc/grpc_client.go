// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package grpc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/internal/safecast"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

const unknownDisplayValue = "unknown"

func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second)
}

// StatefulCapability holds the RFC 8231/8232 Stateful PCE capability flags.
type StatefulCapability struct {
	LSPUpdate            bool `json:"LSPUpdate"`
	IncludeDBVersion     bool `json:"IncludeDBVersion"`
	LSPInstantiation     bool `json:"LSPInstantiation"`
	TriggeredResync      bool `json:"TriggeredResync"`
	DeltaLSPSync         bool `json:"DeltaLSPSync"`
	TriggeredInitialSync bool `json:"TriggeredInitialSync"`
	Color                bool `json:"Color"`
}

// Strings returns the human-readable flags for this capability.
func (c StatefulCapability) Strings() []string {
	ret := []string{"Stateful"}
	if c.LSPUpdate {
		ret = append(ret, "Update")
	}
	if c.IncludeDBVersion {
		ret = append(ret, "Include-DB-Ver")
	}
	if c.LSPInstantiation {
		ret = append(ret, "Instantiation")
	}
	if c.TriggeredResync {
		ret = append(ret, "Triggered-Resync")
	}
	if c.DeltaLSPSync {
		ret = append(ret, "Delta-LSP-Sync")
	}
	if c.TriggeredInitialSync {
		ret = append(ret, "Triggered-Initial-Sync")
	}
	if c.Color {
		ret = append(ret, "Color")
	}
	return ret
}

// SRCapability holds the RFC 8664 SR-PCE capability flags.
type SRCapability struct {
	UnlimitedMSD bool    `json:"UnlimitedMSD"`
	NAISupported bool    `json:"NAISupported"`
	MSD          *uint32 `json:"MSD"`
}

// Strings returns the human-readable flags for this capability.
func (c SRCapability) Strings() []string {
	ret := []string{"SR"}
	switch {
	case c.UnlimitedMSD:
		ret = append(ret, "Unlimited-SID-Depth")
	case c.MSD != nil:
		ret = append(ret, fmt.Sprintf("MSD=%d", *c.MSD))
	}
	if c.NAISupported {
		ret = append(ret, "SR-NAI-Supported")
	}
	return ret
}

// SRv6Capability holds the RFC 9603 SRv6-PCE capability flags.
type SRv6Capability struct {
	NAISupported bool `json:"NAISupported"`
}

// Strings returns the human-readable flags for this capability.
func (c SRv6Capability) Strings() []string {
	ret := []string{"SRv6"}
	if c.NAISupported {
		ret = append(ret, "SRv6-NAI-Supported")
	}
	return ret
}

// PathSetupTypeCapability holds the raw PathSetupType values advertised by the peer,
// along with any per-PST capability sub-TLVs (RFC 8408).
type PathSetupTypeCapability struct {
	PathSetupTypes  []uint32     `json:"PathSetupTypes"`
	SubCapabilities []Capability `json:"SubCapabilities"`
}

// Strings returns the human-readable flags for this capability.
func (c PathSetupTypeCapability) Strings() []string {
	var ret []string
	for _, pst := range c.PathSetupTypes {
		switch pst {
		case 1:
			ret = append(ret, "SR-TE")
		case 3:
			ret = append(ret, "SRv6-TE")
		}
	}
	return ret
}

// AssocTypeListCapability holds the raw Association types advertised by the peer.
type AssocTypeListCapability struct {
	AssocTypes []uint32 `json:"AssocTypes"`
}

// Strings returns the human-readable flags for this capability.
func (c AssocTypeListCapability) Strings() []string {
	ret := make([]string, 0, len(c.AssocTypes))
	for _, at := range c.AssocTypes {
		ret = append(ret, fmt.Sprintf("AssocType:%d", at))
	}
	return ret
}

// LSPDBVersionCapability holds the LSP-DB version number advertised by the peer.
type LSPDBVersionCapability struct {
	VersionNumber uint64 `json:"VersionNumber"`
}

// Strings returns the human-readable flags for this capability.
func (c LSPDBVersionCapability) Strings() []string {
	return []string{"LSP-DB-VERSION"}
}

// MultipathCapability holds the multipath capability flags
// (draft-ietf-pce-multipath).
type MultipathCapability struct {
	MaxMultipaths uint32 `json:"MaxMultipaths"`
	Weighted      bool   `json:"Weighted"`
	OppositeDir   bool   `json:"OppositeDir"`
	ForwardClass  bool   `json:"ForwardClass"`
	CompositePath bool   `json:"CompositePath"`
}

// Strings returns the human-readable flags for this capability.
func (c MultipathCapability) Strings() []string {
	ret := []string{"Multipath", fmt.Sprintf("MaxMultipaths=%d", c.MaxMultipaths)}
	if c.Weighted {
		ret = append(ret, "Weighted")
	}
	if c.OppositeDir {
		ret = append(ret, "OppositeDir")
	}
	if c.ForwardClass {
		ret = append(ret, "ForwardClass")
	}
	if c.CompositePath {
		ret = append(ret, "CompositePath")
	}
	return ret
}

// VendorInformationCapability holds the enterprise number of a vendor-specific capability TLV.
type VendorInformationCapability struct {
	EnterpriseNumber uint32 `json:"EnterpriseNumber"`
}

// Strings returns the human-readable flags for this capability.
func (c VendorInformationCapability) Strings() []string {
	return []string{pcep.EnterpriseNumber(c.EnterpriseNumber).DisplayLabel()}
}

// UnknownCapability holds the raw TLV type of a capability Pola does not recognize.
type UnknownCapability struct {
	TLVType uint32 `json:"TLVType"`
}

// Strings returns a human-readable representation of this capability.
func (c UnknownCapability) Strings() []string {
	return []string{fmt.Sprintf("unknown_type_%d", c.TLVType)}
}

// capabilityDetail is implemented by every typed capability detail above.
type capabilityDetail interface {
	Strings() []string
}

// Capability represents a PCEP capability with optional detailed information.
type Capability struct {
	Type   string           `json:"Type"`
	Detail capabilityDetail `json:"Detail"`
}

// Strings returns a human-readable representation of this capability.
func (c Capability) Strings() []string {
	if c.Detail == nil {
		return []string{c.Type}
	}
	return c.Detail.Strings()
}

// SessionTimers holds the timers advertised by a PCEP speaker.
type SessionTimers struct {
	Keepalive uint32 `json:"Keepalive"`
	DeadTimer uint32 `json:"DeadTimer"`
}

// EffectiveTimers holds the timers currently applied by Pola.
// Keepalive and DeadTimer are nil until the session reaches SESSION_STATE_UP.
type EffectiveTimers struct {
	Keepalive *uint32 `json:"Keepalive"`
	DeadTimer *uint32 `json:"DeadTimer"`
}

// MessageCounter mirrors one RFC 9826 sent/rcvd counter pair.
type MessageCounter struct {
	Sent uint64 `json:"Sent"`
	Rcvd uint64 `json:"Rcvd"`
}

// SessionStats contains per-session PCEP statistics.
type SessionStats struct {
	Open             MessageCounter `json:"Open"`
	Keepalive        MessageCounter `json:"Keepalive"`
	Close            MessageCounter `json:"Close"`
	PCErr            MessageCounter `json:"PCErr"`
	PCNtf            MessageCounter `json:"PCNtf"`
	PCReq            MessageCounter `json:"PCReq"`
	PCRep            MessageCounter `json:"PCRep"`
	Report           MessageCounter `json:"Report"`
	Update           MessageCounter `json:"Update"`
	Initiate         MessageCounter `json:"Initiate"`
	UnrecognizedRcvd uint64         `json:"UnrecognizedRcvd"`
	CorruptRcvd      uint64         `json:"CorruptRcvd"`
	SessSetupOK      uint64         `json:"SessSetupOK"`
	SessSetupFail    uint64         `json:"SessSetupFail"`
}

// Session represents a PCEP session.
type Session struct {
	PeerAddr          netip.Addr      `json:"PeerAddr"`
	State             string          `json:"State"`
	LocalSessionID    *uint32         `json:"LocalSessionID"`
	PeerSessionID     *uint32         `json:"PeerSessionID"`
	LocalTimers       *SessionTimers  `json:"LocalTimers"`
	PeerTimers        *SessionTimers  `json:"PeerTimers"`
	EffectiveTimers   EffectiveTimers `json:"EffectiveTimers"`
	PccType           string          `json:"PccType"`
	LocalCapabilities []Capability    `json:"LocalCapabilities"`
	PeerCapabilities  []Capability    `json:"PeerCapabilities"`
	Initiator         string          `json:"Initiator"`
	SyncState         string          `json:"SyncState"`
	CreatedAt         time.Time       `json:"CreatedAt"`
	EstablishedAt     time.Time       `json:"EstablishedAt"`
	UptimeNanos       int64           `json:"UptimeNanos"`
	Stats             *SessionStats   `json:"Stats"`
}

// SRPolicySession groups SR Policies by PCEP peer.
type SRPolicySession struct {
	PeerAddr   netip.Addr       `json:"PeerAddr"`
	State      string           `json:"State"`
	SyncState  string           `json:"SyncState"`
	SRPolicies []table.SRPolicy `json:"SRPolicies"`
}

// capabilityFromPB converts a gRPC Capability into its typed client-side representation.
func capabilityFromPB(c *pb.Capability) Capability {
	cap := Capability{Type: strings.TrimPrefix(c.GetType().String(), "CAPABILITY_TYPE_")}
	switch detail := c.GetDetail().(type) {
	case *pb.Capability_Stateful:
		cap.Detail = StatefulCapability{
			LSPUpdate:            detail.Stateful.GetLspUpdate(),
			IncludeDBVersion:     detail.Stateful.GetIncludeDbVersion(),
			LSPInstantiation:     detail.Stateful.GetLspInstantiation(),
			TriggeredResync:      detail.Stateful.GetTriggeredResync(),
			DeltaLSPSync:         detail.Stateful.GetDeltaLspSync(),
			TriggeredInitialSync: detail.Stateful.GetTriggeredInitialSync(),
			Color:                detail.Stateful.GetColor(),
		}
	case *pb.Capability_Sr:
		cap.Detail = SRCapability{
			UnlimitedMSD: detail.Sr.GetUnlimitedMsd(),
			NAISupported: detail.Sr.GetNaiSupported(),
			MSD:          detail.Sr.Msd,
		}
	case *pb.Capability_Srv6:
		cap.Detail = SRv6Capability{NAISupported: detail.Srv6.GetNaiSupported()}
	case *pb.Capability_PathSetupType:
		pst := PathSetupTypeCapability{PathSetupTypes: detail.PathSetupType.GetPathSetupTypes()}
		for _, sub := range detail.PathSetupType.GetSubCapabilities() {
			pst.SubCapabilities = append(pst.SubCapabilities, capabilityFromPB(sub))
		}
		cap.Detail = pst
	case *pb.Capability_AssocTypeList:
		cap.Detail = AssocTypeListCapability{AssocTypes: detail.AssocTypeList.GetAssocTypes()}
	case *pb.Capability_LspDbVersion:
		cap.Detail = LSPDBVersionCapability{VersionNumber: detail.LspDbVersion.GetVersionNumber()}
	case *pb.Capability_Multipath:
		cap.Detail = MultipathCapability{
			MaxMultipaths: detail.Multipath.GetMaxMultipaths(),
			Weighted:      detail.Multipath.GetWeighted(),
			OppositeDir:   detail.Multipath.GetOppositeDir(),
			ForwardClass:  detail.Multipath.GetForwardClass(),
			CompositePath: detail.Multipath.GetCompositePath(),
		}
	case *pb.Capability_VendorInformation:
		cap.Detail = VendorInformationCapability{EnterpriseNumber: detail.VendorInformation.GetEnterpriseNumber()}
	case *pb.Capability_Unknown:
		cap.Detail = UnknownCapability{TLVType: detail.Unknown.GetTlvType()}
	}
	return cap
}

func sessionFromPB(pbss *pb.Session) (Session, error) {
	addr, ok := netip.AddrFromSlice(pbss.GetPeerAddr())
	if !ok {
		return Session{}, fmt.Errorf("invalid session address: %v", pbss.GetPeerAddr())
	}

	ss := Session{
		PeerAddr:          addr,
		State:             sessionStateFromPB(pbss.GetState()),
		PccType:           strings.TrimPrefix(pbss.GetPccType().String(), "PCC_TYPE_"),
		LocalCapabilities: []Capability{},
		PeerCapabilities:  []Capability{},
	}
	if v, ok := pb.EffectiveKeepalive(pbss.GetState(), pbss.GetEffectiveTimers()); ok {
		ss.EffectiveTimers.Keepalive = new(v)
	}
	if v, ok := pb.EffectiveDeadTimer(pbss.GetState(), pbss.GetEffectiveTimers()); ok {
		ss.EffectiveTimers.DeadTimer = new(v)
	}
	if pbss.LocalSessionId != nil {
		ss.LocalSessionID = new(pbss.GetLocalSessionId())
	}
	if pbss.PeerSessionId != nil {
		ss.PeerSessionID = new(pbss.GetPeerSessionId())
	}
	if t := pbss.GetLocalTimers(); t != nil {
		ss.LocalTimers = &SessionTimers{Keepalive: t.GetKeepalive(), DeadTimer: t.GetDeadTimer()}
	}
	if t := pbss.GetPeerTimers(); t != nil {
		ss.PeerTimers = &SessionTimers{Keepalive: t.GetKeepalive(), DeadTimer: t.GetDeadTimer()}
	}
	for _, c := range pbss.GetLocalCapabilities() {
		ss.LocalCapabilities = append(ss.LocalCapabilities, capabilityFromPB(c))
	}
	for _, c := range pbss.GetPeerCapabilities() {
		ss.PeerCapabilities = append(ss.PeerCapabilities, capabilityFromPB(c))
	}

	ss.Initiator = initiatorFromPB(pbss.GetInitiator())
	ss.SyncState = syncStateFromPB(pbss.GetSyncState())
	if n := pbss.GetCreatedAtUnixNano(); n != 0 {
		ss.CreatedAt = time.Unix(0, n)
	}
	if n := pbss.GetEstablishedAtUnixNano(); n != 0 {
		ss.EstablishedAt = time.Unix(0, n)
	}
	ss.UptimeNanos = pbss.GetUptimeNanos()
	if s := pbss.GetStats(); s != nil {
		ss.Stats = sessionStatsFromPB(s)
	}

	return ss, nil
}

// initiatorFromPB converts a gRPC SessionInitiator to its CLI/JSON display value.
func initiatorFromPB(initiator pb.SessionInitiator) string {
	switch initiator {
	case pb.SessionInitiator_SESSION_INITIATOR_LOCAL:
		return "local"
	case pb.SessionInitiator_SESSION_INITIATOR_REMOTE:
		return "remote"
	default:
		return unknownDisplayValue
	}
}

// sessionStateFromPB converts a gRPC SessionState to its CLI/JSON display value.
func sessionStateFromPB(state pb.SessionState) string {
	switch state {
	case pb.SessionState_SESSION_STATE_UP:
		return "up"
	case pb.SessionState_SESSION_STATE_TCP_PENDING:
		return "tcp-pending"
	case pb.SessionState_SESSION_STATE_OPEN_WAIT:
		return "open-wait"
	case pb.SessionState_SESSION_STATE_KEEP_WAIT:
		return "keep-wait"
	default:
		return unknownDisplayValue
	}
}

func syncStateFromPB(state pb.LspDbSyncState) string {
	switch state {
	case pb.LspDbSyncState_LSP_DB_SYNC_STATE_PENDING:
		return "pending"
	case pb.LspDbSyncState_LSP_DB_SYNC_STATE_ONGOING:
		return "ongoing"
	case pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED:
		return "finished"
	default:
		return unknownDisplayValue
	}
}

func messageCounterFromPB(c *pb.MessageCounter) MessageCounter {
	return MessageCounter{Sent: c.GetSent(), Rcvd: c.GetRcvd()}
}

func sessionStatsFromPB(s *pb.SessionStats) *SessionStats {
	return &SessionStats{
		Open:             messageCounterFromPB(s.GetOpen()),
		Keepalive:        messageCounterFromPB(s.GetKeepalive()),
		Close:            messageCounterFromPB(s.GetClose()),
		PCErr:            messageCounterFromPB(s.GetPcerr()),
		PCNtf:            messageCounterFromPB(s.GetPcntf()),
		PCReq:            messageCounterFromPB(s.GetPcreq()),
		PCRep:            messageCounterFromPB(s.GetPcrep()),
		Report:           messageCounterFromPB(s.GetReport()),
		Update:           messageCounterFromPB(s.GetUpdate()),
		Initiate:         messageCounterFromPB(s.GetInitiate()),
		UnrecognizedRcvd: s.GetUnrecognizedRcvd(),
		CorruptRcvd:      s.GetCorruptRcvd(),
		SessSetupOK:      s.GetSessSetupOk(),
		SessSetupFail:    s.GetSessSetupFail(),
	}
}

// GetSessions retrieves PCEP sessions, optionally filtered by peer address.
func GetSessions(client pb.PCEServiceClient, addr netip.Addr, includeStats bool) ([]Session, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	req := &pb.GetSessionListRequest{IncludeStats: includeStats}
	if addr.IsValid() {
		req.PeerAddr = addr.AsSlice()
	}

	ret, err := client.GetSessionList(ctx, req)
	if err != nil {
		return nil, err
	}

	var sessions []Session
	for _, pbss := range ret.GetSessions() {
		ss, err := sessionFromPB(pbss)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, ss)
	}

	return sessions, nil
}

// DeleteSession requests deletion of a PCEP session.
func DeleteSession(client pb.PCEServiceClient, req *pb.DeleteSessionRequest) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.DeleteSession(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

// GetSRPolicyList returns SR Policies grouped by PCEP peer,
// optionally filtered by peer address.
func GetSRPolicyList(client pb.PCEServiceClient, peerAddr netip.Addr) ([]SRPolicySession, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	req := &pb.GetSRPolicyListRequest{}
	if peerAddr.IsValid() {
		req.PeerAddr = peerAddr.AsSlice()
	}

	ret, err := client.GetSRPolicyList(ctx, req)
	if err != nil {
		return nil, err
	}

	sessions := make([]SRPolicySession, 0, len(ret.GetSessions()))
	for _, pbSession := range ret.GetSessions() {
		addr, ok := netip.AddrFromSlice(pbSession.GetPeerAddr())
		if !ok {
			return nil, fmt.Errorf("invalid session address: %v", pbSession.GetPeerAddr())
		}

		ss := SRPolicySession{
			PeerAddr:  addr,
			State:     sessionStateFromPB(pbSession.GetState()),
			SyncState: syncStateFromPB(pbSession.GetSyncState()),
		}

		ss.SRPolicies = make([]table.SRPolicy, 0, len(pbSession.GetSrPolicies()))
		for _, p := range pbSession.GetSrPolicies() {
			policy, err := convertSRPolicy(p)
			if err != nil {
				return nil, err
			}
			ss.SRPolicies = append(ss.SRPolicies, policy)
		}

		sessions = append(sessions, ss)
	}

	return sessions, nil
}

func convertSRPolicy(p *pb.SRPolicy) (table.SRPolicy, error) {
	srcAddr, ok := netip.AddrFromSlice(p.GetSrcAddr())
	if !ok {
		return table.SRPolicy{}, fmt.Errorf("invalid SR policy source address: %v", p.GetSrcAddr())
	}

	dstAddr, ok := netip.AddrFromSlice(p.GetDstAddr())
	if !ok {
		return table.SRPolicy{}, fmt.Errorf("invalid SR policy destination address: %v", p.GetDstAddr())
	}

	segmentList := make([]table.Segment, 0, len(p.GetSegmentList()))
	for _, s := range p.GetSegmentList() {
		seg, err := segmentFromPB(s)
		if err != nil {
			return table.SRPolicy{}, err
		}
		segmentList = append(segmentList, seg)
	}

	lspID, err := safecast.Uint16(p.GetLspId(), "SR policy LSP-ID")
	if err != nil {
		return table.SRPolicy{}, err
	}

	return table.SRPolicy{
		PlspID:      p.GetPlspId(),
		Name:        p.GetPolicyName(),
		SegmentList: segmentList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		SrcRouterID: p.GetSrcRouterId(),
		DstRouterID: p.GetDstRouterId(),
		Color:       p.GetColor(),
		Preference:  p.GetPreference(),
		LSPID:       lspID,
		State:       policyStateFromPB(p.GetState()),
		Type:        policyTypeFromPB(p.GetType()),
		Metric:      metricTypeFromPB(p.GetMetric()),
	}, nil
}

func sidStructureFromPB(s *pb.SidStructure) (table.SIDStructure, error) {
	localBlock, err := safecast.Uint8(s.GetLocalBlock(), "SID structure LocalBlock")
	if err != nil {
		return table.SIDStructure{}, err
	}
	localNode, err := safecast.Uint8(s.GetLocalNode(), "SID structure LocalNode")
	if err != nil {
		return table.SIDStructure{}, err
	}
	localFunc, err := safecast.Uint8(s.GetLocalFunc(), "SID structure LocalFunc")
	if err != nil {
		return table.SIDStructure{}, err
	}
	localArg, err := safecast.Uint8(s.GetLocalArg(), "SID structure LocalArg")
	if err != nil {
		return table.SIDStructure{}, err
	}
	return table.SIDStructure{
		LocalBlock: localBlock,
		LocalNode:  localNode,
		LocalFunc:  localFunc,
		LocalArg:   localArg,
	}, nil
}

func policyStateFromPB(state pb.SRPolicyState) table.PolicyState {
	switch state {
	case pb.SRPolicyState_SR_POLICY_STATE_DOWN:
		return table.PolicyDown
	case pb.SRPolicyState_SR_POLICY_STATE_UP:
		return table.PolicyUp
	case pb.SRPolicyState_SR_POLICY_STATE_ACTIVE:
		return table.PolicyActive
	case pb.SRPolicyState_SR_POLICY_STATE_UNKNOWN:
		return table.PolicyUnknown
	default:
		return ""
	}
}

func policyTypeFromPB(polType pb.SRPolicyType) table.PolicyType {
	switch polType {
	case pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT:
		return table.PolicyTypeExplicit
	case pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC:
		return table.PolicyTypeDynamic
	default:
		return ""
	}
}

func metricTypeFromPB(metricType pb.MetricType) table.MetricType {
	switch metricType {
	case pb.MetricType_METRIC_TYPE_IGP:
		return table.IGPMetric
	case pb.MetricType_METRIC_TYPE_TE:
		return table.TEMetric
	case pb.MetricType_METRIC_TYPE_DELAY:
		return table.DelayMetric
	case pb.MetricType_METRIC_TYPE_HOPCOUNT:
		return table.HopcountMetric
	default:
		return table.UnspecifiedMetric
	}
}

func segmentFromPB(s *pb.Segment) (table.Segment, error) {
	seg, err := table.NewSegment(s.GetSid())
	if err != nil {
		return nil, err
	}
	switch v := seg.(type) {
	case table.SegmentSRv6:
		v.LocalAddr, err = parseOptionalAddr(s.GetLocalAddr())
		if err != nil {
			return nil, fmt.Errorf("invalid SRv6 local address %q: %w", s.GetLocalAddr(), err)
		}
		v.RemoteAddr, err = parseOptionalAddr(s.GetRemoteAddr())
		if err != nil {
			return nil, fmt.Errorf("invalid SRv6 remote address %q: %w", s.GetRemoteAddr(), err)
		}
		structure, err := parseSidStructure(s.GetSidStructure())
		if err != nil {
			return nil, fmt.Errorf("invalid SID structure %q: %w", s.GetSidStructure(), err)
		}
		if structure != nil {
			v.Structure = table.SIDStructureBytes(structure)
		}
		return v, nil
	case table.SegmentSRMPLS:
		v.LocalAddr, err = parseOptionalAddr(s.GetLocalAddr())
		if err != nil {
			return nil, fmt.Errorf("invalid SR-MPLS local address %q: %w", s.GetLocalAddr(), err)
		}
		v.RemoteAddr, err = parseOptionalAddr(s.GetRemoteAddr())
		if err != nil {
			return nil, fmt.Errorf("invalid SR-MPLS remote address %q: %w", s.GetRemoteAddr(), err)
		}
		v.SidAbsent = s.GetSidAbsent()
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported segment type for SID %q", s.GetSid())
	}
}

// parseOptionalAddr parses an IP address, treating an empty string as unset.
func parseOptionalAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

// parseSidStructure parses a comma-separated SID structure string and treats an empty string as unset.
func parseSidStructure(s string) ([]uint8, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf("expected 4 comma-separated values, got %d", len(parts))
	}
	result := make([]uint8, 4)
	for i, p := range parts {
		v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("part %d: %w", i, err)
		}
		result[i] = uint8(v)
	}
	if err := table.SIDStructureBytes(result).Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateSRPolicy sends a create SR policy request to the PCE server.
func CreateSRPolicy(client pb.PCEServiceClient, req *pb.CreateSRPolicyRequest) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.CreateSRPolicy(ctx, req)
	return err
}

// DeleteSRPolicy sends a delete SR policy request to the PCE server.
func DeleteSRPolicy(client pb.PCEServiceClient, req *pb.DeleteSRPolicyRequest) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.DeleteSRPolicy(ctx, req)
	return err
}

// GetTED retrieves the Traffic Engineering Database (TED) from the PCE server.
func GetTED(client pb.PCEServiceClient) (*table.LsTED, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetTED(ctx, &pb.GetTEDRequest{})
	if err != nil {
		return nil, err
	}

	if !ret.GetEnabled() {
		return nil, nil
	}

	ted := &table.LsTED{
		Nodes: make(map[string]*table.LsNode),
	}

	initializeLsNodes(ted, ret.GetNodes())

	for _, node := range ret.GetNodes() {
		if err := addLsNode(ted, node); err != nil {
			return nil, err
		}
	}

	return ted, nil
}

// initializeLsNodes initializes LsNodes in the LsTED table.
func initializeLsNodes(ted *table.LsTED, nodes []*pb.LsNode) {
	for _, node := range nodes {
		lsNode := table.NewLsNode(node.GetAsn(), node.GetRouterId())
		lsNode.Hostname = node.GetHostname()
		lsNode.IsisAreaID = node.GetIsisAreaId()
		lsNode.SrgbBegin = node.GetSrgbBegin()
		lsNode.SrgbEnd = node.GetSrgbEnd()

		ted.Nodes[lsNode.RouterID] = lsNode
	}
}

func addLsNode(ted *table.LsTED, node *pb.LsNode) error {
	for _, link := range node.GetLinks() {
		localNode := ted.Nodes[link.LocalRouterId]
		remoteNode := ted.Nodes[link.RemoteRouterId]
		lsLink, err := createLsLink(localNode, remoteNode, link)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetRouterId()].Links = append(ted.Nodes[node.GetRouterId()].Links, lsLink)
	}

	for _, prefix := range node.GetPrefixes() {
		lsPrefix, err := createLsPrefix(ted.Nodes[node.GetRouterId()], prefix)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetRouterId()].Prefixes = append(ted.Nodes[node.GetRouterId()].Prefixes, lsPrefix)
	}

	for _, srv6SID := range node.GetSrv6Sids() {
		lsSrv6SID, err := createSrv6SID(ted.Nodes[node.GetRouterId()], srv6SID)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetRouterId()].SRv6SIDs = append(ted.Nodes[node.GetRouterId()].SRv6SIDs, lsSrv6SID)
	}

	return nil
}

func createLsPrefix(lsNode *table.LsNode, prefix *pb.LsPrefix) (*table.LsPrefix, error) {
	lsPrefix := table.NewLsPrefix(lsNode)
	var err error
	lsPrefix.Prefix, err = netip.ParsePrefix(prefix.GetPrefix())
	if err != nil {
		return nil, err
	}
	if prefix.SidIndex != nil {
		lsPrefix.SidIndex = prefix.GetSidIndex()
		lsPrefix.HasSidIndex = true
	}

	return lsPrefix, nil
}

func createLsLink(localNode, remoteNode *table.LsNode, link *pb.LsLink) (*table.LsLink, error) {
	lsLink := &table.LsLink{
		LocalNode:  localNode,
		RemoteNode: remoteNode,
		AdjSid:     link.GetAdjSid(),
	}
	var err error
	err = lsLink.LocalIP.UnmarshalText([]byte(link.GetLocalIp()))
	if err != nil {
		return nil, err
	}
	err = lsLink.RemoteIP.UnmarshalText([]byte(link.GetRemoteIp()))
	if err != nil {
		return nil, err
	}
	for _, metricInfo := range link.GetMetrics() {
		metric, err := createMetric(metricInfo)
		if err != nil {
			return nil, err
		}
		lsLink.Metrics = append(lsLink.Metrics, metric)
	}
	if link.GetSrv6EndXSid() != nil {
		srv6EndXSID, err := createSrv6EndXSID(link.GetSrv6EndXSid())
		if err != nil {
			return nil, err
		}
		lsLink.Srv6EndXSID = srv6EndXSID
	}
	return lsLink, nil
}

func createMetric(metricInfo *pb.Metric) (*table.Metric, error) {
	switch metricInfo.GetType() {
	case pb.MetricType_METRIC_TYPE_IGP:
		return table.NewMetric(table.IGPMetric, metricInfo.GetValue()), nil
	case pb.MetricType_METRIC_TYPE_TE:
		return table.NewMetric(table.TEMetric, metricInfo.GetValue()), nil
	case pb.MetricType_METRIC_TYPE_DELAY:
		return table.NewMetric(table.DelayMetric, metricInfo.GetValue()), nil
	case pb.MetricType_METRIC_TYPE_HOPCOUNT:
		return table.NewMetric(table.HopcountMetric, metricInfo.GetValue()), nil
	default:
		return nil, errors.New("unknown metric type")
	}
}

func createSrv6EndXSID(srv6EndXSID *pb.Srv6EndXSID) (*table.Srv6EndXSID, error) {
	endpointBehavior, err := safecast.Uint16(srv6EndXSID.EndpointBehavior, "SRv6 End.X SID endpoint behavior")
	if err != nil {
		return nil, err
	}
	structure, err := sidStructureFromPB(srv6EndXSID.GetSidStructure())
	if err != nil {
		return nil, err
	}

	lsSrv6EndXSID := &table.Srv6EndXSID{
		EndpointBehavior: endpointBehavior,
		Sids:             []string{},
		Srv6SIDStructure: structure,
	}

	for _, sid := range srv6EndXSID.GetSids() {
		lsSrv6EndXSID.Sids = append(lsSrv6EndXSID.Sids, sid.GetSid())
	}

	return lsSrv6EndXSID, nil
}

func createSrv6SID(lsNode *table.LsNode, srv6SID *pb.LsSrv6SID) (*table.LsSrv6SID, error) {
	lsSrv6SID := table.NewLsSrv6SID(lsNode)

	for _, sid := range srv6SID.GetSids() {
		lsSrv6SID.Sids = append(lsSrv6SID.Sids, sid.GetSid())
	}
	for _, topoID := range srv6SID.GetMultiTopoIds() {
		lsSrv6SID.MultiTopoIDs = append(lsSrv6SID.MultiTopoIDs, topoID.GetMultiTopoId())
	}

	behavior, err := safecast.Uint16(srv6SID.GetEndpointBehavior().GetBehavior(), "SRv6 SID endpoint behavior")
	if err != nil {
		return nil, err
	}
	flags, err := safecast.Uint8(srv6SID.GetEndpointBehavior().GetFlags(), "SRv6 SID endpoint behavior flags")
	if err != nil {
		return nil, err
	}
	algorithm, err := safecast.Uint8(srv6SID.GetEndpointBehavior().GetAlgorithm(), "SRv6 SID endpoint behavior algorithm")
	if err != nil {
		return nil, err
	}
	lsSrv6SID.EndpointBehavior.Behavior = behavior
	lsSrv6SID.EndpointBehavior.Flags = flags
	lsSrv6SID.EndpointBehavior.Algorithm = algorithm

	structure, err := sidStructureFromPB(srv6SID.GetSidStructure())
	if err != nil {
		return nil, err
	}
	lsSrv6SID.SIDStructure = structure

	return lsSrv6SID, nil
}
