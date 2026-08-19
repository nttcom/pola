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
	"github.com/nttcom/pola/pkg/table"
	"google.golang.org/protobuf/proto"
)

func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second)
}

// StatefulCapability holds the RFC 8231/8232 Stateful PCE capability flags.
type StatefulCapability struct {
	LSPUpdate            bool
	IncludeDBVersion     bool
	LSPInstantiation     bool
	TriggeredResync      bool
	DeltaLSPSync         bool
	TriggeredInitialSync bool
	Color                bool
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
	UnlimitedMSD bool
	NAISupported bool
	MSD          uint32
}

// Strings returns the human-readable flags for this capability.
func (c SRCapability) Strings() []string {
	ret := []string{"SR"}
	if c.UnlimitedMSD {
		ret = append(ret, "Unlimited-SID-Depth")
	} else {
		ret = append(ret, fmt.Sprintf("MSD=%d", c.MSD))
	}
	if c.NAISupported {
		ret = append(ret, "SR-NAI-Supported")
	}
	return ret
}

// SRv6Capability holds the RFC 9603 SRv6-PCE capability flags.
type SRv6Capability struct {
	NAISupported bool
}

// Strings returns the human-readable flags for this capability.
func (c SRv6Capability) Strings() []string {
	ret := []string{"SRv6"}
	if c.NAISupported {
		ret = append(ret, "SRv6-NAI-Supported")
	}
	return ret
}

// PathSetupTypeCapability holds the raw PathSetupType values advertised by the peer.
type PathSetupTypeCapability struct {
	PathSetupTypes []uint32
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
	AssocTypes []uint32
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
	VersionNumber uint64
}

// Strings returns the human-readable flags for this capability.
func (c LSPDBVersionCapability) Strings() []string {
	return []string{"LSP-DB-VERSION"}
}

// MultipathCapability holds the multipath capability flags
// (draft-ietf-pce-multipath).
type MultipathCapability struct {
	MaxMultipaths uint32
	Weighted      bool
	OppositeDir   bool
	ForwardClass  bool
	CompositePath bool
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
	EnterpriseNumber uint32
}

// Strings returns the human-readable flags for this capability.
func (c VendorInformationCapability) Strings() []string {
	return []string{fmt.Sprintf("Vendor-Info(%d)", c.EnterpriseNumber)}
}

// UnknownCapability holds the raw TLV type of a capability Pola does not recognize.
type UnknownCapability struct {
	TLVType uint32
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
	Type   string
	Detail capabilityDetail
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
	Keepalive uint32
	DeadTimer uint32
}

// EffectiveTimers holds the timers currently applied by Pola.
type EffectiveTimers struct {
	Keepalive uint32
	DeadTimer uint32
}

// Session represents a PCEP session.
type Session struct {
	Addr            netip.Addr
	State           string
	LocalSessionID  *uint32
	PccSessionID    *uint32
	LocalTimers     *SessionTimers
	PccTimers       *SessionTimers
	EffectiveTimers EffectiveTimers
	PccType         string
	Capabilities    []Capability
	PccCapabilities []Capability
	IsSynced        bool
	SRPolicies      []table.SRPolicy
}

// CapStrings returns human-readable representations of Pola's capabilities.
func (s Session) CapStrings() []string {
	return capStrings(s.Capabilities)
}

// PccCapStrings returns human-readable representations of the PCC's capabilities.
func (s Session) PccCapStrings() []string {
	return capStrings(s.PccCapabilities)
}

func capStrings(caps []Capability) []string {
	var out []string
	for _, c := range caps {
		out = append(out, c.Strings()...)
	}
	return out
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
			MSD:          detail.Sr.GetMsd(),
		}
	case *pb.Capability_Srv6:
		cap.Detail = SRv6Capability{NAISupported: detail.Srv6.GetNaiSupported()}
	case *pb.Capability_PathSetupType:
		cap.Detail = PathSetupTypeCapability{PathSetupTypes: detail.PathSetupType.GetPathSetupTypes()}
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
	addr, ok := netip.AddrFromSlice(pbss.GetAddr())
	if !ok {
		return Session{}, fmt.Errorf("invalid session address: %v", pbss.GetAddr())
	}

	ss := Session{
		Addr:  addr,
		State: strings.TrimPrefix(pbss.GetState().String(), "SESSION_STATE_"),
		EffectiveTimers: EffectiveTimers{
			Keepalive: pbss.GetEffectiveTimers().GetKeepalive(),
			DeadTimer: pbss.GetEffectiveTimers().GetDeadTimer(),
		},
		PccType:         strings.TrimPrefix(pbss.GetPccType().String(), "PCC_TYPE_"),
		IsSynced:        pbss.GetIsSynced(),
		Capabilities:    []Capability{},
		PccCapabilities: []Capability{},
	}
	if pbss.LocalSessionId != nil {
		ss.LocalSessionID = proto.Uint32(pbss.GetLocalSessionId())
	}
	if pbss.PccSessionId != nil {
		ss.PccSessionID = proto.Uint32(pbss.GetPccSessionId())
	}
	if t := pbss.GetLocalTimers(); t != nil {
		ss.LocalTimers = &SessionTimers{Keepalive: t.GetKeepalive(), DeadTimer: t.GetDeadTimer()}
	}
	if t := pbss.GetPccTimers(); t != nil {
		ss.PccTimers = &SessionTimers{Keepalive: t.GetKeepalive(), DeadTimer: t.GetDeadTimer()}
	}
	for _, c := range pbss.GetCapabilities() {
		ss.Capabilities = append(ss.Capabilities, capabilityFromPB(c))
	}
	for _, c := range pbss.GetPccCapabilities() {
		ss.PccCapabilities = append(ss.PccCapabilities, capabilityFromPB(c))
	}
	return ss, nil
}

// GetSessions retrieves the list of PCEP sessions from the PCE server.
func GetSessions(client pb.PCEServiceClient) ([]Session, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetSessionList(ctx, &pb.GetSessionListRequest{})
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

// DeleteSession sends a delete session request to the PCE server.
func DeleteSession(client pb.PCEServiceClient, req *pb.DeleteSessionRequest) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.DeleteSession(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

// GetSRPolicyList returns SR Policies grouped by PCEP session,
// optionally filtered by session address.
func GetSRPolicyList(client pb.PCEServiceClient, sessionAddr netip.Addr) ([]Session, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	req := &pb.GetSRPolicyListRequest{}
	if sessionAddr.IsValid() {
		req.SessionAddr = sessionAddr.AsSlice()
	}

	ret, err := client.GetSRPolicyList(ctx, req)
	if err != nil {
		return nil, err
	}

	sessions := make([]Session, 0, len(ret.GetSessions()))
	for _, pbSession := range ret.GetSessions() {
		ss, err := sessionFromPB(pbSession)
		if err != nil {
			return nil, err
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
		LSPID:       uint16(p.GetLspId()),
		State:       policyStateFromPB(p.GetState()),
		Type:        policyTypeFromPB(p.GetType()),
		Metric:      metricTypeFromPB(p.GetMetric()),
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

	if !ret.GetEnable() {
		return nil, nil
	}

	ted := &table.LsTED{
		Nodes: make(map[string]*table.LsNode),
	}

	initializeLsNodes(ted, ret.GetLsNodes())

	for _, node := range ret.GetLsNodes() {
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
	for _, link := range node.GetLsLinks() {
		localNode := ted.Nodes[link.LocalRouterId]
		remoteNode := ted.Nodes[link.RemoteRouterId]
		lsLink, err := createLsLink(localNode, remoteNode, link)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetRouterId()].Links = append(ted.Nodes[node.GetRouterId()].Links, lsLink)
	}

	for _, prefix := range node.LsPrefixes {
		lsPrefix, err := createLsPrefix(ted.Nodes[node.GetRouterId()], prefix)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetRouterId()].Prefixes = append(ted.Nodes[node.GetRouterId()].Prefixes, lsPrefix)
	}

	for _, srv6SID := range node.LsSrv6Sids {
		lsSrv6SID := createSrv6SID(ted.Nodes[node.GetRouterId()], srv6SID)
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
		lsLink.Srv6EndXSID = createSrv6EndXSID(link.GetSrv6EndXSid())
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

func createSrv6EndXSID(srv6EndXSID *pb.Srv6EndXSID) *table.Srv6EndXSID {
	lsSrv6EndXSID := &table.Srv6EndXSID{
		EndpointBehavior: uint16(srv6EndXSID.EndpointBehavior),
		Sids:             []string{},
		Srv6SIDStructure: table.SIDStructure{
			LocalBlock: uint8(srv6EndXSID.GetSidStructure().GetLocalBlock()),
			LocalNode:  uint8(srv6EndXSID.GetSidStructure().GetLocalNode()),
			LocalFunc:  uint8(srv6EndXSID.GetSidStructure().GetLocalFunc()),
			LocalArg:   uint8(srv6EndXSID.GetSidStructure().GetLocalArg()),
		},
	}

	for _, sid := range srv6EndXSID.GetSids() {
		lsSrv6EndXSID.Sids = append(lsSrv6EndXSID.Sids, sid.GetSid())
	}

	return lsSrv6EndXSID
}

func createSrv6SID(lsNode *table.LsNode, srv6SID *pb.LsSrv6SID) *table.LsSrv6SID {
	lsSrv6SID := table.NewLsSrv6SID(lsNode)

	for _, sid := range srv6SID.GetSids() {
		lsSrv6SID.Sids = append(lsSrv6SID.Sids, sid.GetSid())
	}
	for _, topoID := range srv6SID.GetMultiTopoIds() {
		lsSrv6SID.MultiTopoIDs = append(lsSrv6SID.MultiTopoIDs, topoID.GetMultiTopoId())
	}

	lsSrv6SID.EndpointBehavior.Behavior = uint16(srv6SID.GetEndpointBehavior().GetBehavior())
	lsSrv6SID.EndpointBehavior.Flags = uint8(srv6SID.GetEndpointBehavior().GetFlags())
	lsSrv6SID.EndpointBehavior.Algorithm = uint8(srv6SID.GetEndpointBehavior().GetAlgorithm())

	lsSrv6SID.SIDStructure.LocalBlock = uint8(srv6SID.GetSidStructure().GetLocalBlock())
	lsSrv6SID.SIDStructure.LocalNode = uint8(srv6SID.GetSidStructure().GetLocalNode())
	lsSrv6SID.SIDStructure.LocalFunc = uint8(srv6SID.GetSidStructure().GetLocalFunc())
	lsSrv6SID.SIDStructure.LocalArg = uint8(srv6SID.GetSidStructure().GetLocalArg())

	return lsSrv6SID
}
