// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"fmt"
	"math"
	"net/netip"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

func dedupCapabilities(lg *logger.Logger, kind string, caps []pcep.CapabilityInterface) []*pb.Capability {
	var pbCaps []*pb.Capability
	seen := make(map[string]struct{})
	for _, cap := range caps {
		b, err := cap.Serialize()
		if err != nil {
			lg.Warn(fmt.Sprintf("failed to serialize %s capability", kind), logger.Error(err))
			continue
		}
		key := fmt.Sprintf("%d:%s", cap.Type(), b)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		pbCaps = append(pbCaps, buildCapability(cap))
	}
	return pbCaps
}

func toPBSessionState(state SessionState) pb.SessionState {
	switch state {
	case SessionStateTCPPending:
		return pb.SessionState_SESSION_STATE_TCP_PENDING
	case SessionStateOpenWait:
		return pb.SessionState_SESSION_STATE_OPEN_WAIT
	case SessionStateKeepWait:
		return pb.SessionState_SESSION_STATE_KEEP_WAIT
	case SessionStateUp:
		return pb.SessionState_SESSION_STATE_UP
	default:
		return pb.SessionState_SESSION_STATE_UNSPECIFIED
	}
}

func toPBInitiator(initiator SessionInitiator) pb.SessionInitiator {
	switch initiator {
	case SessionInitiatorLocal:
		return pb.SessionInitiator_SESSION_INITIATOR_LOCAL
	case SessionInitiatorRemote:
		return pb.SessionInitiator_SESSION_INITIATOR_REMOTE
	default:
		return pb.SessionInitiator_SESSION_INITIATOR_UNSPECIFIED
	}
}

func toPBSyncState(state SyncState) pb.LspDbSyncState {
	switch state {
	case SyncStatePending:
		return pb.LspDbSyncState_LSP_DB_SYNC_STATE_PENDING
	case SyncStateOngoing:
		return pb.LspDbSyncState_LSP_DB_SYNC_STATE_ONGOING
	case SyncStateFinished:
		return pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED
	default:
		return pb.LspDbSyncState_LSP_DB_SYNC_STATE_UNSPECIFIED
	}
}

// toPBSessionStats converts session counters and setup counters to protobuf.
// Counters not applicable to Pola's PCE role are reported as 0.
func toPBSessionStats(stats SessionStats, setupOK, setupFail uint64) *pb.SessionStats {
	return &pb.SessionStats{
		Open:             &pb.MessageCounter{Sent: stats.OpenSent, Rcvd: stats.OpenRcvd},
		Keepalive:        &pb.MessageCounter{Sent: stats.KeepaliveSent, Rcvd: stats.KeepaliveRcvd},
		Close:            &pb.MessageCounter{Sent: stats.CloseSent, Rcvd: stats.CloseRcvd},
		Pcerr:            &pb.MessageCounter{Sent: stats.PCErrSent, Rcvd: stats.PCErrRcvd},
		Pcntf:            &pb.MessageCounter{Sent: 0, Rcvd: stats.PCNtfRcvd},
		Pcreq:            &pb.MessageCounter{Sent: 0, Rcvd: stats.PCReqRcvd},
		Pcrep:            &pb.MessageCounter{Sent: 0, Rcvd: stats.PCRepRcvd},
		Report:           &pb.MessageCounter{Sent: 0, Rcvd: stats.RptRcvd},
		Update:           &pb.MessageCounter{Sent: stats.UpdSent, Rcvd: 0},
		Initiate:         &pb.MessageCounter{Sent: stats.PCInitiateSent, Rcvd: 0},
		UnrecognizedRcvd: stats.UnknownRcvd,
		CorruptRcvd:      stats.CorruptRcvd,
		SessSetupOk:      setupOK,
		SessSetupFail:    setupFail,
	}
}

func toPBPccType(pccType pcep.PccType) pb.PccType {
	switch pccType {
	case pcep.CiscoLegacy:
		return pb.PccType_PCC_TYPE_CISCO_LEGACY
	case pcep.JuniperLegacy:
		return pb.PccType_PCC_TYPE_JUNIPER_LEGACY
	case pcep.RFCCompliant:
		return pb.PccType_PCC_TYPE_RFC_COMPLIANT
	default:
		return pb.PccType_PCC_TYPE_UNSPECIFIED
	}
}

func buildCapability(capability pcep.CapabilityInterface) *pb.Capability {
	c := &pb.Capability{Type: capabilityType(capability.Type())}
	switch tlv := capability.(type) {
	case *pcep.StatefulPCECapability:
		c.Detail = &pb.Capability_Stateful{Stateful: &pb.StatefulCapability{
			LspUpdate:            tlv.LSPUpdateCapability,
			IncludeDbVersion:     tlv.IncludeDBVersion,
			LspInstantiation:     tlv.LSPInstantiationCapability,
			TriggeredResync:      tlv.TriggeredResync,
			DeltaLspSync:         tlv.DeltaLSPSyncCapability,
			TriggeredInitialSync: tlv.TriggeredInitialSync,
			Color:                tlv.ColorCapability,
		}}
	case *pcep.SRPCECapability:
		sr := &pb.SrCapability{
			UnlimitedMsd: tlv.HasUnlimitedMaxSIDDepth,
			NaiSupported: tlv.IsNAISupported,
		}
		if !tlv.HasUnlimitedMaxSIDDepth {
			sr.Msd = new(uint32(tlv.MaximumSidDepth))
		}
		c.Detail = &pb.Capability_Sr{Sr: sr}
	case *pcep.SRv6PCECapability:
		c.Detail = &pb.Capability_Srv6{Srv6: &pb.Srv6Capability{
			NaiSupported: tlv.IsNAISupported,
		}}
	case *pcep.PathSetupTypeCapability:
		psts := make([]uint32, len(tlv.PathSetupTypes))
		for i, pst := range tlv.PathSetupTypes {
			psts[i] = uint32(pst)
		}
		pstCap := &pb.PathSetupTypeCapability{PathSetupTypes: psts}
		for _, subCap := range tlv.SubCapabilities() {
			pstCap.SubCapabilities = append(pstCap.SubCapabilities, buildCapability(subCap))
		}
		c.Detail = &pb.Capability_PathSetupType{PathSetupType: pstCap}
	case *pcep.AssocTypeList:
		assocTypes := make([]uint32, len(tlv.AssocTypes))
		for i, at := range tlv.AssocTypes {
			assocTypes[i] = uint32(at)
		}
		c.Detail = &pb.Capability_AssocTypeList{AssocTypeList: &pb.AssocTypeListCapability{
			AssocTypes: assocTypes,
		}}
	case *pcep.LSPDBVersion:
		c.Detail = &pb.Capability_LspDbVersion{LspDbVersion: &pb.LspDbVersionCapability{
			VersionNumber: tlv.VersionNumber,
		}}
	case *pcep.MultipathCapability:
		c.Detail = &pb.Capability_Multipath{Multipath: &pb.MultipathCapability{
			MaxMultipaths: uint32(tlv.MaxMultipaths),
			Weighted:      tlv.IsWeightedSupported,
			OppositeDir:   tlv.IsOppositeDirSupported,
			ForwardClass:  tlv.IsForwardClassSupported,
			CompositePath: tlv.IsCompositePathSupported,
		}}
	case *pcep.VendorInformation:
		c.Detail = &pb.Capability_VendorInformation{VendorInformation: &pb.VendorInformationCapability{
			EnterpriseNumber: uint32(tlv.EnterpriseNumber),
		}}
	case *pcep.UnknownTLV:
		c.Detail = &pb.Capability_Unknown{Unknown: &pb.UnknownCapability{
			TlvType: uint32(tlv.Typ),
		}}
	}
	return c
}

func capabilityType(t pcep.TLVType) pb.CapabilityType {
	switch t {
	case pcep.TLVStatefulPCECapability:
		return pb.CapabilityType_CAPABILITY_TYPE_STATEFUL
	case pcep.TLVSRPCECapability:
		return pb.CapabilityType_CAPABILITY_TYPE_SR
	case pcep.TLVSRv6PCECapability:
		return pb.CapabilityType_CAPABILITY_TYPE_SRV6
	case pcep.TLVPathSetupTypeCapability:
		return pb.CapabilityType_CAPABILITY_TYPE_PATH_SETUP_TYPE
	case pcep.TLVAssocTypeList:
		return pb.CapabilityType_CAPABILITY_TYPE_ASSOC_TYPE_LIST
	case pcep.TLVLSPDBVersion:
		return pb.CapabilityType_CAPABILITY_TYPE_LSP_DB_VERSION
	case pcep.TLVMultipathCap:
		return pb.CapabilityType_CAPABILITY_TYPE_MULTIPATH
	case pcep.TLVVendorInformation:
		return pb.CapabilityType_CAPABILITY_TYPE_VENDOR_INFORMATION
	default:
		return pb.CapabilityType_CAPABILITY_TYPE_UNKNOWN
	}
}

// buildPBSession converts a Session to its protobuf representation.
// Stats is included only when requested.
func (s *APIServer) buildPBSession(pcepSession *Session, includeStats bool) *pb.Session {
	snap := pcepSession.snapshot()

	pbPccType := pb.PccType_PCC_TYPE_UNSPECIFIED
	if snap.pccOpen != nil {
		pbPccType = toPBPccType(snap.pccType)
	}

	pbSession := &pb.Session{
		PeerAddr:          pcepSession.peerAddr.AsSlice(),
		State:             toPBSessionState(snap.state),
		PccType:           pbPccType,
		LocalCapabilities: dedupCapabilities(s.logger, "advertised", snap.advertisedCapabilities),
		PeerCapabilities:  dedupCapabilities(s.logger, "received", snap.receivedPccCapabilities),
		Initiator:         toPBInitiator(snap.initiator),
		SyncState:         toPBSyncState(snap.syncState),
	}

	if snap.localOpen != nil {
		pbSession.LocalSessionId = new(uint32(snap.localOpen.SessionID))
		pbSession.LocalTimers = &pb.SessionTimers{
			Keepalive: uint32(snap.localOpen.Keepalive),
			DeadTimer: uint32(snap.localOpen.DeadTimer),
		}
	}
	if snap.pccOpen != nil {
		pbSession.PeerSessionId = new(uint32(snap.pccOpen.SessionID))
		pbSession.PeerTimers = &pb.SessionTimers{
			Keepalive: uint32(snap.pccOpen.Keepalive),
			DeadTimer: uint32(snap.pccOpen.DeadTimer),
		}
	}
	if snap.state == SessionStateUp {
		deadTimer := snap.readDeadline() / time.Second
		if deadTimer > math.MaxUint32 {
			deadTimer = 0
		}
		pbSession.EffectiveTimers = &pb.EffectiveTimers{
			Keepalive: uint32(snap.keepaliveInterval()),
			DeadTimer: uint32(deadTimer),
		}
	}
	if !snap.createdAt.IsZero() {
		pbSession.CreatedAtUnixNano = snap.createdAt.UnixNano()
	}
	if !snap.establishedAt.IsZero() {
		pbSession.EstablishedAtUnixNano = snap.establishedAt.UnixNano()
		pbSession.UptimeNanos = time.Since(snap.establishedAt).Nanoseconds()
	}
	if includeStats {
		setupOK, setupFail := s.pce.PeerSetupStats(pcepSession.peerAddr)
		pbSession.Stats = toPBSessionStats(pcepSession.Stats(), setupOK, setupFail)
	}

	return pbSession
}

func (s *APIServer) buildPBSRPolicy(pcepSession *Session, policy *table.SRPolicy, routerIDIndex map[netip.Addr]string) *pb.SRPolicy {
	srPolicy := &pb.SRPolicy{
		PeerAddr:    pcepSession.peerAddr.AsSlice(),
		SegmentList: make([]*pb.Segment, 0, len(policy.SegmentList)),
		Color:       policy.Color,
		Preference:  policy.Preference,
		PolicyName:  policy.Name,
		SrcAddr:     policy.SrcAddr.AsSlice(),
		DstAddr:     policy.DstAddr.AsSlice(),
		PlspId:      policy.PlspID,
		LspId:       uint32(policy.LSPID),
		State:       toPBPolicyState(policy.State),
		Type:        toPBPolicyType(policy.Type),
		Metric:      toPBMetricType(policy.Metric),
	}

	srPolicy.SrcRouterId = routerIDIndex[policy.SrcAddr]
	srPolicy.DstRouterId = routerIDIndex[policy.DstAddr]

	for _, segment := range policy.SegmentList {
		srPolicy.SegmentList = append(srPolicy.SegmentList, convertSegment(segment))
	}

	return srPolicy
}

// buildPBSRPolicySession converts a Session and its SR Policies into the
// lightweight SRPolicySession representation returned by GetSRPolicyList.
func buildPBSRPolicySession(pcepSession *Session, policies []*pb.SRPolicy) *pb.SRPolicySession {
	snap := pcepSession.snapshot()
	return &pb.SRPolicySession{
		PeerAddr:   pcepSession.peerAddr.AsSlice(),
		State:      toPBSessionState(snap.state),
		SyncState:  toPBSyncState(snap.syncState),
		SrPolicies: policies,
	}
}

func toPBPolicyType(polType table.PolicyType) pb.SRPolicyType {
	switch polType {
	case table.PolicyTypeExplicit:
		return pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT
	case table.PolicyTypeDynamic:
		return pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC
	default:
		return pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED
	}
}

func toPBMetricType(metricType table.MetricType) pb.MetricType {
	switch metricType {
	case table.IGPMetric:
		return pb.MetricType_METRIC_TYPE_IGP
	case table.TEMetric:
		return pb.MetricType_METRIC_TYPE_TE
	case table.DelayMetric:
		return pb.MetricType_METRIC_TYPE_DELAY
	case table.HopcountMetric:
		return pb.MetricType_METRIC_TYPE_HOPCOUNT
	default:
		return pb.MetricType_METRIC_TYPE_UNSPECIFIED
	}
}

func toPBPolicyState(state table.PolicyState) pb.SRPolicyState {
	switch state {
	case table.PolicyDown:
		return pb.SRPolicyState_SR_POLICY_STATE_DOWN
	case table.PolicyUp:
		return pb.SRPolicyState_SR_POLICY_STATE_UP
	case table.PolicyActive:
		return pb.SRPolicyState_SR_POLICY_STATE_ACTIVE
	case table.PolicyUnknown:
		return pb.SRPolicyState_SR_POLICY_STATE_UNKNOWN
	default:
		return pb.SRPolicyState_SR_POLICY_STATE_UNSPECIFIED
	}
}

func convertSegment(seg table.Segment) *pb.Segment {
	pbSeg := &pb.Segment{Sid: seg.SidString()}
	switch v := seg.(type) {
	case table.SegmentSRv6:
		if v.LocalAddr.IsValid() {
			pbSeg.LocalAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			pbSeg.RemoteAddr = v.RemoteAddr.String()
		}
		if len(v.Structure) == 4 {
			pbSeg.SidStructure = fmt.Sprintf("%d,%d,%d,%d", v.Structure[0], v.Structure[1], v.Structure[2], v.Structure[3])
		}
	case table.SegmentSRMPLS:
		if v.LocalAddr.IsValid() {
			pbSeg.LocalAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			pbSeg.RemoteAddr = v.RemoteAddr.String()
		}
		pbSeg.SidAbsent = v.SidAbsent
	}
	return pbSeg
}

// convertLsNode converts a table.LsNode to a protobuf LsNode.
func convertLsNode(lsNode *table.LsNode, lg *logger.Logger) *pb.LsNode {
	if lsNode == nil {
		return nil
	}

	return &pb.LsNode{
		Asn:        lsNode.ASN,
		RouterId:   lsNode.RouterID,
		IsisAreaId: lsNode.IsisAreaID,
		Hostname:   lsNode.Hostname,
		SrgbBegin:  lsNode.SrgbBegin,
		SrgbEnd:    lsNode.SrgbEnd,
		Links:      convertLsLinks(lsNode.Links, lg),
		Prefixes:   convertLsPrefixes(lsNode.Prefixes),
		Srv6Sids:   convertLsSrv6SIDs(lsNode.SRv6SIDs),
	}
}

// convertLsLinks converts a slice of table.LsLink to protobuf LsLink.
func convertLsLinks(links []*table.LsLink, lg *logger.Logger) []*pb.LsLink {
	if links == nil {
		return nil
	}
	result := make([]*pb.LsLink, 0, len(links))
	for _, link := range links {
		if link == nil || link.LocalNode == nil || link.RemoteNode == nil {
			lg.Debug("skip link with nil node", logger.Any("link", link))
			continue
		}
		result = append(result, buildLsLink(link))
	}
	return result
}

// buildLsLink converts a single table.LsLink to protobuf LsLink.
func buildLsLink(link *table.LsLink) *pb.LsLink {
	localIP := link.LocalIP.String()
	remoteIP := link.RemoteIP.String()

	pbLink := &pb.LsLink{
		LocalRouterId:  link.LocalNode.RouterID,
		LocalAsn:       link.LocalNode.ASN,
		LocalIp:        localIP,
		RemoteRouterId: link.RemoteNode.RouterID,
		RemoteAsn:      link.RemoteNode.ASN,
		RemoteIp:       remoteIP,
		Metrics:        convertMetrics(link.Metrics),
		AdjSid:         link.AdjSid,
	}

	if link.Srv6EndXSID != nil {
		pbLink.Srv6EndXSid = convertSrv6EndXSID(link.Srv6EndXSID)
	}
	return pbLink
}

// convertMetrics converts a slice of table.Metric to protobuf Metric.
func convertMetrics(metrics []*table.Metric) []*pb.Metric {
	if metrics == nil {
		return nil
	}
	result := make([]*pb.Metric, 0, len(metrics))
	for _, m := range metrics {
		if m != nil {
			if mt, ok := pb.MetricType_value[m.Type.String()]; ok {
				result = append(result, &pb.Metric{Type: pb.MetricType(mt), Value: m.Value})
			}
		}
	}
	return result
}

// convertLsPrefixes converts a slice of table.LsPrefix to protobuf LsPrefix.
func convertLsPrefixes(prefixes []*table.LsPrefix) []*pb.LsPrefix {
	if prefixes == nil {
		return nil
	}
	result := make([]*pb.LsPrefix, 0, len(prefixes))
	for _, p := range prefixes {
		if p != nil {
			pbPrefix := &pb.LsPrefix{Prefix: p.Prefix.String()}
			// Preserve Prefix-SID presence, including index 0.
			if p.HasPrefixSID() {
				pbPrefix.SidIndex = new(p.SidIndex)
			}
			result = append(result, pbPrefix)
		}
	}
	return result
}

// convertLsSrv6SIDs converts a slice of table.LsSrv6SID to protobuf LsSrv6SID.
func convertLsSrv6SIDs(sids []*table.LsSrv6SID) []*pb.LsSrv6SID {
	if sids == nil {
		return nil
	}
	result := make([]*pb.LsSrv6SID, 0, len(sids))
	for _, s := range sids {
		if s != nil {
			result = append(result, buildLsSrv6SID(s))
		}
	}
	return result
}

// buildLsSrv6SID converts a single table.LsSrv6SID to protobuf LsSrv6SID.
func buildLsSrv6SID(s *table.LsSrv6SID) *pb.LsSrv6SID {
	pbSID := &pb.LsSrv6SID{
		Sids:         make([]*pb.SID, 0, len(s.Sids)),
		MultiTopoIds: make([]*pb.MultiTopoID, 0, len(s.MultiTopoIDs)),
		SidStructure: &pb.SidStructure{
			LocalBlock: uint32(s.SIDStructure.LocalBlock),
			LocalNode:  uint32(s.SIDStructure.LocalNode),
			LocalFunc:  uint32(s.SIDStructure.LocalFunc),
			LocalArg:   uint32(s.SIDStructure.LocalArg),
		},
	}

	for _, sid := range s.Sids {
		if sid != "" {
			pbSID.Sids = append(pbSID.Sids, &pb.SID{Sid: sid})
		}
	}

	for _, topoID := range s.MultiTopoIDs {
		pbSID.MultiTopoIds = append(pbSID.MultiTopoIds, &pb.MultiTopoID{MultiTopoId: topoID})
	}

	if s.EndpointBehavior != (table.EndpointBehavior{}) {
		pbSID.EndpointBehavior = &pb.EndpointBehavior{
			Behavior:  uint32(s.EndpointBehavior.Behavior),
			Flags:     uint32(s.EndpointBehavior.Flags),
			Algorithm: uint32(s.EndpointBehavior.Algorithm),
		}
	}

	return pbSID
}

// convertSrv6EndXSID converts table.Srv6EndXSID to protobuf Srv6EndXSID.
func convertSrv6EndXSID(sid *table.Srv6EndXSID) *pb.Srv6EndXSID {
	pbSID := &pb.Srv6EndXSID{
		EndpointBehavior: uint32(sid.EndpointBehavior),
		Sids:             make([]*pb.SID, 0, len(sid.Sids)),
		SidStructure: &pb.SidStructure{
			LocalBlock: uint32(sid.Srv6SIDStructure.LocalBlock),
			LocalNode:  uint32(sid.Srv6SIDStructure.LocalNode),
			LocalFunc:  uint32(sid.Srv6SIDStructure.LocalFunc),
			LocalArg:   uint32(sid.Srv6SIDStructure.LocalArg),
		},
	}

	for _, s := range sid.Sids {
		if s != "" {
			pbSID.Sids = append(pbSID.Sids, &pb.SID{Sid: s})
		}
	}

	return pbSID
}
