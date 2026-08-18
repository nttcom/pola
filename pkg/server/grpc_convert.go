// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"fmt"
	"net/netip"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

func buildCapability(cap pcep.CapabilityInterface) *pb.Capability {
	c := &pb.Capability{Type: capabilityType(cap.Type())}
	switch tlv := cap.(type) {
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
		c.Detail = &pb.Capability_Sr{Sr: &pb.SrCapability{
			UnlimitedMsd: tlv.HasUnlimitedMaxSIDDepth,
			NaiSupported: tlv.IsNAISupported,
			Msd:          uint32(tlv.MaximumSidDepth),
		}}
	case *pcep.SRv6PCECapability:
		c.Detail = &pb.Capability_Srv6{Srv6: &pb.Srv6Capability{
			NaiSupported: tlv.IsNAISupported,
		}}
	case *pcep.PathSetupTypeCapability:
		psts := make([]uint32, len(tlv.PathSetupTypes))
		for i, pst := range tlv.PathSetupTypes {
			psts[i] = uint32(pst)
		}
		c.Detail = &pb.Capability_PathSetupType{PathSetupType: &pb.PathSetupTypeCapability{
			PathSetupTypes: psts,
		}}
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

func (s *APIServer) buildPBSRPolicy(peerAddr netip.Addr, policy *table.SRPolicy, routerIDIndex map[netip.Addr]string) *pb.SRPolicy {
	srPolicy := &pb.SRPolicy{
		PcepSessionAddr: peerAddr.AsSlice(),
		SegmentList:     make([]*pb.Segment, 0, len(policy.SegmentList)),
		Color:           policy.Color,
		Preference:      policy.Preference,
		PolicyName:      policy.Name,
		SrcAddr:         policy.SrcAddr.AsSlice(),
		DstAddr:         policy.DstAddr.AsSlice(),
		PlspId:          policy.PlspID,
		LspId:           uint32(policy.LSPID),
		State:           toPBPolicyState(policy.State),
		Type:            toPBPolicyType(policy.Type),
		Metric:          toPBMetricType(policy.Metric),
	}

	srPolicy.SrcRouterId = routerIDIndex[policy.SrcAddr]
	srPolicy.DstRouterId = routerIDIndex[policy.DstAddr]

	for _, segment := range policy.SegmentList {
		srPolicy.SegmentList = append(srPolicy.SegmentList, convertSegment(segment))
	}

	return srPolicy
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
	}
	return pbSeg
}

// convertLsNode converts a table.LsNode to a protobuf LsNode.
func convertLsNode(lsNode *table.LsNode, logger *zap.Logger) *pb.LsNode {
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
		LsLinks:    convertLsLinks(lsNode.Links, logger),
		LsPrefixes: convertLsPrefixes(lsNode.Prefixes),
		LsSrv6Sids: convertLsSrv6SIDs(lsNode.SRv6SIDs),
	}
}

// convertLsLinks converts a slice of table.LsLink to protobuf LsLink.
func convertLsLinks(links []*table.LsLink, logger *zap.Logger) []*pb.LsLink {
	if links == nil {
		return nil
	}
	result := make([]*pb.LsLink, 0, len(links))
	for _, link := range links {
		if link == nil || link.LocalNode == nil || link.RemoteNode == nil {
			logger.Debug("skip link with nil node", zap.Any("link", link))
			continue
		}
		result = append(result, buildLsLink(link))
	}
	return result
}

// buildLsLink converts a single table.LsLink to protobuf LsLink.
func buildLsLink(link *table.LsLink) *pb.LsLink {
	localIP, _ := link.LocalIP.MarshalText()
	remoteIP, _ := link.RemoteIP.MarshalText()

	pbLink := &pb.LsLink{
		LocalRouterId:  link.LocalNode.RouterID,
		LocalAsn:       link.LocalNode.ASN,
		LocalIp:        string(localIP),
		RemoteRouterId: link.RemoteNode.RouterID,
		RemoteAsn:      link.RemoteNode.ASN,
		RemoteIp:       string(remoteIP),
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
				pbPrefix.SidIndex = proto.Uint32(p.SidIndex)
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
