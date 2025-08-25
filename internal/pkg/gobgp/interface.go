// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package gobgp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"strings"

	"github.com/nttcom/pola/internal/pkg/table"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func GetBGPlsNLRIs(serverAddr string, serverPort string) ([]table.TEDElem, error) {
	gobgpAddress := fmt.Sprintf("%s:%s", serverAddr, serverPort)

	// Establish gRPC connection
	cc, err := grpc.NewClient(
		gobgpAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client (address: %s): %w", gobgpAddress, err)
	}
	defer func() {
		if err := cc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to close gRPC client connection: %v\n", err)
		}
	}()

	// Create gRPC client
	client := api.NewGoBgpServiceClient(cc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_LS,
			Safi: api.Family_SAFI_LS,
		},
		Name:     "",
		SortType: api.ListPathRequest_SORT_TYPE_PREFIX,
	}

	stream, err := client.ListPath(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve paths from gRPC server: %w", err)
	}

	var tedElems []table.TEDElem
	for {
		r, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error receiving stream data: %w", err)
		}

		convertedElems, err := ConvertToTEDElem(r.Destination)
		if err != nil {
			return nil, fmt.Errorf("failed to convert path to TED element (destination: %v): %w", r.Destination, err)
		}

		tedElems = append(tedElems, convertedElems...)
	}

	return tedElems, nil
}

func ConvertToTEDElem(dst *api.Destination) ([]table.TEDElem, error) {
	if len(dst.GetPaths()) != 1 {
		return nil, errors.New("invalid path length: expected 1 path")
	}

	path := dst.GetPaths()[0]
	nlri := path.GetNlri()
	if nlri == nil {
		return nil, errors.New("NLRI is nil")
	}

	switch nlriType := nlri.GetNlri().(type) {
	case *api.NLRI_LsAddrPrefix:
		switch linkStateNLRI := nlriType.LsAddrPrefix.Nlri.GetNlri().(type) {
		case *api.LsAddrPrefix_LsNLRI_Node:
			lsNode, err := getLsNodeNLRI(linkStateNLRI.Node, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Node NLRI: %w", err)
			}
			return []table.TEDElem{lsNode}, nil
		case *api.LsAddrPrefix_LsNLRI_Link:
			lsLink, err := getLsLinkNLRI(linkStateNLRI.Link, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Link NLRI: %w", err)
			}
			return []table.TEDElem{lsLink}, nil
		case *api.LsAddrPrefix_LsNLRI_PrefixV4, *api.LsAddrPrefix_LsNLRI_PrefixV6:
			lsPrefixList, err := getLsPrefixList(path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Prefix V4 NLRI: %w", err)
			}
			return lsPrefixList, nil
		case *api.LsAddrPrefix_LsNLRI_Srv6Sid:
			lsSrv6SIDList, err := getLsSrv6SIDNLRIList(path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
			}
			return lsSrv6SIDList, nil
		default:
			return nil, fmt.Errorf("invalid LS Link State NLRI type: %T", linkStateNLRI)
		}
	default:
		return nil, fmt.Errorf("invalid NLRI type: %T", nlriType)
	}
}

// formatIsisAreaID formats the ISIS Area ID into a human-readable string.
func formatIsisAreaID(isisArea []byte) string {
	tmpIsisArea := hex.EncodeToString(isisArea)
	var strIsisArea strings.Builder
	for i, s := range strings.Split(tmpIsisArea, "") {
		if (len(tmpIsisArea)-i)%4 == 0 && i != 0 {
			strIsisArea.WriteString(".")
		}
		strIsisArea.WriteString(s)
	}
	return strIsisArea.String()
}

func getLsNodeNLRI(typedLinkStateNLRI *api.LsNodeNLRI, pathAttrs []*api.Attribute) (*table.LsNode, error) {
	asn := typedLinkStateNLRI.GetLocalNode().GetAsn()
	routerID := typedLinkStateNLRI.GetLocalNode().GetIgpRouterId()

	lsNode := table.NewLsNode(asn, routerID)

	for _, pathAttr := range pathAttrs {
		switch bgplsAttr := pathAttr.Attr.(type) {
		case *api.Attribute_Ls:
			isisArea := bgplsAttr.Ls.Node.GetIsisArea()
			lsNode.IsisAreaID = formatIsisAreaID(isisArea)
			lsNode.Hostname = bgplsAttr.Ls.Node.GetName()
			if bgplsAttr.Ls.Node.GetSrCapabilities() != nil {
				srCapabilities := bgplsAttr.Ls.Node.GetSrCapabilities().GetRanges()
				if len(srCapabilities) != 1 {
					return nil, fmt.Errorf("expected 1 SR Capability TLV, got: %d", len(srCapabilities))
				} else {
					lsNode.SrgbBegin = srCapabilities[0].GetBegin()
					lsNode.SrgbEnd = srCapabilities[0].GetEnd()
				}
			}
		default:
			continue
		}

	}

	return lsNode, nil
}

func getLsLinkNLRI(typedLinkStateNLRI *api.LsLinkNLRI, pathAttrs []*api.Attribute) (*table.LsLink, error) {
	localNode := table.NewLsNode(typedLinkStateNLRI.GetLocalNode().GetAsn(), typedLinkStateNLRI.GetLocalNode().GetIgpRouterId())
	remoteNode := table.NewLsNode(typedLinkStateNLRI.GetRemoteNode().GetAsn(), typedLinkStateNLRI.GetRemoteNode().GetIgpRouterId())

	var err error
	var localIP netip.Addr
	if typedLinkStateNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4() != "" {
		localIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv4 address: %v", err)
		}
	} else if typedLinkStateNLRI.GetLinkDescriptor().GetInterfaceAddrIpv6() != "" {
		localIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetInterfaceAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv6 address: %v", err)
		}
	} else {
		localIP = netip.Addr{}
	}

	var remoteIP netip.Addr
	if typedLinkStateNLRI.GetLinkDescriptor().GetNeighborAddrIpv4() != "" {
		remoteIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetNeighborAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv4 address: %v", err)
		}
	} else if typedLinkStateNLRI.GetLinkDescriptor().GetNeighborAddrIpv6() != "" {
		remoteIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetNeighborAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv6 address: %v", err)
		}
	} else {
		remoteIP = netip.Addr{}
	}

	lsLink := table.NewLsLink(localNode, remoteNode)
	lsLink.LocalIP = localIP
	lsLink.RemoteIP = remoteIP

	for _, pathAttr := range pathAttrs {
		switch bgplsAttr := pathAttr.Attr.(type) {
		case *api.Attribute_Ls:
			lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.IGPMetric), bgplsAttr.Ls.Link.GetIgpMetric()))

			teMetric := bgplsAttr.Ls.Link.GetDefaultTeMetric()
			if teMetric != 0 {
				lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.TEMetric), teMetric))
			}

			lsLink.AdjSid = bgplsAttr.Ls.Link.GetSrAdjacencySid()

			// handle SRv6 SID TLV
			var srv6EndXSID *api.LsSrv6EndXSID
			srv6EndXSID = bgplsAttr.Ls.Link.GetSrv6EndXSid()
			if srv6EndXSID != nil {
				lsLink.Srv6EndXSID = &table.Srv6EndXSID{
					EndpointBehavior: uint16(srv6EndXSID.EndpointBehavior),
					Sids:             srv6EndXSID.Sids,
					Srv6SIDStructure: table.SIDStructure{
						LocalBlock: uint8(srv6EndXSID.Srv6SidStructure.GetLocalBlock()),
						LocalNode:  uint8(srv6EndXSID.Srv6SidStructure.GetLocalNode()),
						LocalFunc:  uint8(srv6EndXSID.Srv6SidStructure.GetLocalFunc()),
						LocalArg:   uint8(srv6EndXSID.Srv6SidStructure.GetLocalArg()),
					},
				}
			}
		default:
			continue
		}
	}

	return lsLink, nil
}

func getLsPrefixList(pathAttrs []*api.Attribute) ([]table.TEDElem, error) {
	var lsPrefixList []table.TEDElem
	var sidIndex uint32

	for _, pathAttr := range pathAttrs {
		switch bgplsAttr := pathAttr.Attr.(type) {
		case *api.Attribute_Ls:
			if bgplsAttr.Ls.GetPrefix().GetSrPrefixSid() != 0 {
				sidIndex = bgplsAttr.Ls.GetPrefix().GetSrPrefixSid()
			} else {
				sidIndex = 0
			}
		case *api.Attribute_MpReach:
			for _, nlri := range bgplsAttr.MpReach.GetNlris() {
				switch nlriType := nlri.GetNlri().(type) {
				case *api.NLRI_LsAddrPrefix:
					lsPrefix, err := getLsPrefix(nlri.GetLsAddrPrefix(), sidIndex)
					if err != nil {
						return nil, fmt.Errorf("failed to get LS Prefix: %v", err)
					}
					lsPrefixList = append(lsPrefixList, lsPrefix)
				default:
					return nil, fmt.Errorf("unexpected NLRI type: %T", nlriType)
				}
			}
		}
	}

	return lsPrefixList, nil
}

func getLsPrefix(lsNlri *api.LsAddrPrefix, sidIndex uint32) (*table.LsPrefix, error) {
	var localNodeID string
	var localNodeAsn uint32
	var prefix []string

	switch prefNlri := lsNlri.Nlri.Nlri.(type) {
	case *api.LsAddrPrefix_LsNLRI_PrefixV4:
		localNodeID = prefNlri.PrefixV4.GetLocalNode().GetIgpRouterId()
		localNodeAsn = prefNlri.PrefixV4.GetLocalNode().GetAsn()
		prefix = prefNlri.PrefixV4.GetPrefixDescriptor().GetIpReachability()
	case *api.LsAddrPrefix_LsNLRI_PrefixV6:
		localNodeID = prefNlri.PrefixV6.GetLocalNode().GetIgpRouterId()
		localNodeAsn = prefNlri.PrefixV6.GetLocalNode().GetAsn()
		prefix = prefNlri.PrefixV6.GetPrefixDescriptor().GetIpReachability()
	default:
		return nil, errors.New("invalid LS prefix NLRI type")
	}

	localNode := table.NewLsNode(localNodeAsn, localNodeID)
	lsPrefix := table.NewLsPrefix(localNode)
	lsPrefix.SidIndex = sidIndex

	if len(prefix) != 1 {
		return nil, errors.New("invalid prefix length: expected 1 prefix")
	}

	var err error
	lsPrefix.Prefix, err = netip.ParsePrefix(prefix[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse prefix: %v", err)
	}

	return lsPrefix, nil
}

func getLsSrv6SIDNLRIList(pathAttrs []*api.Attribute) ([]table.TEDElem, error) {
	var lsSrv6SIDList []table.TEDElem
	var endpointBehavior *api.LsSrv6EndpointBehavior
	var srv6SIDStructure *api.LsSrv6SIDStructure

	for _, pathAttr := range pathAttrs {
		switch attr := pathAttr.Attr.(type) {
		case *api.Attribute_Ls:
			srv6SIDStructure = attr.Ls.GetSrv6Sid().GetSrv6SidStructure()
			endpointBehavior = attr.Ls.GetSrv6Sid().GetSrv6EndpointBehavior()
		case *api.Attribute_MpReach:
			for _, nlri := range attr.MpReach.GetNlris() {
				switch nlriType := nlri.GetNlri().(type) {
				case *api.NLRI_LsAddrPrefix:
					lsSrv6SID, err := getLsSrv6SIDNLRI(nlri.GetLsAddrPrefix().Nlri.GetSrv6Sid(), endpointBehavior, srv6SIDStructure)
					if err != nil {
						return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
					}
					lsSrv6SIDList = append(lsSrv6SIDList, lsSrv6SID)
				default:
					return nil, fmt.Errorf("unexpected NLRI type: %T", nlriType)
				}
			}
		}
	}
	return lsSrv6SIDList, nil
}

// extractField retrieves a field by its name using reflection and returns its value.
func extractField(v any, fieldName string) reflect.Value {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer && val.IsNil() {
		return reflect.Value{}
	}
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}
	field := val.FieldByName(fieldName)
	if !field.IsValid() {
		return reflect.Value{}
	}
	return field
}

// extractMethodValue extracts the method's return value using reflection.
func extractMethodValue(val reflect.Value, methodName string) (any, error) {
	method := val.MethodByName(methodName)
	if !method.IsValid() {
		return nil, fmt.Errorf("method %s not found or invalid", methodName)
	}
	res := method.Call(nil)
	if len(res) != 1 {
		return nil, fmt.Errorf("method %s returned unexpected number of results", methodName)
	}
	return res[0].Interface(), nil
}

// getLsSrv6SIDNLRI processes the LS SRv6 SID NLRI and returns a corresponding LsSrv6SID.
func getLsSrv6SIDNLRI(srv6SIDNLRI *api.LsSrv6SIDNLRI, endpointBehavior *api.LsSrv6EndpointBehavior, srv6SIDStructure *api.LsSrv6SIDStructure) (*table.LsSrv6SID, error) {
	localNodeID := srv6SIDNLRI.GetLocalNode().GetIgpRouterId()
	localNodeASN := srv6SIDNLRI.GetLocalNode().GetAsn()
	srv6SIDs := srv6SIDNLRI.GetSrv6SidInformation().GetSids()
	multiTopoIDs := srv6SIDNLRI.GetMultiTopoId().GetMultiTopoIds()

	// Reflect processing for draft-ietf-idr-bgp-ls-sr-service-segments until merged into GoBGP master.
	var serviceType, trafficType, opaqueType uint32
	var value []byte
	if scVal := extractField(srv6SIDNLRI, "ServiceChaining"); scVal.IsValid() {
		if st, err := extractMethodValue(scVal, "GetServicetype"); err == nil {
			if stVal, ok := st.(uint32); ok {
				serviceType = stVal
			}
		} else {
			return nil, fmt.Errorf("failed to extract ServiceType: %w", err)
		}
		if tt, err := extractMethodValue(scVal, "GetTraffictype"); err == nil {
			if ttVal, ok := tt.(uint32); ok {
				trafficType = ttVal
			}
		} else {
			return nil, fmt.Errorf("failed to extract TrafficType: %w", err)
		}
	}
	if omVal := extractField(srv6SIDNLRI, "OpaqueMetadata"); omVal.IsValid() {
		if ot, err := extractMethodValue(omVal, "GetOpaquetype"); err == nil {
			if otVal, ok := ot.(uint32); ok {
				opaqueType = otVal
			}
		} else {
			return nil, fmt.Errorf("failed to extract OpaqueType: %w", err)
		}
		if val, err := extractMethodValue(omVal, "GetValue"); err == nil {
			if v, ok := val.([]byte); ok {
				value = v
			}
		} else {
			return nil, fmt.Errorf("failed to extract Value: %w", err)
		}
	}

	localNode := table.NewLsNode(localNodeASN, localNodeID)
	lsSrv6SID := table.NewLsSrv6SID(localNode)
	lsSrv6SID.SIDStructure.LocalBlock = uint8(srv6SIDStructure.GetLocalBlock())
	lsSrv6SID.SIDStructure.LocalNode = uint8(srv6SIDStructure.GetLocalNode())
	lsSrv6SID.SIDStructure.LocalFunc = uint8(srv6SIDStructure.GetLocalFunc())
	lsSrv6SID.SIDStructure.LocalArg = uint8(srv6SIDStructure.GetLocalArg())
	lsSrv6SID.EndpointBehavior.Behavior = uint16(endpointBehavior.GetEndpointBehavior())
	lsSrv6SID.EndpointBehavior.Flags = uint8(endpointBehavior.GetFlags())
	lsSrv6SID.EndpointBehavior.Algorithm = uint8(endpointBehavior.GetAlgorithm())
	lsSrv6SID.Sids = srv6SIDs
	lsSrv6SID.MultiTopoIDs = multiTopoIDs
	lsSrv6SID.ServiceType = serviceType
	lsSrv6SID.TrafficType = trafficType
	lsSrv6SID.OpaqueType = opaqueType
	lsSrv6SID.Value = value

	return lsSrv6SID, nil
}
