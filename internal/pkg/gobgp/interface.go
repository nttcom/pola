// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package gobgp

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"strings"

	"github.com/golang/protobuf/ptypes/any"
	"github.com/nttcom/pola/internal/pkg/table"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
)

type GobgpOptions struct {
	GobgpAddr string
	GobgpPort string
}

func GetBgplsNlris(serverAddr string, serverPort string) ([]table.TedElem, error) {
	gobgpAddress := serverAddr + ":" + serverPort

	// Get connection
	cc, err := grpc.NewClient(
		gobgpAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	defer cc.Close()

	// Create gRPC client
	client := api.NewGobgpApiClient(cc)
	ctx := context.Background()

	req := &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_LS,
			Safi: api.Family_SAFI_LS,
		},
		Name:     "",
		SortType: api.ListPathRequest_PREFIX,
	}
	stream, err := client.ListPath(ctx, req)
	if err != nil {
		return nil, err
	}

	var tedElems []table.TedElem
	for {
		r, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		convertedElems, err := ConvertToTedElem(r.Destination)
		if err != nil {
			return nil, err
		}

		tedElems = append(tedElems, convertedElems...)
	}
	return tedElems, nil
}

func ConvertToTedElem(dst *api.Destination) ([]table.TedElem, error) {
	if len(dst.GetPaths()) != 1 {
		return nil, errors.New("invalid path length")
	}

	path := dst.GetPaths()[0]
	nlri, err := path.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, err
	}

	switch nlri := nlri.(type) {
	case *api.LsAddrPrefix:
		linkStateNlri, err := nlri.GetNlri().UnmarshalNew()
		if err != nil {
			return nil, err
		}

		switch linkStateNlri := linkStateNlri.(type) {
		case *api.LsNodeNLRI:
			lsNode, err := getLsNodeNLRI(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, err
			}
			return []table.TedElem{lsNode}, nil
		case *api.LsLinkNLRI:
			lsLink, err := getLsLinkNLRI(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, err
			}
			return []table.TedElem{lsLink}, nil
		case *api.LsPrefixV4NLRI:
			lsPrefixV4List, err := getLsPrefixV4List(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, err
			}
			return lsPrefixV4List, nil
		// Add case for LsPrefixV6NLRI
		case *api.LsPrefixV6NLRI:
			lsPrefixV6List, err := getLsPrefixV6List(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, err
			}
			return lsPrefixV6List, nil
		// Add case for LsSrv6SIDNLRI
		case *api.LsSrv6SIDNLRI:
			lsSrv6SID, err := getLsSrv6SIDNLRI(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, err
			}
			return []table.TedElem{lsSrv6SID}, nil
		default:
			return nil, errors.New("invalid linkStateNlri type")
		}
	default:
		return nil, errors.New("invalid nlri type")
	}
}

func getLsNodeNLRI(typedLinkStateNlri *api.LsNodeNLRI, pathAttrs []*anypb.Any) (*table.LsNode, error) {
	asn := typedLinkStateNlri.GetLocalNode().GetAsn()
	routerID := typedLinkStateNlri.GetLocalNode().GetIgpRouterId()

	lsNode := table.NewLsNode(asn, routerID)

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, err
		}

		bgplsAttr, ok := typedPathAttr.(*api.LsAttribute)
		if !ok {
			continue
		}

		isisArea := bgplsAttr.GetNode().GetIsisArea()
		tmpIsisArea := hex.EncodeToString(isisArea)
		strIsisArea := ""
		for i, s := range strings.Split(tmpIsisArea, "") {
			if (len(tmpIsisArea)-i)%4 == 0 {
				strIsisArea += "."
			}
			strIsisArea += s
		}
		lsNode.IsisAreaID = strIsisArea
		lsNode.Hostname = bgplsAttr.GetNode().GetName()

		srCapabilities := bgplsAttr.GetNode().GetSrCapabilities().GetRanges()
		if len(srCapabilities) != 1 {
			return nil, errors.New("invalid SR Capability TLV")
		}
		lsNode.SrgbBegin = srCapabilities[0].GetBegin()
		lsNode.SrgbEnd = srCapabilities[0].GetEnd()
	}

	return lsNode, nil
}

func getLsLinkNLRI(typedLinkStateNlri *api.LsLinkNLRI, pathAttrs []*anypb.Any) (*table.LsLink, error) {
	localNode := table.NewLsNode(typedLinkStateNlri.GetLocalNode().GetAsn(), typedLinkStateNlri.GetLocalNode().GetIgpRouterId())
	remoteNode := table.NewLsNode(typedLinkStateNlri.GetRemoteNode().GetAsn(), typedLinkStateNlri.GetRemoteNode().GetIgpRouterId())

	localIP, err := netip.ParseAddr(typedLinkStateNlri.GetLinkDescriptor().GetInterfaceAddrIpv4())
	if err != nil {
		return nil, err
	}

	remoteIP, err := netip.ParseAddr(typedLinkStateNlri.GetLinkDescriptor().GetNeighborAddrIpv4())
	if err != nil {
		return nil, err
	}

	lsLink := table.NewLsLink(localNode, remoteNode)
	lsLink.LocalIP = localIP
	lsLink.RemoteIP = remoteIP

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, err
		}

		bgplsAttr, ok := typedPathAttr.(*api.LsAttribute)
		if !ok {
			continue
		}

		lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.IGP_METRIC), bgplsAttr.GetLink().GetIgpMetric()))

		teMetric := bgplsAttr.GetLink().GetDefaultTeMetric()
		if teMetric != 0 {
			lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.TE_METRIC), teMetric))
		}

		lsLink.AdjSid = bgplsAttr.GetLink().GetSrAdjacencySid()
	}

	return lsLink, nil
}

func getLsPrefixV4List(lsPrefixV4Nlri *api.LsPrefixV4NLRI, pathAttrs []*any.Any) ([]table.TedElem, error) {
	var lsPrefixV4List []table.TedElem
	var sidIndex uint32

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, err
		}

		switch typedPathAttr := typedPathAttr.(type) {
		case *api.LsAttribute:
			sidIndex = typedPathAttr.GetPrefix().GetSrPrefixSid()

		case *api.MpReachNLRIAttribute:
			for _, nlri := range typedPathAttr.GetNlris() {
				typedNlri, err := nlri.UnmarshalNew()
				if err != nil {
					return nil, err
				}

				if lsNlri, ok := typedNlri.(*api.LsAddrPrefix); ok {
					lsPrefixV4, err := getLsPrefixV4(lsNlri, sidIndex)
					if err != nil {
						return nil, err
					}
					lsPrefixV4List = append(lsPrefixV4List, lsPrefixV4)
				}
			}
		}
	}

	return lsPrefixV4List, nil
}

func getLsPrefixV4(lsNlri *api.LsAddrPrefix, sidIndex uint32) (*table.LsPrefixV4, error) {
	prefNlri, err := lsNlri.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, err
	}
	prefv4Nlri, ok := prefNlri.(*api.LsPrefixV4NLRI)
	if !ok {
		return nil, errors.New("invalid LS prefix v4 NLRI type")
	}
	localNodeID := prefv4Nlri.GetLocalNode().GetIgpRouterId()
	localNodeAsn := prefv4Nlri.GetLocalNode().GetAsn()
	prefixV4 := prefv4Nlri.GetPrefixDescriptor().GetIpReachability()

	localNode := table.NewLsNode(localNodeAsn, localNodeID)
	lsPrefixV4 := table.NewLsPrefixV4(localNode)
	lsPrefixV4.SidIndex = sidIndex
	if len(prefixV4) != 1 {
		return nil, errors.New("invalid prefix length")
	}
	lsPrefixV4.Prefix, err = netip.ParsePrefix(prefixV4[0])
	if err != nil {
		return nil, err
	}

	return lsPrefixV4, nil
}

// Add function to get LsPrefixV6NLRI
func getLsPrefixV6List(lsPrefixV6Nlri *api.LsPrefixV6NLRI, pathAttrs []*any.Any) ([]table.TedElem, error) {
	var lsPrefixV6List []table.TedElem
	var sidIndex uint32

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, err
		}

		switch typedPathAttr := typedPathAttr.(type) {
		case *api.IPv6AddressSpecificExtended:
			sidIndex = typedPathAttr.GetSubType()

		case *api.MpReachNLRIAttribute:
			for _, nlri := range typedPathAttr.GetNlris() {
				typedNlri, err := nlri.UnmarshalNew()
				if err != nil {
					return nil, err
				}

				if lsNlri, ok := typedNlri.(*api.LsAddrPrefix); ok {
					lsPrefixV6, err := getLsPrefixV6(lsNlri, sidIndex)
					if err != nil {
						return nil, err
					}
					lsPrefixV6List = append(lsPrefixV6List, lsPrefixV6)
				}
			}
		}
	}

	return lsPrefixV6List, nil
}

func getLsPrefixV6(lsNlri *api.LsAddrPrefix, sidIndex uint32) (*table.LsPrefixV6, error) {
	prefNlri, err := lsNlri.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, err
	}
	prefv6Nlri, ok := prefNlri.(*api.LsPrefixV6NLRI)
	if !ok {
		return nil, errors.New("invalid LS prefix v6 NLRI type")
	}
	localNodeID := prefv6Nlri.GetLocalNode().GetIgpRouterId()
	localNodeAsn := prefv6Nlri.GetLocalNode().GetAsn()
	prefixV6 := prefv6Nlri.GetPrefixDescriptor().GetIpReachability()

	localNode := table.NewLsNode(localNodeAsn, localNodeID)
	lsPrefixV6 := table.NewLsPrefixV6(localNode)
	lsPrefixV6.SidIndex = sidIndex
	if len(prefixV6) != 1 {
		return nil, errors.New("invalid prefix length")
	}
	lsPrefixV6.Prefix, err = netip.ParsePrefix(prefixV6[0])
	if err != nil {
		return nil, err
	}

	return lsPrefixV6, nil
}

// Add function to get LsSrv6SIDNLRI
func getLsSrv6SIDNLRI(typedLinkStateNlri *api.LsSrv6SIDNLRI, pathAttrs []*anypb.Any) (*table.LsSrv6SID, error) {
	localNode := table.NewLsNode(typedLinkStateNlri.GetLocalNode().GetAsn(), typedLinkStateNlri.GetLocalNode().GetIgpRouterId())
	lsSrv6SID := table.NewLsSrv6SID(localNode)

	lsSrv6SID.Sids = typedLinkStateNlri.GetSrv6SidInformation().GetSids()
	lsSrv6SID.MultiTopoIDs = typedLinkStateNlri.GetMultiTopoId().GetMultiTopoIds()
	lsSrv6SID.ServiceType = typedLinkStateNlri.GetServiceChaining().GetServicetype()
	lsSrv6SID.TrafficType = typedLinkStateNlri.GetServiceChaining().GetTraffictype()
	lsSrv6SID.OpaqueType = typedLinkStateNlri.GetOpaqueMetadata().GetOpaquetype()
	lsSrv6SID.Value = typedLinkStateNlri.GetOpaqueMetadata().GetValue()

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, err
		}

		if endpointBehavior, ok := typedPathAttr.(*api.SRv6EndPointBehavior); ok {
			lsSrv6SID.EndpointBehavior = uint32(endpointBehavior.GetBehavior())
		}
	}
	return lsSrv6SID, nil
}
