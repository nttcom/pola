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
	"strings"

	"github.com/nttcom/pola/internal/pkg/table"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
)

func GetBgplsNlris(serverAddr string, serverPort string) ([]table.TedElem, error) {
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
	client := api.NewGobgpApiClient(cc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		return nil, fmt.Errorf("failed to retrieve paths from gRPC server: %w", err)
	}

	var tedElems []table.TedElem
	for {
		r, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error receiving stream data: %w", err)
		}

		convertedElems, err := ConvertToTedElem(r.Destination)
		if err != nil {
			return nil, fmt.Errorf("failed to convert path to TED element (destination: %v): %w", r.Destination, err)
		}

		tedElems = append(tedElems, convertedElems...)
	}

	return tedElems, nil
}

func ConvertToTedElem(dst *api.Destination) ([]table.TedElem, error) {
	if len(dst.GetPaths()) != 1 {
		return nil, errors.New("invalid path length: expected 1 path")
	}

	path := dst.GetPaths()[0]
	nlri, err := path.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NLRI: %w", err)
	}

	switch nlri := nlri.(type) {
	case *api.LsAddrPrefix:
		linkStateNlri, err := nlri.GetNlri().UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal LS Address Prefix: %w", err)
		}

		switch linkStateNlri := linkStateNlri.(type) {
		case *api.LsNodeNLRI:
			lsNode, err := getLsNodeNLRI(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Node NLRI: %w", err)
			}
			return []table.TedElem{lsNode}, nil
		case *api.LsLinkNLRI:
			lsLink, err := getLsLinkNLRI(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Link NLRI: %w", err)
			}
			return []table.TedElem{lsLink}, nil
		case *api.LsPrefixV4NLRI:
			lsPrefixV4List, err := getLsPrefixV4List(path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Prefix V4 NLRI: %w", err)
			}
			return lsPrefixV4List, nil
		case *api.LsSrv6SIDNLRI:
			lsSrv6SIDList, err := getLsSrv6SIDNLRIList(path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
			}
			return lsSrv6SIDList, nil
		case *api.LsPrefixV6NLRI:
			return nil, nil // TODO: Implement LsPrefixV6NLRI handling
		default:
			return nil, fmt.Errorf("invalid LS Link State NLRI type: %T", linkStateNlri)
		}
	default:
		return nil, fmt.Errorf("invalid NLRI type: %T", nlri)
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

func getLsNodeNLRI(typedLinkStateNlri *api.LsNodeNLRI, pathAttrs []*anypb.Any) (*table.LsNode, error) {
	asn := typedLinkStateNlri.GetLocalNode().GetAsn()
	routerID := typedLinkStateNlri.GetLocalNode().GetIgpRouterId()

	lsNode := table.NewLsNode(asn, routerID)

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %w", err)
		}

		bgplsAttr, ok := typedPathAttr.(*api.LsAttribute)
		if !ok {
			continue
		}

		isisArea := bgplsAttr.GetNode().GetIsisArea()
		lsNode.IsisAreaID = formatIsisAreaID(isisArea)
		lsNode.Hostname = bgplsAttr.GetNode().GetName()
		srCapabilities := bgplsAttr.GetNode().GetSrCapabilities().GetRanges()
		if len(srCapabilities) != 1 {
			return nil, fmt.Errorf("expected 1 SR Capability TLV, got: %d", len(srCapabilities))
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
		return nil, fmt.Errorf("failed to parse local IP address %q: %v", typedLinkStateNlri.GetLinkDescriptor().GetInterfaceAddrIpv4(), err)
	}

	remoteIP, err := netip.ParseAddr(typedLinkStateNlri.GetLinkDescriptor().GetNeighborAddrIpv4())
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote IP address %q: %v", typedLinkStateNlri.GetLinkDescriptor().GetNeighborAddrIpv4(), err)
	}

	lsLink := table.NewLsLink(localNode, remoteNode)
	lsLink.LocalIP = localIP
	lsLink.RemoteIP = remoteIP

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute %v: %v", pathAttr, err)
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

func getLsPrefixV4List(pathAttrs []*anypb.Any) ([]table.TedElem, error) {
	var lsPrefixV4List []table.TedElem
	var sidIndex uint32

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %w", err)
		}

		switch typedPathAttr := typedPathAttr.(type) {
		case *api.LsAttribute:
			sidIndex = typedPathAttr.GetPrefix().GetSrPrefixSid()

		case *api.MpReachNLRIAttribute:
			for _, nlri := range typedPathAttr.GetNlris() {
				typedNlri, err := nlri.UnmarshalNew()
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal NLRI: %w", err)
				}

				if lsNlri, ok := typedNlri.(*api.LsAddrPrefix); ok {
					lsPrefixV4, err := getLsPrefixV4(lsNlri, sidIndex)
					if err != nil {
						return nil, fmt.Errorf("failed to get LS Prefix V4: %w", err)
					}
					lsPrefixV4List = append(lsPrefixV4List, lsPrefixV4)
				} else {
					return nil, fmt.Errorf("unexpected NLRI type: %T", typedNlri)
				}
			}
		}
	}

	return lsPrefixV4List, nil
}

func getLsPrefixV4(lsNlri *api.LsAddrPrefix, sidIndex uint32) (*table.LsPrefixV4, error) {
	prefNlri, err := lsNlri.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LS Prefix V4: %w", err)
	}
	prefv4Nlri, ok := prefNlri.(*api.LsPrefixV4NLRI)
	if !ok {
		return nil, fmt.Errorf("invalid LS prefix v4 NLRI type: %T", prefNlri)
	}

	localNodeID := prefv4Nlri.GetLocalNode().GetIgpRouterId()
	localNodeAsn := prefv4Nlri.GetLocalNode().GetAsn()
	prefixV4 := prefv4Nlri.GetPrefixDescriptor().GetIpReachability()

	localNode := table.NewLsNode(localNodeAsn, localNodeID)
	lsPrefixV4 := table.NewLsPrefixV4(localNode)
	lsPrefixV4.SidIndex = sidIndex

	if len(prefixV4) != 1 {
		return nil, fmt.Errorf("invalid prefix length: expected 1, got %d", len(prefixV4))
	}

	lsPrefixV4.Prefix, err = netip.ParsePrefix(prefixV4[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse prefix %q: %w", prefixV4[0], err)
	}

	return lsPrefixV4, nil
}

func getLsSrv6SIDNLRIList(pathAttrs []*anypb.Any) ([]table.TedElem, error) {
	var lsSrv6SIDList []table.TedElem
	var endpointBehavior uint32

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %w", err)
		}

		switch typedPathAttr := typedPathAttr.(type) {
		case *api.SRv6EndPointBehavior:
			endpointBehavior = uint32(typedPathAttr.GetBehavior())
		case *api.MpReachNLRIAttribute:
			for _, nlri := range typedPathAttr.GetNlris() {
				typedNlri, err := nlri.UnmarshalNew()
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal NLRI: %w", err)
				}
				if lsNlri, ok := typedNlri.(*api.LsAddrPrefix); ok {
					lsSrv6SID, err := getLsSrv6SIDNLRI(lsNlri, endpointBehavior)
					if err != nil {
						return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
					}
					lsSrv6SIDList = append(lsSrv6SIDList, lsSrv6SID)
				} else {
					return nil, fmt.Errorf("unexpected NLRI type: %T", typedNlri)
				}
			}
		}
	}
	return lsSrv6SIDList, nil
}

func getLsSrv6SIDNLRI(lsNlri *api.LsAddrPrefix, endpointBehavior uint32) (*table.LsSrv6SID, error) {
	srv6Nlri, err := lsNlri.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LS NLRI: %w", err)
	}
	srv6SIDNlri, ok := srv6Nlri.(*api.LsSrv6SIDNLRI)
	if !ok {
		return nil, fmt.Errorf("invalid LS SRv6 SID NLRI type: %T", srv6Nlri)
	}
	localNodeID := srv6SIDNlri.GetLocalNode().GetIgpRouterId()
	localNodeAsn := srv6SIDNlri.GetLocalNode().GetAsn()
	srv6SIDs := srv6SIDNlri.GetSrv6SidInformation().GetSids()
	multiTopoIDs := srv6SIDNlri.GetMultiTopoId().GetMultiTopoIds()

	localNode := table.NewLsNode(localNodeAsn, localNodeID)
	lsSrv6SID := table.NewLsSrv6SID(localNode)
	lsSrv6SID.EndpointBehavior = endpointBehavior
	lsSrv6SID.Sids = srv6SIDs
	lsSrv6SID.MultiTopoIDs = multiTopoIDs

	return lsSrv6SID, nil
}
