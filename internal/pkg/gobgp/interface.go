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
	nlri, err := path.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NLRI: %w", err)
	}

	switch nlri := nlri.(type) {
	case *api.LsAddrPrefix:
		linkStateNLRI, err := nlri.GetNlri().UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal LS Address Prefix: %w", err)
		}

		switch linkStateNLRI := linkStateNLRI.(type) {
		case *api.LsNodeNLRI:
			lsNode, err := getLsNodeNLRI(linkStateNLRI, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Node NLRI: %w", err)
			}
			return []table.TEDElem{lsNode}, nil
		case *api.LsLinkNLRI:
			lsLink, err := getLsLinkNLRI(linkStateNLRI, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Link NLRI: %w", err)
			}
			return []table.TEDElem{lsLink}, nil
		case *api.LsPrefixV4NLRI, *api.LsPrefixV6NLRI:
			lsPrefixList, err := getLsPrefixList(path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Prefix V4 NLRI: %w", err)
			}
			return lsPrefixList, nil
		case *api.LsSrv6SIDNLRI:
			lsSrv6SIDList, err := getLsSrv6SIDNLRIList(path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
			}
			return lsSrv6SIDList, nil
		default:
			return nil, fmt.Errorf("invalid LS Link State NLRI type: %T", linkStateNLRI)
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

func getLsNodeNLRI(typedLinkStateNLRI *api.LsNodeNLRI, pathAttrs []*anypb.Any) (*table.LsNode, error) {
	asn := typedLinkStateNLRI.GetLocalNode().GetAsn()
	routerID := typedLinkStateNLRI.GetLocalNode().GetIgpRouterId()

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
		if bgplsAttr.GetNode().GetSrCapabilities() != nil {
			srCapabilities := bgplsAttr.GetNode().GetSrCapabilities().GetRanges()
			if len(srCapabilities) != 1 {
				return nil, fmt.Errorf("expected 1 SR Capability TLV, got: %d", len(srCapabilities))
			} else {
				lsNode.SrgbBegin = srCapabilities[0].GetBegin()
				lsNode.SrgbEnd = srCapabilities[0].GetEnd()
			}
		}
	}

	return lsNode, nil
}

func getLsLinkNLRI(typedLinkStateNLRI *api.LsLinkNLRI, pathAttrs []*anypb.Any) (*table.LsLink, error) {
	localNode := table.NewLsNode(typedLinkStateNLRI.GetLocalNode().GetAsn(), typedLinkStateNLRI.GetLocalNode().GetIgpRouterId())
	remoteNode := table.NewLsNode(typedLinkStateNLRI.GetRemoteNode().GetAsn(), typedLinkStateNLRI.GetRemoteNode().GetIgpRouterId())

	var err error
	var localIP netip.Addr
	if typedLinkStateNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4() != "" {
		localIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv4 address: %v", err)
		}
	} else {
		localIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetInterfaceAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv6 address: %v", err)
		}
	}

	var remoteIP netip.Addr
	if typedLinkStateNLRI.GetLinkDescriptor().GetNeighborAddrIpv4() != "" {
		remoteIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetNeighborAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv4 address: %v", err)
		}
	} else {
		remoteIP, err = netip.ParseAddr(typedLinkStateNLRI.GetLinkDescriptor().GetNeighborAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv6 address: %v", err)
		}
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

		lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.IGPMetric), bgplsAttr.GetLink().GetIgpMetric()))

		teMetric := bgplsAttr.GetLink().GetDefaultTeMetric()
		if teMetric != 0 {
			lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.TEMetric), teMetric))
		}

		lsLink.AdjSid = bgplsAttr.GetLink().GetSrAdjacencySid()
	}

	return lsLink, nil
}

func getLsPrefixList(pathAttrs []*anypb.Any) ([]table.TEDElem, error) {
	var lsPrefixList []table.TEDElem
	var sidIndex uint32

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %v", err)
		}

		switch typedPathAttr := typedPathAttr.(type) {
		case *api.LsAttribute:
			if typedPathAttr.GetPrefix().GetSrPrefixSid() != 0 {
				sidIndex = typedPathAttr.GetPrefix().GetSrPrefixSid()
			} else {
				sidIndex = 0
			}
		case *api.MpReachNLRIAttribute:
			for _, nlri := range typedPathAttr.GetNlris() {
				typedNlri, err := nlri.UnmarshalNew()
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal NLRI: %v", err)
				}

				if lsNlri, ok := typedNlri.(*api.LsAddrPrefix); ok {
					lsPrefix, err := getLsPrefix(lsNlri, sidIndex)
					if err != nil {
						return nil, fmt.Errorf("failed to get LS Prefix: %v", err)
					}
					lsPrefixList = append(lsPrefixList, lsPrefix)
				}
			}
		}
	}

	return lsPrefixList, nil
}

func getLsPrefix(lsNlri *api.LsAddrPrefix, sidIndex uint32) (*table.LsPrefix, error) {
	nlri, err := lsNlri.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LS Prefix V4: %v", err)
	}

	var localNodeID string
	var localNodeAsn uint32
	var prefix []string

	switch prefNlri := nlri.(type) {
	case *api.LsPrefixV4NLRI:
		localNodeID = prefNlri.GetLocalNode().GetIgpRouterId()
		localNodeAsn = prefNlri.GetLocalNode().GetAsn()
		prefix = prefNlri.GetPrefixDescriptor().GetIpReachability()
	case *api.LsPrefixV6NLRI:
		localNodeID = prefNlri.GetLocalNode().GetIgpRouterId()
		localNodeAsn = prefNlri.GetLocalNode().GetAsn()
		prefix = prefNlri.GetPrefixDescriptor().GetIpReachability()
	default:
		return nil, errors.New("invalid LS prefix NLRI type")
	}

	localNode := table.NewLsNode(localNodeAsn, localNodeID)
	lsPrefix := table.NewLsPrefix(localNode)
	lsPrefix.SidIndex = sidIndex

	if len(prefix) != 1 {
		return nil, errors.New("invalid prefix length: expected 1 prefix")
	}

	lsPrefix.Prefix, err = netip.ParsePrefix(prefix[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse prefix: %v", err)
	}

	return lsPrefix, nil
}

func getLsSrv6SIDNLRIList(pathAttrs []*anypb.Any) ([]table.TEDElem, error) {
	var lsSrv6SIDList []table.TEDElem
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
				typedNLRI, err := nlri.UnmarshalNew()
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal NLRI: %w", err)
				}
				if lsNLRI, ok := typedNLRI.(*api.LsAddrPrefix); ok {
					lsSrv6SID, err := getLsSrv6SIDNLRI(lsNLRI, endpointBehavior)
					if err != nil {
						return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
					}
					lsSrv6SIDList = append(lsSrv6SIDList, lsSrv6SID)
				} else {
					return nil, fmt.Errorf("unexpected NLRI type: %T", typedNLRI)
				}
			}
		}
	}
	return lsSrv6SIDList, nil
}

// getLsSrv6SIDNLRI processes the LS SRv6 SID NLRI and returns a corresponding LsSrv6SID.
func getLsSrv6SIDNLRI(lsNLRI *api.LsAddrPrefix, endpointBehavior uint32) (*table.LsSrv6SID, error) {
	srv6NLRI, err := lsNLRI.GetNlri().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LS NLRI: %w", err)
	}
	srv6SIDNLRI, ok := srv6NLRI.(*api.LsSrv6SIDNLRI)
	if !ok {
		return nil, fmt.Errorf("invalid LS SRv6 SID NLRI type: %T", srv6NLRI)
	}

	localNodeID := srv6SIDNLRI.GetLocalNode().GetIgpRouterId()
	localNodeASN := srv6SIDNLRI.GetLocalNode().GetAsn()
	srv6SIDs := srv6SIDNLRI.GetSrv6SidInformation().GetSids()
	multiTopoIDs := srv6SIDNLRI.GetMultiTopoId().GetMultiTopoIds()

	localNode := table.NewLsNode(localNodeASN, localNodeID)
	lsSrv6SID := table.NewLsSrv6SID(localNode)
	lsSrv6SID.EndpointBehavior = endpointBehavior
	lsSrv6SID.Sids = srv6SIDs
	lsSrv6SID.MultiTopoIDs = multiTopoIDs

	return lsSrv6SID, nil
}
