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
		return nil, fmt.Errorf("failed to create gRPC client: %v", err)
	}
	defer func() {
		if err := cc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close gRPC client connection: %v\n", err)
		}
	}()

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
		return nil, fmt.Errorf("failed to retrieve paths: %v", err)
	}

	var tedElems []table.TedElem
	for {
		r, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error receiving stream data: %v", err)
		}

		convertedElems, err := ConvertToTedElem(r.Destination)
		if err != nil {
			return nil, fmt.Errorf("failed to convert path to TED element: %v", err)
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
		return nil, fmt.Errorf("failed to unmarshal NLRI: %v", err)
	}

	switch nlri := nlri.(type) {
	case *api.LsAddrPrefix:
		linkStateNlri, err := nlri.GetNlri().UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal LS Address Prefix: %v", err)
		}

		switch linkStateNlri := linkStateNlri.(type) {
		case *api.LsNodeNLRI:
			lsNode, err := getLsNodeNLRI(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Node NLRI: %v", err)
			}
			return []table.TedElem{lsNode}, nil
		case *api.LsLinkNLRI:
			lsLink, err := getLsLinkNLRI(linkStateNlri, path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Link NLRI: %v", err)
			}
			return []table.TedElem{lsLink}, nil
		case *api.LsPrefixV4NLRI:
			lsPrefixV4List, err := getLsPrefixV4List(path.GetPattrs())
			if err != nil {
				return nil, fmt.Errorf("failed to process LS Prefix V4 NLRI: %v", err)
			}
			return lsPrefixV4List, nil
		default:
			return nil, errors.New("invalid LS Link State NLRI type")
		}
	default:
		return nil, errors.New("invalid NLRI type")
	}
}

func getLsNodeNLRI(typedLinkStateNlri *api.LsNodeNLRI, pathAttrs []*anypb.Any) (*table.LsNode, error) {
	asn := typedLinkStateNlri.GetLocalNode().GetAsn()
	routerID := typedLinkStateNlri.GetLocalNode().GetIgpRouterId()

	lsNode := table.NewLsNode(asn, routerID)

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %v", err)
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
			return nil, fmt.Errorf("expected 1 SR Capability TLV, got: %d", len(srCapabilities))
		} else {
			lsNode.SrgbBegin = srCapabilities[0].GetBegin()
			lsNode.SrgbEnd = srCapabilities[0].GetEnd()
		}
	}

	return lsNode, nil
}

func getLsLinkNLRI(typedLinkStateNlri *api.LsLinkNLRI, pathAttrs []*anypb.Any) (*table.LsLink, error) {
	localNode := table.NewLsNode(typedLinkStateNlri.GetLocalNode().GetAsn(), typedLinkStateNlri.GetLocalNode().GetIgpRouterId())
	remoteNode := table.NewLsNode(typedLinkStateNlri.GetRemoteNode().GetAsn(), typedLinkStateNlri.GetRemoteNode().GetIgpRouterId())

	localIP, err := netip.ParseAddr(typedLinkStateNlri.GetLinkDescriptor().GetInterfaceAddrIpv4())
	if err != nil {
		return nil, fmt.Errorf("failed to parse local IP address: %v", err)
	}

	remoteIP, err := netip.ParseAddr(typedLinkStateNlri.GetLinkDescriptor().GetNeighborAddrIpv4())
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote IP address: %v", err)
	}

	lsLink := table.NewLsLink(localNode, remoteNode)
	lsLink.LocalIP = localIP
	lsLink.RemoteIP = remoteIP

	for _, pathAttr := range pathAttrs {
		typedPathAttr, err := pathAttr.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal path attribute: %v", err)
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
			return nil, fmt.Errorf("failed to unmarshal path attribute: %v", err)
		}

		switch typedPathAttr := typedPathAttr.(type) {
		case *api.LsAttribute:
			sidIndex = typedPathAttr.GetPrefix().GetSrPrefixSid()

		case *api.MpReachNLRIAttribute:
			for _, nlri := range typedPathAttr.GetNlris() {
				typedNlri, err := nlri.UnmarshalNew()
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal NLRI: %v", err)
				}

				if lsNlri, ok := typedNlri.(*api.LsAddrPrefix); ok {
					lsPrefixV4, err := getLsPrefixV4(lsNlri, sidIndex)
					if err != nil {
						return nil, fmt.Errorf("failed to get LS Prefix V4: %v", err)
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
		return nil, fmt.Errorf("failed to unmarshal LS Prefix V4: %v", err)
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
		return nil, errors.New("invalid prefix length: expected 1 prefix")
	}

	lsPrefixV4.Prefix, err = netip.ParsePrefix(prefixV4[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse prefix: %v", err)
	}

	return lsPrefixV4, nil
}
