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

	"github.com/nttcom/pola/internal/pkg/table"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GobgpOptions struct {
	GobgpAddr string
	GobgpPort string
}

func GetBgplsNlris(serverAddr string, serverPort string) ([]table.TedElem, error) {
	gobgpAddress := serverAddr + ":" + serverPort

	// Get connection
	cc, err := grpc.Dial(gobgpAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer cc.Close()

	// Create gRPC client
	client := api.NewGobgpApiClient(cc)
	ctx := context.Background()

	stream, err := client.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_LS,
			Safi: api.Family_SAFI_LS,
		},
		Name:     "",
		SortType: api.ListPathRequest_PREFIX,
	})
	if err != nil {
		return nil, err
	}

	tedElems := make([]table.TedElem, 0)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
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
	tedElems := []table.TedElem{}
	if len(dst.GetPaths()) != 1 {
		return nil, errors.New("invalid pathes length")
	}
	nlri, err := dst.GetPaths()[0].GetNlri().UnmarshalNew()
	if err != nil {
		return nil, err
	}

	switch typedNlri := nlri.(type) {
	case *api.LsAddrPrefix:
		linkStateNlri, err := typedNlri.GetNlri().UnmarshalNew()
		pathAttrs := dst.GetPaths()[0].GetPattrs()
		if err != nil {
			return nil, err
		}
		switch typedLinkStateNlri := linkStateNlri.(type) {
		case *api.LsNodeNLRI:
			// Get information from MP-REACH-NLRI Attr
			asn := typedLinkStateNlri.GetLocalNode().GetAsn()
			routerId := typedLinkStateNlri.GetLocalNode().GetIgpRouterId()

			lsNode := table.NewLsNode(asn, routerId)

			// Get information from BGP-LS Attr
			for _, pathAttr := range pathAttrs {
				typedPathAttr, err := pathAttr.UnmarshalNew()
				if err != nil {
					return nil, err
				}
				if bgplsAttr, ok := typedPathAttr.(*api.LsAttribute); ok {
					isisArea := bgplsAttr.GetNode().GetIsisArea()
					tmpIsisArea := hex.EncodeToString(isisArea)
					strIsisArea := ""
					for i, s := range strings.Split(tmpIsisArea, "") {
						if (len(tmpIsisArea)-i)%4 == 0 {
							strIsisArea += "."
						}
						strIsisArea += s
					}
					lsNode.IsisAreaId = strIsisArea
					lsNode.Hostname = bgplsAttr.GetNode().GetName()
					srCapabilities := bgplsAttr.GetNode().GetSrCapabilities().GetRanges()
					if len(srCapabilities) != 1 {
						return nil, errors.New("invalid SR Capability TLV")
					}
					lsNode.SrgbBegin = srCapabilities[0].GetBegin()
					lsNode.SrgbEnd = srCapabilities[0].GetEnd()
				}
			}
			tedElems = append(tedElems, lsNode)
		case *api.LsLinkNLRI:
			// Get information from MP-REACH-NLRI Attr
			localNodeId := typedLinkStateNlri.GetLocalNode().GetIgpRouterId()
			localNodeAsn := typedLinkStateNlri.GetLocalNode().GetAsn()
			remoteNodeId := typedLinkStateNlri.GetRemoteNode().GetIgpRouterId()
			remoteNodeAsn := typedLinkStateNlri.GetRemoteNode().GetAsn()
			localIP, err := netip.ParseAddr(typedLinkStateNlri.GetLinkDescriptor().GetInterfaceAddrIpv4())
			if err != nil {
				return nil, err
			}
			remoteIP, err := netip.ParseAddr(typedLinkStateNlri.GetLinkDescriptor().GetNeighborAddrIpv4())
			if err != nil {
				return nil, err
			}
			localNode := table.NewLsNode(localNodeAsn, localNodeId)
			remoteNode := table.NewLsNode(remoteNodeAsn, remoteNodeId)
			lsLink := table.NewLsLink(localNode, remoteNode)
			lsLink.LocalIP = localIP
			lsLink.RemoteIP = remoteIP

			// Get information from BGP-LS Attr
			for _, pathAttr := range pathAttrs {
				typedPathAttr, err := pathAttr.UnmarshalNew()
				if err != nil {
					return nil, err
				}
				if bgplsAttr, ok := typedPathAttr.(*api.LsAttribute); ok {
					igpMetric := table.NewMetric(table.MetricType(table.IGP_METRIC), bgplsAttr.GetLink().GetIgpMetric())
					lsLink.Metrics = append(lsLink.Metrics, igpMetric)

					if bgplsAttr.GetLink().GetDefaultTeMetric() != 0 {
						teMetric := table.NewMetric(table.MetricType(table.TE_METRIC), bgplsAttr.GetLink().GetDefaultTeMetric())
						lsLink.Metrics = append(lsLink.Metrics, teMetric)
					}

					lsLink.AdjSid = bgplsAttr.GetLink().GetSrAdjacencySid()
				}
			}
			tedElems = append(tedElems, lsLink)
		case *api.LsPrefixV4NLRI:
			// Get information from MP-REACH-NLRI Attr
			var sidIndex uint32
			for _, pathAttr := range pathAttrs {
				typedPathAttr, err := pathAttr.UnmarshalNew()
				if err != nil {
					return nil, err
				}
				// Get information from BGP-LS Attr
				if bgplsAttr, ok := typedPathAttr.(*api.LsAttribute); ok {
					// if sidIndex != 0 then Loopback interface Address Prefix
					sidIndex = bgplsAttr.GetPrefix().GetSrPrefixSid()
				}
				if mpReachNlriAttr, ok := typedPathAttr.(*api.MpReachNLRIAttribute); ok {
					for _, nlri := range mpReachNlriAttr.GetNlris() {
						typedNlri, err := nlri.UnmarshalNew()
						if err != nil {
							return nil, err
						}
						if lsNlri, ok := typedNlri.(*api.LsAddrPrefix); ok {

							prefNlri, err := lsNlri.GetNlri().UnmarshalNew()
							if err != nil {
								return nil, err
							}
							prefv4Nlri := prefNlri.(*api.LsPrefixV4NLRI)
							localNodeId := prefv4Nlri.GetLocalNode().GetIgpRouterId()
							localNodeAsn := prefv4Nlri.GetLocalNode().GetAsn()
							prefixV4 := prefv4Nlri.GetPrefixDescriptor().GetIpReachability()

							localNode := table.NewLsNode(localNodeAsn, localNodeId)
							lsPrefixV4 := table.NewLsPrefixV4(localNode)
							lsPrefixV4.SidIndex = sidIndex
							if len(prefixV4) != 1 {
								return nil, errors.New("invalid prefix length")
							}
							lsPrefixV4.Prefix, _ = netip.ParsePrefix(prefixV4[0])
							tedElems = append(tedElems, lsPrefixV4)
						}
					}
				}
			}
		}
	default:
		return nil, errors.New("invalid Nlri Type")
	}

	return tedElems, nil
}
