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
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/pkg/table"
	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func MonitorBGPLsEvents(serverAddr string, serverPort string, tedChan chan []table.TEDElem, logger *zap.Logger) {
	// Establish gRPC connection
	cc, client, err := newGoBGPClient(serverAddr, serverPort)
	if err != nil {
		logger.Error("failed to create gRPC client", zap.String("address", fmt.Sprintf("%s:%s", serverAddr, serverPort)), zap.Error(err))
		return
	}
	defer func() {
		if err := cc.Close(); err != nil {
			logger.Error("failed to close gRPC connection", zap.Error(err))
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial TED sync
	initialSync(client, tedChan, logger)

	req := newWatchRequest()

	// Establish watch stream with retry
	var stream grpc.ServerStreamingClient[api.WatchEventResponse]
	for {
		stream, err = client.WatchEvent(ctx, req)
		if err != nil {
			logger.Error("failed to monitor BGP-LS events from gRPC server", zap.Error(err))
			time.Sleep(10 * time.Second)
			continue
		}
		break
	}

	debouncer := NewDebouncer(5 * time.Second) // If no additional triggers occur within this time from the trigger, TED is retrieved once

	fetch := func() ([]table.TEDElem, error) {
		return GetBGPlsNLRIs(client)
	}

	deliver := func(tedElems []table.TEDElem) {
		select {
		case tedChan <- tedElems:
		case <-ctx.Done():
		}
	}
	// Debounce start function: starts a goroutine on the first event.
	// Subsequent events update lastEvent, and the goroutine waits for the cooldown to elapse before retrieving TED once.

	// Event receive loop: update lastEvent on each receive, start debounce only on the first event
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			logger.Error("error receiving BGP-LS event", zap.Error(err))
			time.Sleep(10 * time.Second)
			for {
				stream, err = client.WatchEvent(ctx, req)
				if err != nil {
					logger.Error("failed to re-establish watch stream", zap.Error(err))
					time.Sleep(10 * time.Second)
					continue
				}
				break
			}
			continue
		}

		if t := res.GetTable(); t != nil {
			// Start debounce goroutine only on the first trigger (subsequent triggers only update the timestamp)
			debouncer.Trigger(ctx, fetch, deliver, logger)
		}
	}
}

func newGoBGPClient(serverAddress string, serverPort string) (*grpc.ClientConn, api.GoBgpServiceClient, error) {
	gobgpAddress := fmt.Sprintf("%s:%s", serverAddress, serverPort)

	// Establish gRPC connection
	cc, err := grpc.NewClient(
		gobgpAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, err
	}

	// Create gRPC client
	client := api.NewGoBgpServiceClient(cc)
	return cc, client, nil
}

func initialSync(client api.GoBgpServiceClient, tedChan chan []table.TEDElem, logger *zap.Logger) {
	tedElems, err := GetBGPlsNLRIs(client)
	if err != nil {
		logger.Error("failed to get initial TED info", zap.Error(err))
		return
	}
	tedChan <- tedElems
}

type Debouncer struct {
	mu       sync.Mutex
	active   bool
	last     time.Time
	cooldown time.Duration
}

func NewDebouncer(cd time.Duration) *Debouncer {
	return &Debouncer{cooldown: cd}
}

// Debounce start function: starts a goroutine on the first event.
// Subsequent events update lastEvent, and the goroutine waits for the cooldown to elapse before retrieving TED once.
func (d *Debouncer) Trigger(
	ctx context.Context,
	fetch func() ([]table.TEDElem, error),
	deliver func([]table.TEDElem),
	logger *zap.Logger,
) {
	d.mu.Lock()
	d.last = time.Now()
	if d.active {
		d.mu.Unlock()
		return
	}
	d.active = true
	d.mu.Unlock()

	go func() {
		defer func() {
			d.mu.Lock()
			d.active = false
			d.mu.Unlock()
		}()

		for {
			d.mu.Lock()
			remaining := d.cooldown - time.Since(d.last)
			d.mu.Unlock()

			if remaining <= 0 {
				break // If no additional triggers occur within the cooldown, retrieve TED once
			}

			// Wait with context cancellation support
			timer := time.NewTimer(remaining)
			select {
			case <-timer.C:
				// Loop again to recalculate remaining
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			}
		}

		// Retrieve TED info: GetBGPlsNLRIs()
		tedElems, err := fetch()
		if err != nil {
			logger.Error("failed to get TED info", zap.Error(err))
			return
		}

		if ctx.Err() != nil {
			logger.Debug("deliver aborted due to context cancel")
			return
		}
		deliver(tedElems)
	}()
}

func newWatchRequest() *api.WatchEventRequest {
	return &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{
					Type: api.WatchEventRequest_Table_Filter_TYPE_ADJIN,
					Init: false,
				},
			},
		},
	}
}
func GetBGPlsNLRIs(client api.GoBgpServiceClient) ([]table.TEDElem, error) {

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

// ConvertToTEDElem converts a single api.Destination to TEDElem(s) with low cyclomatic complexity.
func ConvertToTEDElem(dst *api.Destination) ([]table.TEDElem, error) {
	if len(dst.GetPaths()) != 1 {
		return nil, errors.New("invalid path length: expected 1 path")
	}

	path := dst.GetPaths()[0]
	nlri := path.GetNlri()
	if nlri == nil {
		return nil, errors.New("NLRI is nil")
	}

	lsAddrPrefix := nlri.GetLsAddrPrefix()
	if lsAddrPrefix == nil {
		return nil, errors.New("LSAddrPrefix is nil")
	}

	lsAttr := findLsAttribute(path)
	if lsAttr == nil {
		// BGP-LS Attribute not found, return empty
		return nil, nil
	}

	return convertByNlriType(lsAddrPrefix, lsAttr, path)
}

// findLsAttribute extracts the BGP-LS attribute from a path.
func findLsAttribute(path *api.Path) *api.Attribute_Ls {
	for _, pathAttr := range path.GetPattrs() {
		if lsAttr, ok := pathAttr.Attr.(*api.Attribute_Ls); ok {
			return lsAttr
		}
	}
	return nil
}

// convertByNlriType dispatches NLRI processing based on its type.
func convertByNlriType(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls, path *api.Path) ([]table.TEDElem, error) {
	switch nlri.GetType() {
	case api.LsNLRIType_LS_NLRI_TYPE_NODE:
		return convertNode(nlri, lsAttr)
	case api.LsNLRIType_LS_NLRI_TYPE_LINK:
		return convertLink(nlri, lsAttr)
	case api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V4, api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V6:
		return convertPrefix(nlri, lsAttr, path)
	case api.LsNLRIType_LS_NLRI_TYPE_SRV6_SID:
		return convertSrv6SID(nlri, lsAttr, path)
	default:
		return nil, fmt.Errorf("invalid LS NLRI type: %s", nlri.GetType().String())
	}
}

// convertNode handles LS Node NLRI.
func convertNode(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls) ([]table.TEDElem, error) {
	nodeAttr := lsAttr.Ls.GetNode()
	if nodeAttr == nil {
		return nil, fmt.Errorf("LS Node Attribute is nil")
	}
	lsNode, err := getLsNode(nlri, nodeAttr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS Node NLRI: %w", err)
	}
	return []table.TEDElem{lsNode}, nil
}

// convertLink handles LS Link NLRI.
func convertLink(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls) ([]table.TEDElem, error) {
	linkAttr := lsAttr.Ls.GetLink()
	if linkAttr == nil {
		return nil, fmt.Errorf("LS Link Attribute is nil")
	}
	lsLink, err := getLsLink(nlri, linkAttr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS Link NLRI: %w", err)
	}
	return []table.TEDElem{lsLink}, nil
}

// convertPrefix handles LS Prefix V4/V6 NLRI.
func convertPrefix(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls, path *api.Path) ([]table.TEDElem, error) {
	prefixAttr := lsAttr.Ls.GetPrefix()
	if prefixAttr == nil {
		return nil, fmt.Errorf("LS Prefix Attribute is nil")
	}

	mpReach := findMpReach(path)
	if mpReach == nil {
		return nil, errors.New("MP-REACH NLRI Attribute is nil")
	}

	lsPrefixList, err := getLsPrefixList(mpReach.GetNlris(), prefixAttr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS Prefix NLRI: %w", err)
	}

	return lsPrefixList, nil
}

// convertSrv6SID handles LS SRv6 SID NLRI.
func convertSrv6SID(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls, path *api.Path) ([]table.TEDElem, error) {
	srv6Attr := lsAttr.Ls.GetSrv6Sid()
	if srv6Attr == nil {
		return nil, fmt.Errorf("LS SRv6 SID Attribute is nil")
	}

	mpReach := findMpReach(path)
	if mpReach == nil {
		return nil, errors.New("MP-REACH NLRI Attribute is nil")
	}

	lsSrv6List, err := getLsSrv6SIDList(mpReach.GetNlris(), srv6Attr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
	}

	return lsSrv6List, nil
}

// findMpReach searches for MP-REACH NLRI attribute in path.
func findMpReach(path *api.Path) *api.MpReachNLRIAttribute {
	for _, attr := range path.GetPattrs() {
		if mp := attr.GetMpReach(); mp != nil {
			return mp
		}
	}
	return nil
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

func getLsNode(typedLinkStateNLRI *api.LsAddrPrefix, lsAttrNode *api.LsAttributeNode) (*table.LsNode, error) {
	localNode := typedLinkStateNLRI.Nlri.GetNode().GetLocalNode()
	lsNode := table.NewLsNode(localNode.GetAsn(), localNode.GetIgpRouterId())

	lsNode.IsisAreaID = formatIsisAreaID(lsAttrNode.GetIsisArea())
	lsNode.Hostname = lsAttrNode.GetName()

	if lsAttrNode.GetSrCapabilities() != nil {
		srCapabilities := lsAttrNode.GetSrCapabilities().GetRanges()
		if len(srCapabilities) != 1 {
			return nil, fmt.Errorf("expected 1 SR Capability TLV, got: %d", len(srCapabilities))
		}
		lsNode.SrgbBegin = srCapabilities[0].GetBegin()
		lsNode.SrgbEnd = srCapabilities[0].GetEnd()
	}
	return lsNode, nil
}

func getLsLink(typedLinkStateNLRI *api.LsAddrPrefix, lsAttrLink *api.LsAttributeLink) (*table.LsLink, error) {
	lsLinkNLRI := typedLinkStateNLRI.Nlri.GetLink()
	localNode := table.NewLsNode(lsLinkNLRI.GetLocalNode().GetAsn(), lsLinkNLRI.GetLocalNode().GetIgpRouterId())
	remoteNode := table.NewLsNode(lsLinkNLRI.GetRemoteNode().GetAsn(), lsLinkNLRI.GetRemoteNode().GetIgpRouterId())

	var err error
	var localIP netip.Addr
	if lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4() != "" {
		localIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv4 address: %v", err)
		}
	} else if lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv6() != "" {
		localIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv6 address: %v", err)
		}
	} else {
		localIP = netip.Addr{}
	}

	var remoteIP netip.Addr
	if lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv4() != "" {
		remoteIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv4 address: %v", err)
		}
	} else if lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv6() != "" {
		remoteIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv6 address: %v", err)
		}
	} else {
		remoteIP = netip.Addr{}
	}

	lsLink := table.NewLsLink(localNode, remoteNode)
	lsLink.LocalIP = localIP
	lsLink.RemoteIP = remoteIP

	lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.IGPMetric), lsAttrLink.GetIgpMetric()))

	teMetric := lsAttrLink.GetDefaultTeMetric()
	if teMetric != 0 {
		lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.MetricType(table.TEMetric), teMetric))
	}

	lsLink.AdjSid = lsAttrLink.GetSrAdjacencySid()

	// handle SRv6 SID TLV
	srv6EndXSID := lsAttrLink.GetSrv6EndXSid()
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

	return lsLink, nil
}

func getLsPrefixList(nlris []*api.NLRI, lsAttrPrefix *api.LsAttributePrefix) ([]table.TEDElem, error) {
	var lsPrefixList []table.TEDElem

	for _, nlri := range nlris {
		lsAddrPrefix := nlri.GetLsAddrPrefix()

		lsPrefix, err := getLsPrefix(lsAddrPrefix, lsAttrPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to get LS Prefix: %v", err)
		}
		lsPrefixList = append(lsPrefixList, lsPrefix)
	}
	return lsPrefixList, nil
}

func getLsPrefix(typedLinkStateNLRI *api.LsAddrPrefix, lsAttrPrefix *api.LsAttributePrefix) (*table.LsPrefix, error) {
	var localNodeID string
	var localNodeAsn uint32
	var prefix []string
	var sidIndex uint32

	if lsAttrPrefix.GetSrPrefixSid() != 0 {
		sidIndex = lsAttrPrefix.GetSrPrefixSid()
	} else {
		sidIndex = 0
	}

	switch prefNLRI := typedLinkStateNLRI.Nlri.Nlri.(type) {
	case *api.LsAddrPrefix_LsNLRI_PrefixV4:
		localNodeID = prefNLRI.PrefixV4.GetLocalNode().GetIgpRouterId()
		localNodeAsn = prefNLRI.PrefixV4.GetLocalNode().GetAsn()
		prefix = prefNLRI.PrefixV4.GetPrefixDescriptor().GetIpReachability()
	case *api.LsAddrPrefix_LsNLRI_PrefixV6:
		localNodeID = prefNLRI.PrefixV6.GetLocalNode().GetIgpRouterId()
		localNodeAsn = prefNLRI.PrefixV6.GetLocalNode().GetAsn()
		prefix = prefNLRI.PrefixV6.GetPrefixDescriptor().GetIpReachability()
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

func getLsSrv6SIDList(nlris []*api.NLRI, lsAttrSrv6SID *api.LsAttributeSrv6SID) ([]table.TEDElem, error) {
	var lsSrv6SIDList []table.TEDElem

	for _, nlri := range nlris {
		lsAddrPrefix := nlri.GetLsAddrPrefix()

		lsPrefix, err := getLsSrv6SID(lsAddrPrefix, lsAttrSrv6SID)
		if err != nil {
			return nil, fmt.Errorf("failed to get LS Prefix: %v", err)
		}
		lsSrv6SIDList = append(lsSrv6SIDList, lsPrefix)
	}

	return lsSrv6SIDList, nil
}

// getLsSrv6SID processes the LS SRv6 SID NLRI and returns a corresponding LsSrv6SID.
func getLsSrv6SID(typedLinkStateNLRI *api.LsAddrPrefix, lsAttrSrv6SID *api.LsAttributeSrv6SID) (*table.LsSrv6SID, error) {

	srv6SIDStructure := lsAttrSrv6SID.GetSrv6SidStructure()
	endpointBehavior := lsAttrSrv6SID.GetSrv6EndpointBehavior()
	srv6SIDNLRI := typedLinkStateNLRI.Nlri.GetSrv6Sid()

	localNodeID := srv6SIDNLRI.GetLocalNode().GetIgpRouterId()
	localNodeASN := srv6SIDNLRI.GetLocalNode().GetAsn()
	srv6SIDs := srv6SIDNLRI.GetSrv6SidInformation().GetSids()
	multiTopoIDs := srv6SIDNLRI.GetMultiTopoId().GetMultiTopoIds()

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

	return lsSrv6SID, nil
}
