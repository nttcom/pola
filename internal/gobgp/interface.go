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

	"github.com/nttcom/pola/internal/safecast"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/table"
	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultDebounceCooldown = 5 * time.Second
	defaultRetryInterval    = 10 * time.Second
)

type monitorOptions struct {
	debounceCooldown time.Duration
	retryInterval    time.Duration
}

// MonitorBGPLsEvents monitors BGP-LS events and sends updates to the TED channel.
func MonitorBGPLsEvents(ctx context.Context, serverAddr string, serverPort string, tedChan chan []table.TEDElem, lg *logger.Logger) {
	monitorBGPLsEvents(ctx, serverAddr, serverPort, tedChan, lg, monitorOptions{
		debounceCooldown: defaultDebounceCooldown,
		retryInterval:    defaultRetryInterval,
	})
}

func monitorBGPLsEvents(ctx context.Context, serverAddr string, serverPort string, tedChan chan []table.TEDElem, lg *logger.Logger, opts monitorOptions) {
	cc, client, err := newGoBGPClient(serverAddr, serverPort)
	if err != nil {
		lg.Error("failed to create gRPC client", logger.String("address", fmt.Sprintf("%s:%s", serverAddr, serverPort)), logger.Error(err))
		return
	}
	defer func() {
		if err := cc.Close(); err != nil {
			lg.Error("failed to close gRPC connection", logger.Error(err))
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	initialSync(ctx, client, tedChan, lg)

	req := newWatchRequest()

	stream, ok := establishWatchStream(ctx, client, req, opts.retryInterval, lg)
	if !ok {
		return
	}

	debouncer := NewDebouncer(opts.debounceCooldown)

	fetch := func() ([]table.TEDElem, error) {
		return GetBGPlsNLRIs(ctx, client)
	}

	deliver := func(tedElems []table.TEDElem) {
		select {
		case tedChan <- tedElems:
		case <-ctx.Done():
		}
	}

	// Debounce consecutive events to avoid fetching TED for every event.
	for {
		res, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				lg.Info("BGP-LS watch stream closed by peer, reconnecting")
			} else {
				lg.Error("error receiving BGP-LS event", logger.Error(err))
			}

			stream, ok = reconnectWatchStream(ctx, client, req, opts.retryInterval, lg, debouncer, fetch, deliver)
			if !ok {
				return
			}
			continue
		}

		if t := res.GetTable(); t != nil {
			debouncer.Trigger(ctx, fetch, deliver, lg)
		}
	}
}

func reconnectWatchStream(
	ctx context.Context,
	client api.GoBgpServiceClient,
	req *api.WatchEventRequest,
	retryInterval time.Duration,
	lg *logger.Logger,
	debouncer *Debouncer,
	fetch func() ([]table.TEDElem, error),
	deliver func([]table.TEDElem),
) (grpc.ServerStreamingClient[api.WatchEventResponse], bool) {
	if !waitForRetry(ctx, retryInterval) {
		return nil, false
	}

	stream, ok := establishWatchStream(ctx, client, req, retryInterval, lg)
	if !ok {
		return nil, false
	}

	debouncer.Trigger(ctx, fetch, deliver, lg)

	return stream, true
}

func establishWatchStream(
	ctx context.Context,
	client api.GoBgpServiceClient,
	req *api.WatchEventRequest,
	retryInterval time.Duration,
	lg *logger.Logger,
) (grpc.ServerStreamingClient[api.WatchEventResponse], bool) {
	for {
		stream, err := client.WatchEvent(ctx, req)
		if err == nil {
			return stream, true
		}
		lg.Error("failed to establish watch stream", logger.Error(err))
		if !waitForRetry(ctx, retryInterval) {
			return nil, false
		}
	}
}

func waitForRetry(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func newGoBGPClient(serverAddress string, serverPort string) (*grpc.ClientConn, api.GoBgpServiceClient, error) {
	gobgpAddress := fmt.Sprintf("%s:%s", serverAddress, serverPort)

	cc, err := grpc.NewClient(
		gobgpAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, err
	}

	client := api.NewGoBgpServiceClient(cc)
	return cc, client, nil
}

func initialSync(ctx context.Context, client api.GoBgpServiceClient, tedChan chan []table.TEDElem, lg *logger.Logger) {
	tedElems, err := GetBGPlsNLRIs(ctx, client)
	if err != nil {
		lg.Error("failed to get initial TED info", logger.Error(err))
		return
	}

	select {
	case tedChan <- tedElems:
	case <-ctx.Done():
	}
}

// Debouncer debounces consecutive events to avoid excessive TED fetches.
type Debouncer struct {
	mu       sync.Mutex
	active   bool
	last     time.Time
	cooldown time.Duration
}

// NewDebouncer creates a new Debouncer with the specified cooldown duration.
func NewDebouncer(cd time.Duration) *Debouncer {
	return &Debouncer{cooldown: cd}
}

// Trigger debounces consecutive events before retrieving TED.
func (d *Debouncer) Trigger(
	ctx context.Context,
	fetch func() ([]table.TEDElem, error),
	deliver func([]table.TEDElem),
	lg *logger.Logger,
) {
	d.mu.Lock()
	d.last = time.Now()
	if d.active {
		d.mu.Unlock()
		return
	}
	d.active = true
	d.mu.Unlock()

	go d.run(ctx, fetch, deliver, lg)
}

func (d *Debouncer) run(
	ctx context.Context,
	fetch func() ([]table.TEDElem, error),
	deliver func([]table.TEDElem),
	lg *logger.Logger,
) {
	released := false
	defer func() {
		if released {
			return
		}
		d.mu.Lock()
		d.active = false
		d.mu.Unlock()
	}()

	// finish checks for a pending trigger and releases the worker atomically.
	finish := func(cycleStart time.Time) (pending bool) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.last.After(cycleStart) {
			return true
		}
		d.active = false
		released = true
		return false
	}

outer:
	for {
		for {
			d.mu.Lock()
			remaining := d.cooldown - time.Since(d.last)
			d.mu.Unlock()

			if remaining <= 0 {
				break
			}

			timer := time.NewTimer(remaining)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				if finish(time.Now()) {
					continue outer
				}
				return
			}
		}

		fetchStart := time.Now()
		tedElems, err := fetch()
		if err != nil {
			lg.Error("failed to get TED info", logger.Error(err))
			if finish(fetchStart) {
				continue outer
			}
			return
		}

		if ctx.Err() != nil {
			lg.Debug("deliver aborted due to context cancel")
			if finish(fetchStart) {
				continue outer
			}
			return
		}
		deliver(tedElems)

		if finish(fetchStart) {
			continue outer
		}
		return
	}
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

// GetBGPlsNLRIs retrieves BGP-LS NLRIs from the GoBGP server and converts them to TEDElem format.
func GetBGPlsNLRIs(ctx context.Context, client api.GoBgpServiceClient) ([]table.TEDElem, error) {
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
			if errors.Is(err, io.EOF) {
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

// ConvertToTEDElem converts a BGP-LS destination to TEDElem format.
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
		return nil, nil
	}

	return convertByNlriType(lsAddrPrefix, lsAttr, path)
}

func findLsAttribute(path *api.Path) *api.Attribute_Ls {
	for _, pathAttr := range path.GetPattrs() {
		if lsAttr, ok := pathAttr.Attr.(*api.Attribute_Ls); ok {
			return lsAttr
		}
	}
	return nil
}

func convertByNlriType(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls, path *api.Path) ([]table.TEDElem, error) {
	switch nlri.GetType() {
	case api.LsNLRIType_LS_NLRI_TYPE_NODE:
		return convertNode(nlri, lsAttr)
	case api.LsNLRIType_LS_NLRI_TYPE_LINK:
		return convertLink(nlri, lsAttr)
	case api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V4, api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V6:
		nlris, err := mpReachNlris(path)
		if err != nil {
			return nil, err
		}
		return convertPrefix(lsAttr, nlris)
	case api.LsNLRIType_LS_NLRI_TYPE_SRV6_SID:
		nlris, err := mpReachNlris(path)
		if err != nil {
			return nil, err
		}
		return convertSrv6SID(lsAttr, nlris)
	default:
		return nil, fmt.Errorf("invalid LS NLRI type: %s", nlri.GetType().String())
	}
}

func convertNode(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls) ([]table.TEDElem, error) {
	nodeAttr := lsAttr.Ls.GetNode()
	if nodeAttr == nil {
		return nil, errors.New("LS Node Attribute is nil")
	}
	lsNode, err := getLsNode(nlri, nodeAttr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS Node NLRI: %w", err)
	}
	return []table.TEDElem{lsNode}, nil
}

func convertLink(nlri *api.LsAddrPrefix, lsAttr *api.Attribute_Ls) ([]table.TEDElem, error) {
	linkAttr := lsAttr.Ls.GetLink()
	if linkAttr == nil {
		return nil, errors.New("LS Link Attribute is nil")
	}
	lsLink, err := getLsLink(nlri, linkAttr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS Link NLRI: %w", err)
	}
	return []table.TEDElem{lsLink}, nil
}

func convertPrefix(lsAttr *api.Attribute_Ls, nlris []*api.NLRI) ([]table.TEDElem, error) {
	prefixAttr := lsAttr.Ls.GetPrefix()
	if prefixAttr == nil {
		return nil, errors.New("LS Prefix Attribute is nil")
	}

	lsPrefixList, err := getLsPrefixList(nlris, prefixAttr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS Prefix NLRI: %w", err)
	}

	return lsPrefixList, nil
}

func convertSrv6SID(lsAttr *api.Attribute_Ls, nlris []*api.NLRI) ([]table.TEDElem, error) {
	srv6Attr := lsAttr.Ls.GetSrv6Sid()
	if srv6Attr == nil {
		return nil, errors.New("LS SRv6 SID Attribute is nil")
	}

	lsSrv6List, err := getLsSrv6SIDList(nlris, srv6Attr)
	if err != nil {
		return nil, fmt.Errorf("failed to process LS SRv6 SID NLRI: %w", err)
	}

	return lsSrv6List, nil
}

func findMpReach(path *api.Path) *api.MpReachNLRIAttribute {
	for _, attr := range path.GetPattrs() {
		if mp := attr.GetMpReach(); mp != nil {
			return mp
		}
	}
	return nil
}

func mpReachNlris(path *api.Path) ([]*api.NLRI, error) {
	mpReach := findMpReach(path)
	if mpReach == nil {
		return nil, errors.New("MP-REACH NLRI Attribute is nil")
	}
	return mpReach.GetNlris(), nil
}

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
	if typedLinkStateNLRI == nil {
		return nil, errors.New("LS Link NLRI is nil")
	}
	lsLinkNLRI := typedLinkStateNLRI.Nlri.GetLink()
	if lsLinkNLRI == nil {
		return nil, errors.New("LS Link NLRI is not a link type")
	}
	localNode := table.NewLsNode(lsLinkNLRI.GetLocalNode().GetAsn(), lsLinkNLRI.GetLocalNode().GetIgpRouterId())
	remoteNode := table.NewLsNode(lsLinkNLRI.GetRemoteNode().GetAsn(), lsLinkNLRI.GetRemoteNode().GetIgpRouterId())

	var err error
	var localIP netip.Addr
	switch {
	case lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4() != "":
		localIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv4 address: %w", err)
		}
	case lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv6() != "":
		localIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetInterfaceAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local IPv6 address: %w", err)
		}
	default:
		localIP = netip.Addr{}
	}

	var remoteIP netip.Addr
	switch {
	case lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv4() != "":
		remoteIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv4())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv4 address: %w", err)
		}
	case lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv6() != "":
		remoteIP, err = netip.ParseAddr(lsLinkNLRI.GetLinkDescriptor().GetNeighborAddrIpv6())
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote IPv6 address: %w", err)
		}
	default:
		remoteIP = netip.Addr{}
	}

	lsLink := table.NewLsLink(localNode, remoteNode)
	lsLink.LocalIP = localIP
	lsLink.RemoteIP = remoteIP

	lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.IGPMetric, lsAttrLink.GetIgpMetric()))

	teMetric := lsAttrLink.GetDefaultTeMetric()
	if teMetric != 0 {
		lsLink.Metrics = append(lsLink.Metrics, table.NewMetric(table.TEMetric, teMetric))
	}

	if delay := lsAttrLink.GetUnidirectionalLinkDelay(); delay != 0 {
		lsLink.Metrics = append(
			lsLink.Metrics,
			table.NewMetric(table.DelayMetric, delay),
		)
	}

	lsLink.AdjSid = lsAttrLink.GetSrAdjacencySid()

	if srv6EndXSID := lsAttrLink.GetSrv6EndXSid(); srv6EndXSID != nil {
		converted, err := srv6EndXSIDFromAPI(srv6EndXSID)
		if err != nil {
			return nil, err
		}
		lsLink.Srv6EndXSID = converted
	}

	return lsLink, nil
}

func srv6EndXSIDFromAPI(srv6EndXSID *api.LsSrv6EndXSID) (*table.Srv6EndXSID, error) {
	endpointBehavior, err := safecast.Uint16(srv6EndXSID.EndpointBehavior, "SRv6 End.X SID endpoint behavior")
	if err != nil {
		return nil, err
	}
	structure, err := srv6SIDStructureFromAPI(srv6EndXSID.GetSrv6SidStructure())
	if err != nil {
		return nil, err
	}
	return &table.Srv6EndXSID{
		EndpointBehavior: endpointBehavior,
		Sids:             srv6EndXSID.Sids,
		Srv6SIDStructure: structure,
	}, nil
}

func srv6SIDStructureFromAPI(s *api.LsSrv6SIDStructure) (table.SIDStructure, error) {
	localBlock, err := safecast.Uint8(s.GetLocalBlock(), "SRv6 SID structure LocalBlock")
	if err != nil {
		return table.SIDStructure{}, err
	}
	localNode, err := safecast.Uint8(s.GetLocalNode(), "SRv6 SID structure LocalNode")
	if err != nil {
		return table.SIDStructure{}, err
	}
	localFunc, err := safecast.Uint8(s.GetLocalFunc(), "SRv6 SID structure LocalFunc")
	if err != nil {
		return table.SIDStructure{}, err
	}
	localArg, err := safecast.Uint8(s.GetLocalArg(), "SRv6 SID structure LocalArg")
	if err != nil {
		return table.SIDStructure{}, err
	}
	return table.SIDStructure{
		LocalBlock: localBlock,
		LocalNode:  localNode,
		LocalFunc:  localFunc,
		LocalArg:   localArg,
	}, nil
}

func getLsPrefixList(nlris []*api.NLRI, lsAttrPrefix *api.LsAttributePrefix) ([]table.TEDElem, error) {
	var lsPrefixList []table.TEDElem

	for _, nlri := range nlris {
		lsAddrPrefix := nlri.GetLsAddrPrefix()

		lsPrefix, err := getLsPrefix(lsAddrPrefix, lsAttrPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to get LS Prefix: %w", err)
		}
		lsPrefixList = append(lsPrefixList, lsPrefix)
	}
	return lsPrefixList, nil
}

// algo0PrefixSID returns the algorithm 0 Prefix-SID index, if present.
// The repeated field takes precedence when populated.
func algo0PrefixSID(lsAttrPrefix *api.LsAttributePrefix) (uint32, bool) {
	if sids := lsAttrPrefix.GetSrPrefixSids(); len(sids) > 0 {
		for _, sid := range sids {
			if sid.GetAlgorithm() == 0 {
				return sid.GetSid(), true
			}
		}
		return 0, false
	}
	if sid := lsAttrPrefix.GetSrPrefixSid(); sid != 0 {
		return sid, true
	}
	return 0, false
}

func getLsPrefix(typedLinkStateNLRI *api.LsAddrPrefix, lsAttrPrefix *api.LsAttributePrefix) (*table.LsPrefix, error) {
	var localNodeID string
	var localNodeAsn uint32
	var prefix []string

	if typedLinkStateNLRI == nil || typedLinkStateNLRI.Nlri == nil {
		return nil, errors.New("LS Prefix NLRI is nil")
	}

	sidIndex, hasSidIndex := algo0PrefixSID(lsAttrPrefix)

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
	lsPrefix.HasSidIndex = hasSidIndex

	if len(prefix) != 1 {
		return nil, errors.New("invalid prefix length: expected 1 prefix")
	}

	var err error
	lsPrefix.Prefix, err = netip.ParsePrefix(prefix[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse prefix: %w", err)
	}

	return lsPrefix, nil
}

func getLsSrv6SIDList(nlris []*api.NLRI, lsAttrSrv6SID *api.LsAttributeSrv6SID) ([]table.TEDElem, error) {
	var lsSrv6SIDList []table.TEDElem

	for _, nlri := range nlris {
		lsAddrPrefix := nlri.GetLsAddrPrefix()

		lsPrefix, err := getLsSrv6SID(lsAddrPrefix, lsAttrSrv6SID)
		if err != nil {
			return nil, fmt.Errorf("failed to get LS Prefix: %w", err)
		}
		lsSrv6SIDList = append(lsSrv6SIDList, lsPrefix)
	}

	return lsSrv6SIDList, nil
}

func getLsSrv6SID(typedLinkStateNLRI *api.LsAddrPrefix, lsAttrSrv6SID *api.LsAttributeSrv6SID) (*table.LsSrv6SID, error) {
	if typedLinkStateNLRI == nil {
		return nil, errors.New("LS SRv6 SID NLRI is nil")
	}

	srv6SIDStructure := lsAttrSrv6SID.GetSrv6SidStructure()
	endpointBehavior := lsAttrSrv6SID.GetSrv6EndpointBehavior()
	srv6SIDNLRI := typedLinkStateNLRI.Nlri.GetSrv6Sid()
	if srv6SIDNLRI == nil {
		return nil, errors.New("LS SRv6 SID NLRI is not an SRv6 SID type")
	}

	localNodeID := srv6SIDNLRI.GetLocalNode().GetIgpRouterId()
	localNodeASN := srv6SIDNLRI.GetLocalNode().GetAsn()
	srv6SIDs := srv6SIDNLRI.GetSrv6SidInformation().GetSids()
	multiTopoIDs := srv6SIDNLRI.GetMultiTopoId().GetMultiTopoIds()

	structure, err := srv6SIDStructureFromAPI(srv6SIDStructure)
	if err != nil {
		return nil, err
	}
	behavior, err := safecast.Uint16(endpointBehavior.GetEndpointBehavior(), "SRv6 SID endpoint behavior")
	if err != nil {
		return nil, err
	}
	flags, err := safecast.Uint8(endpointBehavior.GetFlags(), "SRv6 SID endpoint behavior flags")
	if err != nil {
		return nil, err
	}
	algorithm, err := safecast.Uint8(endpointBehavior.GetAlgorithm(), "SRv6 SID endpoint behavior algorithm")
	if err != nil {
		return nil, err
	}

	localNode := table.NewLsNode(localNodeASN, localNodeID)
	lsSrv6SID := table.NewLsSrv6SID(localNode)
	lsSrv6SID.SIDStructure = structure
	lsSrv6SID.EndpointBehavior.Behavior = behavior
	lsSrv6SID.EndpointBehavior.Flags = flags
	lsSrv6SID.EndpointBehavior.Algorithm = algorithm
	lsSrv6SID.Sids = srv6SIDs
	lsSrv6SID.MultiTopoIDs = multiTopoIDs

	return lsSrv6SID, nil
}
