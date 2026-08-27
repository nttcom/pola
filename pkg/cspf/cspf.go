// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/nttcom/pola/pkg/table"
)

// InvalidInputError indicates that path computation failed due to invalid input.
type InvalidInputError struct {
	Err error
}

func (e *InvalidInputError) Error() string { return e.Err.Error() }
func (e *InvalidInputError) Unwrap() error { return e.Err }

func invalidInputf(format string, a ...any) error {
	return &InvalidInputError{Err: fmt.Errorf(format, a...)}
}

// TopologyLimitationError indicates that path computation failed due to the current TED.
type TopologyLimitationError struct {
	Err    error
	Reason string
}

func (e *TopologyLimitationError) Error() string { return e.Err.Error() }
func (e *TopologyLimitationError) Unwrap() error { return e.Err }

func topologyLimitationf(reason, format string, a ...any) error {
	return &TopologyLimitationError{Err: fmt.Errorf(format, a...), Reason: reason}
}

const (
	reasonTEDDataIncomplete      = "TED_DATA_INCOMPLETE"
	reasonMetricNotCarried       = "METRIC_NOT_CARRIED"
	reasonDestinationUnreachable = "DESTINATION_UNREACHABLE"
)

const errNextNodeNotFound = "next node not found"

type node struct {
	id          string
	calculated  bool
	cost        uint32
	prevNode    string
	nodeSegment table.Segment
}

func newNode(id string, cost uint32, nodeSeg table.Segment) *node {
	return &node{
		id:          id,
		cost:        cost,
		nodeSegment: nodeSeg,
	}
}

// validateMetricType rejects metric types that cannot be used for path computation.
func validateMetricType(metric table.MetricType) error {
	if !metric.IsValid() {
		return invalidInputf("unsupported metric type %d", int(metric))
	}
	if metric == table.UnspecifiedMetric {
		return invalidInputf("metric type must be specified for path computation")
	}
	return nil
}

// CSPF computes the shortest path from srcRouterID to dstRouterID using the given metric.
func CSPF(srcRouterID string, dstRouterID string, metric table.MetricType, ted *table.LsTED) ([]table.Segment, error) {
	if ted == nil {
		return nil, errors.New("ted is nil")
	}
	if err := validateMetricType(metric); err != nil {
		return nil, err
	}

	segmentList, err := spf(srcRouterID, dstRouterID, metric, ted.Nodes)
	if err != nil {
		return nil, err
	}

	return segmentList, nil
}

// WithLooseSourceRouting computes a path with optional waypoints using loose source routing.
func WithLooseSourceRouting(
	src, dst string,
	waypoints []table.Waypoint,
	metric table.MetricType,
	ted *table.LsTED,
) ([]table.Segment, error) {
	if ted == nil {
		return nil, errors.New("ted is nil")
	}
	if err := validateMetricType(metric); err != nil {
		return nil, err
	}

	// Validate waypoints before computing any section.
	for _, wp := range waypoints {
		if _, ok := nodeInTED(ted.Nodes, wp.RouterID); !ok {
			return nil, invalidInputf("waypoint router %s not found in TED", wp.RouterID)
		}
	}

	fullList := []table.Segment{}
	prev := src

	// Append the destination without modifying the input slice.
	allWaypoints := append(append([]table.Waypoint{}, waypoints...), table.Waypoint{RouterID: dst})

	for _, wp := range allWaypoints {
		sectionSegs, seg, err := buildSectionSegments(prev, wp, metric, ted, fullList)
		if err != nil {
			return nil, err
		}
		fullList = append(fullList, sectionSegs...)
		fullList = appendIfNotDuplicate(fullList, seg)
		prev = wp.RouterID
	}

	return fullList, nil
}

// buildSectionSegments calculates CSPF to waypoint and builds the waypoint segment.
func buildSectionSegments(prev string, wp table.Waypoint, metric table.MetricType, ted *table.LsTED, fullList []table.Segment) ([]table.Segment, table.Segment, error) {
	// Compute CSPF from prev → waypoint
	sectionSegs, err := CSPF(prev, wp.RouterID, metric, ted)
	if err != nil {
		return nil, nil, fmt.Errorf("CSPF failed between %s and %s: %w", prev, wp.RouterID, err)
	}

	// Remove first segment if it duplicates the last segment of the previous sections
	sectionSegs = removeDuplicateFirst(fullList, sectionSegs)

	// Lookup the node from TED; existence is already guaranteed by the CSPF call above.
	node, _ := nodeInTED(ted.Nodes, wp.RouterID)

	// Build the segment (SRv6 or SR-MPLS)
	seg, err := buildWaypointSegment(node, wp.SID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build segment for waypoint %s: %w", wp.RouterID, err)
	}

	return sectionSegs, seg, nil
}

// buildWaypointSegment builds a Segment for a waypoint using the node and optional explicit SID.
func buildWaypointSegment(node *table.LsNode, explicitSID string) (table.Segment, error) {
	if explicitSID != "" {
		addr, err := netip.ParseAddr(explicitSID)
		if err != nil {
			return nil, invalidInputf("invalid explicit SID %q: %w", explicitSID, err)
		}
		// Explicit SID must be an IPv6 address.
		addr = addr.Unmap()
		if !addr.Is6() {
			return nil, invalidInputf("explicit SID %q must be an IPv6 SRv6 SID", explicitSID)
		}
		seg, err := table.NewSegmentSRv6WithNodeInfo(addr, node)
		if err != nil {
			return nil, topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
		}
		return seg, nil
	}
	seg, err := node.NodeSegment()
	if err != nil {
		return nil, topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
	}
	return seg, nil
}

// removeDuplicateFirst removes the first segment of section if it equals the last of fullList.
func removeDuplicateFirst(fullList []table.Segment, section []table.Segment) []table.Segment {
	if len(fullList) > 0 && len(section) > 0 && table.SegmentsEqual(fullList[len(fullList)-1], section[0]) {
		return section[1:]
	}
	return section
}

// appendIfNotDuplicate appends a segment to the list if it is not equal to the last segment.
func appendIfNotDuplicate(list []table.Segment, seg table.Segment) []table.Segment {
	if len(list) == 0 || !table.SegmentsEqual(list[len(list)-1], seg) {
		list = append(list, seg)
	}
	return list
}

func spf(srcRouterID string, dstRouterID string, metricType table.MetricType, network map[string]*table.LsNode) ([]table.Segment, error) {
	calculatingNodes, err := initNodeMap(srcRouterID, network)
	if err != nil {
		return nil, err
	}

	if _, ok := nodeInTED(network, dstRouterID); !ok {
		return nil, invalidInputf("destination router %s not found in TED", dstRouterID)
	}

	// Keep calculating the shortest path until the destination node is reached.
	for {
		calcNodeID, err := nextNode(calculatingNodes)
		if err != nil {
			return nil, err
		}
		if calcNodeID == dstRouterID {
			break
		}

		if err := updateNeighborCosts(calcNodeID, calculatingNodes, network, metricType); err != nil {
			return nil, err
		}

		calculatingNodes[calcNodeID].calculated = true
	}

	return buildSegmentListFromPath(srcRouterID, dstRouterID, calculatingNodes), nil
}

// nodeInTED returns the node for routerID if it exists and is non-nil.
func nodeInTED(network map[string]*table.LsNode, routerID string) (*table.LsNode, bool) {
	node, ok := network[routerID]
	if !ok || node == nil {
		return nil, false
	}
	return node, true
}

// initNodeMap initializes the map of nodes used for SPF calculation.
func initNodeMap(srcRouterID string, network map[string]*table.LsNode) (map[string]*node, error) {
	srcNode, ok := nodeInTED(network, srcRouterID)
	if !ok {
		return nil, invalidInputf("source router %s not found in TED", srcRouterID)
	}
	startNodeSeg, err := srcNode.NodeSegment()
	if err != nil {
		return nil, topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
	}
	startNode := newNode(srcRouterID, 0, startNodeSeg)
	startNode.calculated = false
	return map[string]*node{srcRouterID: startNode}, nil
}

// updateNeighborCosts updates costs for neighbors of the given node in SPF calculation.
func updateNeighborCosts(calcNodeID string, calculatingNodes map[string]*node, network map[string]*table.LsNode, metricType table.MetricType) error {
	calcNode, ok := nodeInTED(network, calcNodeID)
	if !ok {
		return topologyLimitationf(reasonTEDDataIncomplete, "router %s not found in TED", calcNodeID)
	}

	for _, link := range calcNode.Links {
		if link == nil || link.RemoteNode == nil {
			continue
		}
		if _, ok := nodeInTED(network, link.RemoteNode.RouterID); !ok {
			continue
		}

		metric, err := link.Metric(metricType)
		if err != nil {
			return topologyLimitationf(reasonMetricNotCarried, "%w", err)
		}

		if remoteNode, exists := calculatingNodes[link.RemoteNode.RouterID]; exists {
			if calculatingNodes[calcNodeID].cost+metric < remoteNode.cost {
				remoteNode.cost = calculatingNodes[calcNodeID].cost + metric
				remoteNode.prevNode = calcNodeID
			}
		} else {
			remoteNodeSeg, err := link.RemoteNode.NodeSegment()
			if err != nil {
				return topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
			}
			remoteNode := newNode(link.RemoteNode.RouterID, calculatingNodes[calcNodeID].cost+metric, remoteNodeSeg)
			remoteNode.prevNode = calcNodeID
			calculatingNodes[link.RemoteNode.RouterID] = remoteNode
		}
	}
	return nil
}

// buildSegmentListFromPath builds the segment list from SPF results.
func buildSegmentListFromPath(srcRouterID, dstRouterID string, calculatingNodes map[string]*node) []table.Segment {
	segmentList := []table.Segment{}
	for pathNode := calculatingNodes[dstRouterID]; pathNode.id != srcRouterID; pathNode = calculatingNodes[pathNode.prevNode] {
		segmentList = append(segmentList, pathNode.nodeSegment)
	}

	// Reverse the segment list to get correct order from src → dst
	for i, j := 0, len(segmentList)-1; i < j; i, j = i+1, j-1 {
		segmentList[i], segmentList[j] = segmentList[j], segmentList[i]
	}

	return segmentList
}

// nextNode returns the ID of the next node to calculate.
func nextNode(calculatingNodes map[string]*node) (string, error) {
	nextNodeID := ""
	for nodeID, node := range calculatingNodes {
		if node.calculated {
			continue
		}
		if nextNodeID == "" || calculatingNodes[nextNodeID].cost > node.cost {
			nextNodeID = nodeID
		}
	}
	if nextNodeID == "" {
		return "", topologyLimitationf(reasonDestinationUnreachable, errNextNodeNotFound)
	}
	return nextNodeID, nil
}
