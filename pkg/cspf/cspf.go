// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package cspf computes constrained shortest paths over the TED for dynamic SR Policies.
package cspf

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"

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

// PathScope constrains path computation to a single underlay plane.
// The plane must be fully specified; no implicit default is used.
type PathScope struct {
	Plane table.Plane
}

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

func validateMetricType(metric table.MetricType) error {
	if !metric.IsValid() {
		return invalidInputf("unsupported metric type %d", int(metric))
	}

	if metric == table.UnspecifiedMetric {
		return invalidInputf("metric type must be specified for path computation")
	}

	return nil
}

// CSPF computes the shortest path from srcRouterID to dstRouterID using the given metric and scope.
func CSPF(srcRouterID, dstRouterID string, metric table.MetricType, scope PathScope, ted *table.LsTED) ([]table.Segment, error) {
	if ted == nil {
		return nil, errors.New("ted is nil")
	}

	if err := validateMetricType(metric); err != nil {
		return nil, err
	}

	if err := scope.Plane.Validate(); err != nil {
		return nil, invalidInputf("invalid scope: %w", err)
	}

	segmentList, err := spf(srcRouterID, dstRouterID, metric, scope, ted.Nodes)
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
	scope PathScope,
	ted *table.LsTED,
) ([]table.Segment, error) {
	if ted == nil {
		return nil, errors.New("ted is nil")
	}

	if err := validateMetricType(metric); err != nil {
		return nil, err
	}

	if err := scope.Plane.Validate(); err != nil {
		return nil, invalidInputf("invalid scope: %w", err)
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
		sectionSegs, seg, err := buildSectionSegments(prev, wp, metric, scope, ted, fullList)
		if err != nil {
			return nil, err
		}

		fullList = append(fullList, sectionSegs...)
		fullList = appendIfNotDuplicate(fullList, seg)
		prev = wp.RouterID
	}

	return fullList, nil
}

func buildSectionSegments(
	prev string,
	wp table.Waypoint,
	metric table.MetricType,
	scope PathScope,
	ted *table.LsTED,
	fullList []table.Segment,
) (sectionSegs []table.Segment, waypointSeg table.Segment, err error) {
	sectionSegs, err = CSPF(prev, wp.RouterID, metric, scope, ted)
	if err != nil {
		return nil, nil, fmt.Errorf("CSPF failed between %s and %s: %w", prev, wp.RouterID, err)
	}

	sectionSegs = removeDuplicateFirst(fullList, sectionSegs)

	// Existence is guaranteed by the CSPF call above.
	node, _ := nodeInTED(ted.Nodes, wp.RouterID)

	waypointSeg, err = buildWaypointSegment(node, wp.SID, scope)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build segment for waypoint %s: %w", wp.RouterID, err)
	}

	return sectionSegs, waypointSeg, nil
}

func buildWaypointSegment(node *table.LsNode, explicitSID string, scope PathScope) (table.Segment, error) {
	if explicitSID != "" {
		return buildExplicitWaypointSegment(node, explicitSID, scope)
	}

	seg, err := node.NodeSegment(scope.Plane)
	if err != nil {
		return nil, topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
	}

	return seg, nil
}

// buildExplicitWaypointSegment parses and validates an explicit waypoint SID
// according to the scope's data plane.
func buildExplicitWaypointSegment(node *table.LsNode, explicitSID string, scope PathScope) (table.Segment, error) {
	switch scope.Plane.DataPlane {
	case table.DPSRv6:
		addr, err := netip.ParseAddr(explicitSID)
		if err != nil {
			return nil, invalidInputf("invalid explicit SID %q: %w", explicitSID, err)
		}

		sid, err := table.ParseSRv6SID(addr.Unmap().String())
		if err != nil {
			return nil, invalidInputf("explicit SID %q must be an IPv6 SRv6 SID: %w", explicitSID, err)
		}

		seg, err := table.NewSegmentSRv6WithNodeInfo(sid, node)
		if err != nil {
			return nil, topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
		}

		return seg, nil
	case table.DPSRMPLS:
		label, err := strconv.ParseUint(explicitSID, 10, 32)
		if err != nil {
			return nil, invalidInputf("invalid explicit SID %q: %w", explicitSID, err)
		}

		if label > uint64(table.MPLSLabelMax) {
			return nil, invalidInputf("explicit SID %q exceeds the maximum SR-MPLS label %d", explicitSID, table.MPLSLabelMax)
		}

		return table.NewSegmentSRMPLS(uint32(label)), nil
	default:
		return nil, invalidInputf("data plane must be specified to build a waypoint segment")
	}
}

func removeDuplicateFirst(fullList, section []table.Segment) []table.Segment {
	if len(fullList) > 0 && len(section) > 0 && table.SegmentsEqual(fullList[len(fullList)-1], section[0]) {
		return section[1:]
	}

	return section
}

func appendIfNotDuplicate(list []table.Segment, seg table.Segment) []table.Segment {
	if len(list) == 0 || !table.SegmentsEqual(list[len(list)-1], seg) {
		list = append(list, seg)
	}

	return list
}

func spf(srcRouterID, dstRouterID string, metricType table.MetricType, scope PathScope, network map[string]*table.LsNode) ([]table.Segment, error) {
	calculatingNodes, err := initNodeMap(srcRouterID, scope, network)
	if err != nil {
		return nil, err
	}

	if _, ok := nodeInTED(network, dstRouterID); !ok {
		return nil, invalidInputf("destination router %s not found in TED", dstRouterID)
	}

	for {
		calcNodeID, err := nextNode(calculatingNodes)
		if err != nil {
			return nil, err
		}

		if calcNodeID == dstRouterID {
			break
		}

		if err := updateNeighborCosts(calcNodeID, calculatingNodes, network, metricType, scope); err != nil {
			return nil, err
		}

		calculatingNodes[calcNodeID].calculated = true
	}

	return buildSegmentListFromPath(srcRouterID, dstRouterID, calculatingNodes), nil
}

func nodeInTED(network map[string]*table.LsNode, routerID string) (*table.LsNode, bool) {
	node, ok := network[routerID]
	if !ok || node == nil {
		return nil, false
	}

	return node, true
}

func initNodeMap(srcRouterID string, scope PathScope, network map[string]*table.LsNode) (map[string]*node, error) {
	srcNode, ok := nodeInTED(network, srcRouterID)
	if !ok {
		return nil, invalidInputf("source router %s not found in TED", srcRouterID)
	}

	startNodeSeg, err := srcNode.NodeSegment(scope.Plane)
	if err != nil {
		return nil, topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
	}

	startNode := newNode(srcRouterID, 0, startNodeSeg)
	startNode.calculated = false

	return map[string]*node{srcRouterID: startNode}, nil
}

// linkUsable is the sole edge filter for path computation.
// Unnumbered links remain usable; otherwise both endpoints must support the scope's family.
func linkUsable(link *table.LsLink, scope PathScope) bool {
	if link.Families().Has(scope.Plane.Family) {
		return true
	}

	return linkUnnumbered(link)
}

func linkUnnumbered(link *table.LsLink) bool {
	return !link.Local.IPv4.IsValid() && !link.Local.IPv6.IsValid() &&
		!link.Remote.IPv4.IsValid() && !link.Remote.IPv6.IsValid()
}

func updateNeighborCosts(calcNodeID string, calculatingNodes map[string]*node, network map[string]*table.LsNode, metricType table.MetricType, scope PathScope) error {
	calcNode, ok := nodeInTED(network, calcNodeID)
	if !ok {
		return topologyLimitationf(reasonTEDDataIncomplete, "router %s not found in TED", calcNodeID)
	}

	for _, link := range calcNode.Links {
		if link == nil || link.Remote.Node == nil {
			continue
		}

		if !linkUsable(link, scope) {
			continue
		}

		remoteRouterID := link.Remote.Node.RouterID

		if _, ok := nodeInTED(network, remoteRouterID); !ok {
			continue
		}

		metric, err := link.Metric(metricType)
		if err != nil {
			return topologyLimitationf(reasonMetricNotCarried, "%w", err)
		}

		if remoteNode, exists := calculatingNodes[remoteRouterID]; exists {
			if calculatingNodes[calcNodeID].cost+metric < remoteNode.cost {
				remoteNode.cost = calculatingNodes[calcNodeID].cost + metric
				remoteNode.prevNode = calcNodeID
			}
		} else {
			remoteNodeSeg, err := link.Remote.Node.NodeSegment(scope.Plane)
			if err != nil {
				return topologyLimitationf(reasonTEDDataIncomplete, "%w", err)
			}

			remoteNode := newNode(remoteRouterID, calculatingNodes[calcNodeID].cost+metric, remoteNodeSeg)
			remoteNode.prevNode = calcNodeID
			calculatingNodes[remoteRouterID] = remoteNode
		}
	}

	return nil
}

func buildSegmentListFromPath(srcRouterID, dstRouterID string, calculatingNodes map[string]*node) []table.Segment {
	segmentList := []table.Segment{}
	for pathNode := calculatingNodes[dstRouterID]; pathNode.id != srcRouterID; pathNode = calculatingNodes[pathNode.prevNode] {
		segmentList = append(segmentList, pathNode.nodeSegment)
	}

	for i, j := 0, len(segmentList)-1; i < j; i, j = i+1, j-1 {
		segmentList[i], segmentList[j] = segmentList[j], segmentList[i]
	}

	return segmentList
}

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
