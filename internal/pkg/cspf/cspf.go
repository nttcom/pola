// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/nttcom/pola/internal/pkg/table"
)

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

func CSPF(srcRouterID string, dstRouterID string, as uint32, metric table.MetricType, ted *table.LsTED) ([]table.Segment, error) {
	network := ted.Nodes[as]
	// TODO: update network information according to constraints
	segmentList, err := spf(srcRouterID, dstRouterID, metric, network)
	if err != nil {
		return nil, err
	}

	return segmentList, nil
}

// CSPFWithLooseSourceRouting computes a path with optional waypoints using loose source routing.
func CSPFWithLooseSourceRouting(
	src, dst string,
	waypoints []table.Waypoint,
	as uint32,
	metric table.MetricType,
	ted *table.LsTED,
) ([]table.Segment, error) {
	fullList := []table.Segment{}
	prev := src

	// Append destination as a pseudo-waypoint
	allWaypoints := append(waypoints, table.Waypoint{RouterID: dst})

	for _, wp := range allWaypoints {
		sectionSegs, seg, err := buildSectionSegments(prev, wp, as, metric, ted)
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
func buildSectionSegments(prev string, wp table.Waypoint, as uint32, metric table.MetricType, ted *table.LsTED) ([]table.Segment, table.Segment, error) {
	// Compute CSPF from prev → waypoint
	sectionSegs, err := CSPF(prev, wp.RouterID, as, metric, ted)
	if err != nil {
		return nil, nil, fmt.Errorf("CSPF failed between %s and %s: %w", prev, wp.RouterID, err)
	}
	sectionSegs = removeDuplicateFirst(nil, sectionSegs)

	// Lookup the node from TED
	node, ok := ted.Nodes[as][wp.RouterID]
	if !ok {
		return nil, nil, fmt.Errorf("waypoint router %s not found in TED", wp.RouterID)
	}

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
			return nil, fmt.Errorf("invalid explicit SID %q: %w", explicitSID, err)
		}
		return table.NewSegmentSRv6WithNodeInfo(addr, node)
	}
	return node.NodeSegment()
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
	// Create a new starting node with cost 0 and add it to the calculating nodes
	startNodeSeg, err := network[srcRouterID].NodeSegment()
	if err != nil {
		return nil, err
	}
	startNode := newNode(srcRouterID, 0, startNodeSeg)
	startNode.calculated = false
	calculatingNodes := map[string]*node{srcRouterID: startNode}

	// Keep calculating the shortest path until the destination node is reached
	for {
		// Select the next node to calculate
		calcNodeID, err := nextNode(calculatingNodes)
		if err != nil {
			return nil, err
		}
		if calcNodeID == dstRouterID {
			break
		}

		// Calculate the cost of each link from the selected node
		for _, link := range network[calcNodeID].Links {
			metric, err := link.Metric(metricType)
			if err != nil {
				return nil, err
			}

			// If the remote node is already being calculated, update its cost if necessary
			if remoteNode, exists := calculatingNodes[link.RemoteNode.RouterID]; exists {
				if calculatingNodes[calcNodeID].cost+metric < remoteNode.cost {
					remoteNode.cost = calculatingNodes[calcNodeID].cost + metric
					remoteNode.prevNode = calcNodeID
				}
			} else {
				// If the remote node has not been calculated yet, create a new node for it and add it to the calculating nodes
				remoteNodeSeg, err := link.RemoteNode.NodeSegment()
				if err != nil {
					return nil, err
				}
				remoteNode := newNode(link.RemoteNode.RouterID, calculatingNodes[calcNodeID].cost+metric, remoteNodeSeg)
				remoteNode.prevNode = calcNodeID
				calculatingNodes[link.RemoteNode.RouterID] = remoteNode
			}
		}

		// Mark the selected node as calculated
		calculatingNodes[calcNodeID].calculated = true
	}

	// Generate the segment list from the shortest path calculation results
	segmentList := []table.Segment{}
	for pathNode := calculatingNodes[dstRouterID]; pathNode.id != srcRouterID; pathNode = calculatingNodes[pathNode.prevNode] {
		segmentList = append(segmentList, pathNode.nodeSegment)
	}

	// Reverse the order of the segment list
	for i, j := 0, len(segmentList)-1; i < j; i, j = i+1, j-1 {
		segmentList[i], segmentList[j] = segmentList[j], segmentList[i]
	}

	return segmentList, nil
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
		return "", errors.New("next node not found")
	}
	return nextNodeID, nil
}
