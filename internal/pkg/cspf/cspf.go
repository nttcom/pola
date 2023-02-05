// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf

import (
	"errors"

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
	node := &node{
		id:          id,
		cost:        cost,
		nodeSegment: nodeSeg,
	}
	return node
}

func Cspf(srcRouterId string, dstRouterId string, as uint32, metric table.MetricType, ted *table.LsTed) ([]table.Segment, error) {
	network := ted.Nodes[as]
	// TODO: update network information according to constraints
	segmentList, err := spf(srcRouterId, dstRouterId, metric, network)
	if err != nil {
		return nil, err
	}
	return segmentList, nil
}

func spf(srcRouterId string, dstRouterId string, metric table.MetricType, network map[string]*table.LsNode) ([]table.Segment, error) {
	segmentList := []table.Segment{}

	startNodeSeg, err := network[srcRouterId].NodeSegment()
	if err != nil {
		return nil, err
	}

	startNode := newNode(srcRouterId, 0, startNodeSeg)
	startNode.calculated = false

	calculatingNodes := map[string]*node{}
	calculatingNodes[srcRouterId] = startNode

	for {
		// Selection of nodes for calculation
		calcNodeId, err := nextNode(calculatingNodes)
		if err != nil {
			return nil, err
		}

		if calcNodeId == dstRouterId {
			// End of calculation of shortest path
			break
		}

		for _, link := range network[calcNodeId].Links {
			metric, err := link.Metric(metric)
			if err != nil {
				return nil, err
			}

			if _, exist := calculatingNodes[link.RemoteNode.RouterId]; exist {
				if calculatingNodes[calcNodeId].cost+metric < calculatingNodes[link.RemoteNode.RouterId].cost {
					calculatingNodes[link.RemoteNode.RouterId].cost = calculatingNodes[calcNodeId].cost + metric
					calculatingNodes[link.RemoteNode.RouterId].prevNode = calcNodeId
				}
			} else {
				remoteNodeSeg, err := link.RemoteNode.NodeSegment()
				if err != nil {
					return nil, err
				}

				calculatingNodes[link.RemoteNode.RouterId] = newNode(link.RemoteNode.RouterId, calculatingNodes[calcNodeId].cost+metric, remoteNodeSeg)
				calculatingNodes[link.RemoteNode.RouterId].prevNode = calcNodeId
			}
		}
	}

	// Generate SegmentList from calculation results
	for pathNode := calculatingNodes[dstRouterId]; pathNode.id != srcRouterId; pathNode = calculatingNodes[pathNode.prevNode] {
		if len(segmentList) == 0 {
			segmentList = append(segmentList, pathNode.nodeSegment)
		} else {
			segmentList = append(segmentList[:1], segmentList[0:]...)
			segmentList[0] = pathNode.nodeSegment
		}
	}
	return segmentList, nil
}

func nextNode(calculatingNodes map[string]*node) (nextNodeId string, err error) {
	for nodeId, node := range calculatingNodes {
		if node.calculated {
			continue
		}
		if nextNodeId == "" {
			nextNodeId = nodeId
		}
		if calculatingNodes[nextNodeId].cost > node.cost {
			nextNodeId = nodeId
		}
	}
	if nextNodeId == "" {
		return nextNodeId, errors.New("next node not found")
	}
	// Set the node with the smallest arrival cost as calculated
	calculatingNodes[nextNodeId].calculated = true
	return
}
