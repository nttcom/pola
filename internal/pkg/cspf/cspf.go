// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf

import (
	"errors"
	"net"

	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/pkg/packet/pcep"
)

type node struct {
	id         string
	calculated bool
	cost       uint32
	prevNode   string
	nodeSid    uint32
	LoAddr     net.IP
}

func newNode(id string, cost uint32, nodeSid uint32, loAddr net.IP) *node {
	node := &node{
		id:      id,
		cost:    cost,
		nodeSid: nodeSid,
		LoAddr:  loAddr,
	}
	return node
}

func Cspf(srcRouterId string, dstRouterId string, as uint32, metric table.MetricType, ted *table.LsTed) ([]pcep.Label, error) {
	network := ted.Nodes[as]
	// TODO: update network information according to constraints
	segmentList, err := spf(srcRouterId, dstRouterId, metric, network)
	if err != nil {
		return nil, err
	}
	return segmentList, nil
}

func spf(srcRouterId string, dstRouterId string, metric table.MetricType, network map[string]*table.LsNode) ([]pcep.Label, error) {
	segmentList := []pcep.Label{}

	startNodeSid, err := network[srcRouterId].NodeSid()
	if err != nil {
		return nil, err
	}

	startNodeLoAddr, err := network[srcRouterId].LoopbackAddr()
	if err != nil {
		return nil, err
	}

	startNode := newNode(srcRouterId, 0, startNodeSid, startNodeLoAddr)
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
				remoteNodeSid, err := link.RemoteNode.NodeSid()
				if err != nil {
					return nil, err
				}

				remoteNodeLoAddr, err := link.RemoteNode.LoopbackAddr()
				if err != nil {
					return nil, err
				}

				calculatingNodes[link.RemoteNode.RouterId] = newNode(link.RemoteNode.RouterId, calculatingNodes[calcNodeId].cost+metric, remoteNodeSid, remoteNodeLoAddr)
				calculatingNodes[link.RemoteNode.RouterId].prevNode = calcNodeId
			}
		}
	}

	// Generate SegmentList from calculation results
	for pathNode := calculatingNodes[dstRouterId]; pathNode.id != srcRouterId; pathNode = calculatingNodes[pathNode.prevNode] {
		segment := pcep.Label{
			Sid:    pathNode.nodeSid,
			LoAddr: pathNode.LoAddr.To4(),
		}
		if len(segmentList) == 0 {
			segmentList = append(segmentList, segment)
		} else {
			segmentList = append(segmentList[:1], segmentList[0:]...)
			segmentList[0] = segment
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
