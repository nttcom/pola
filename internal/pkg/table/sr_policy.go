// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"errors"
	"net/netip"
	"strconv"
)

// sr-policy state
type PolicyState string

const (
	PolicyDown    = PolicyState("down")
	PolicyUp      = PolicyState("up")
	PolicyActive  = PolicyState("active")
	PolicyUnknown = PolicyState("unknown")
)

type SRPolicy struct {
	PlspID      uint32
	Name        string
	SegmentList []Segment
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	Color       uint32
	Preference  uint32
	LSPID       uint16
	State       PolicyState
}

func NewSRPolicy(
	plspID uint32,
	name string,
	segmentList []Segment,
	srcAddr netip.Addr,
	dstAddr netip.Addr,
	color uint32,
	preference uint32,
	lspID uint16,
	state PolicyState,
) *SRPolicy {
	p := &SRPolicy{
		PlspID:      plspID,
		Name:        name,
		SegmentList: segmentList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       color,
		Preference:  preference,
		LSPID:       lspID,
		State:       state,
	}

	return p
}

// SR Policy parameter that can be changed
type PolicyDiff struct {
	Name        *string
	Color       *uint32
	Preference  *uint32
	SegmentList []Segment
	LSPID       uint16
	State       PolicyState
}

func (p *SRPolicy) Update(df PolicyDiff) {
	p.State = df.State
	p.LSPID = df.LSPID
	if df.Name != nil {
		p.Name = *df.Name
	}
	if df.Color != nil {
		p.Color = *df.Color
	}
	if df.Preference != nil {
		p.Preference = *df.Preference
	}
	if df.SegmentList != nil {
		p.SegmentList = df.SegmentList
	}
}

const SRv6SIDBitLength = 128

type Segment interface {
	SidString() string
}

func NewSegment(sid string) (Segment, error) {
	addr, err := netip.ParseAddr(sid)
	if err == nil && addr.Is6() {
		return NewSegmentSRv6(addr), nil
	}

	i, err := strconv.ParseUint(sid, 10, 32)
	if err == nil {
		return NewSegmentSRMPLS(uint32(i)), nil
	}

	return nil, errors.New("invalid SID")
}

const (
	BehaviorReserved uint16 = 0x0000
	BehaviorEND      uint16 = 0x0001
	BehaviorENDX     uint16 = 0x0005
	BehaviorUN       uint16 = 0x0030
	BehaviorUA       uint16 = 0x0039
)

func BehaviorToString(behavior uint16) string {
	switch behavior {
	case BehaviorReserved:
		return "RESERVED"
	case BehaviorEND:
		return "END"
	case BehaviorENDX:
		return "ENDX"
	case BehaviorUN:
		return "UN"
	case BehaviorUA:
		return "UA"
	default:
		return "UNKNOWN"
	}
}

const (
	FirstSRv6SIDIndex = 0 // Index for first SRv6 SID in array
	FirstSIDIndex     = 0 // Index for first SID in Sids array
)

type SegmentSRv6 struct {
	Sid        netip.Addr
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	Structure  []uint8
	USid       bool
}

func (seg SegmentSRv6) SidString() string {
	return seg.Sid.String()
}

func (seg SegmentSRv6) Behavior() uint16 {
	if !seg.LocalAddr.IsValid() {
		return BehaviorReserved
	}
	if seg.USid {
		if seg.RemoteAddr.IsValid() {
			return BehaviorUA
		}
		return BehaviorUN
	}
	if seg.RemoteAddr.IsValid() {
		return BehaviorENDX
	}
	return BehaviorEND
}

func NewSegmentSRv6(sid netip.Addr) SegmentSRv6 {
	return SegmentSRv6{
		Sid: sid,
	}
}

func NewSegmentSRv6WithNodeInfo(sid netip.Addr, n *LsNode) (SegmentSRv6, error) {
	seg := SegmentSRv6{
		Sid: sid,
	}

	if len(n.SRv6SIDs) == 0 || len(n.SRv6SIDs[FirstSRv6SIDIndex].Sids) == 0 {
		return seg, errors.New("no SRv6 SIDs available")
	}

	addr, err := netip.ParseAddr(n.SRv6SIDs[FirstSRv6SIDIndex].Sids[FirstSIDIndex])
	if err != nil {
		return seg, err
	}
	seg.LocalAddr = addr

	for _, srv6SID := range n.SRv6SIDs {
		if len(srv6SID.Sids) > 0 {
			seg.Structure = []uint8{
				srv6SID.SIDStructure.LocalBlock,
				srv6SID.SIDStructure.LocalNode,
				srv6SID.SIDStructure.LocalFunc,
				srv6SID.SIDStructure.LocalArg,
			}

			switch srv6SID.EndpointBehavior.Behavior {
			case BehaviorUN, BehaviorUA:
				seg.USid = true
			default:
				seg.USid = false
			}
			break
		}
	}

	return seg, nil
}

type SegmentSRMPLS struct {
	Sid uint32
}

func (seg SegmentSRMPLS) SidString() string {
	return strconv.Itoa(int(seg.Sid))
}

func NewSegmentSRMPLS(sid uint32) SegmentSRMPLS {
	return SegmentSRMPLS{
		Sid: sid,
	}
}
