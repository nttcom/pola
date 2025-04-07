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
	POLICY_DOWN    = PolicyState("down")
	POLICY_UP      = PolicyState("up")
	POLICY_ACTIVE  = PolicyState("active")
	POLICY_UNKNOWN = PolicyState("unknown")
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
	plspId uint32,
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
		PlspID:      plspId,
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

const SRV6_SID_BIT_LENGTH = 128

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
	BEHAVIOR_RESERVED uint16 = 0x0000
	BEHAVIOR_END      uint16 = 0x0001
	BEHAVIOR_END_X    uint16 = 0x0005
	BEHAVIOR_UN       uint16 = 0x0030
	BEHAVIOR_UA       uint16 = 0x0039
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
	if seg.LocalAddr.IsValid() {
		if seg.USid {
			if seg.RemoteAddr.IsValid() {
				return BEHAVIOR_UA
			} else {
				return BEHAVIOR_UN
			}
		} else {
			if seg.RemoteAddr.IsValid() {
				return BEHAVIOR_END_X
			} else {
				return BEHAVIOR_END
			}
		}
	} else {
		return BEHAVIOR_RESERVED
	}
}

func NewSegmentSRv6(sid netip.Addr) SegmentSRv6 {
	return SegmentSRv6{
		Sid: sid,
	}
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
