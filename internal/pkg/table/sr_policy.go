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

type SRPolicy struct {
	PlspId      uint32
	Name        string
	SegmentList []Segment
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	Color       uint32
	Preference  uint32
}

type Segment interface {
	SidString() string
}

func NewSegment(sid string) (seg Segment, err error) {

	if addr, err := netip.ParseAddr(sid); err == nil && addr.Is6() {
		seg = NewSegmentSRv6(addr)
	} else if i, err := strconv.ParseUint(sid, 10, 32); err == nil {
		seg = NewSegmentSRMPLS(uint32(i))
	} else {
		return nil, errors.New("invalid SID")
	}
	return seg, nil
}

type SegmentSRv6 struct {
	Sid netip.Addr
}

func (seg SegmentSRv6) SidString() string {
	return seg.Sid.String()
}

func NewSegmentSRv6(sid netip.Addr) (seg SegmentSRv6) {
	seg = SegmentSRv6{
		Sid: sid,
	}
	return seg
}

type SegmentSRMPLS struct {
	Sid uint32
}

func (seg SegmentSRMPLS) SidString() string {
	return strconv.Itoa(int(seg.Sid))
}

func NewSegmentSRMPLS(sid uint32) (seg SegmentSRMPLS) {
	seg = SegmentSRMPLS{
		Sid: sid,
	}
	return seg
}
