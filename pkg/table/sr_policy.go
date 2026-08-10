// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// sr-policy state
type PolicyState string

const (
	PolicyDown    = PolicyState("down")
	PolicyUp      = PolicyState("up")
	PolicyActive  = PolicyState("active")
	PolicyUnknown = PolicyState("unknown")
)

// PolicyType is the RFC 9256 §2.4.2 SR Policy candidate path type: a candidate path
// is either explicit (a fixed SID list) or dynamic (computed against an optimization
// metric and subject to recomputation). The zero value means "not known": PCEP
// carries no TLV for this on PCRpt, so it can only be known for policies Pola itself
// created (see Session.RememberSRPolicyIntent).
type PolicyType string

const (
	PolicyTypeExplicit = PolicyType("explicit")
	PolicyTypeDynamic  = PolicyType("dynamic")
)

type SRPolicy struct {
	PlspID      uint32      `json:"plspId,omitempty"`
	Name        string      `json:"policyName"`
	SegmentList []Segment   `json:"segmentList"`
	SrcAddr     netip.Addr  `json:"srcAddr"`
	DstAddr     netip.Addr  `json:"dstAddr"`
	SrcRouterID string      `json:"srcRouterId,omitempty"`
	DstRouterID string      `json:"dstRouterId,omitempty"`
	Color       uint32      `json:"color"`
	Preference  uint32      `json:"preference"`
	LSPID       uint16      `json:"lspId,omitempty"`
	State       PolicyState `json:"state,omitempty"`
	// Type and Metric are only known for policies Pola itself created; both are
	// left at their zero value ("" / UnspecifiedMetric) otherwise. See PolicyType.
	Type   PolicyType `json:"type,omitempty"`
	Metric MetricType `json:"metric,omitempty"`
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

func segmentFamily(segment Segment) SegmentFamily {
	switch segment.(type) {
	case SegmentSRv6:
		return SegmentSRv6Family
	case SegmentSRMPLS:
		return SegmentSRMPLSFamily
	default:
		return SegmentUnknown
	}
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

const FirstSIDIndex = 0 // Index for first SID in Sids array

// SIDStructureBytes is the [LocalBlock, LocalNode, LocalFunc, LocalArg] length split of an SRv6 SID.
// It marshals as a comma-separated string (e.g. "32,16,0,80").
type SIDStructureBytes []uint8

func (s SIDStructureBytes) MarshalJSON() ([]byte, error) {
	if len(s) == 0 {
		return json.Marshal(nil)
	}
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = strconv.Itoa(int(v))
	}
	return json.Marshal(strings.Join(parts, ","))
}

type SegmentSRv6 struct {
	Sid        netip.Addr        `json:"sid"`
	LocalAddr  netip.Addr        `json:"localAddr,omitzero"`
	RemoteAddr netip.Addr        `json:"remoteAddr,omitzero"`
	Structure  SIDStructureBytes `json:"sidStructure,omitempty"`
	USid       bool              `json:"uSid,omitempty"`
}

func (seg SegmentSRv6) SidString() string {
	return seg.Sid.String()
}

func (seg SegmentSRv6) Behavior() (uint16, error) {
	if !seg.LocalAddr.IsValid() {
		return 0, errors.New("SegmentSRv6: LocalAddr is invalid")
	}
	if seg.USid {
		if seg.RemoteAddr.IsValid() {
			return BehaviorUA, nil
		}
		return BehaviorUN, nil
	}
	if seg.RemoteAddr.IsValid() {
		return BehaviorENDX, nil
	}
	return BehaviorEND, nil
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

	var found bool
	for _, srv6SID := range n.SRv6SIDs {
		if len(srv6SID.Sids) > 0 {
			addr, err := netip.ParseAddr(srv6SID.Sids[FirstSIDIndex])
			if err != nil {
				return seg, err
			}
			seg.LocalAddr = addr
			seg.Structure = SIDStructureBytes{
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
			found = true
			break
		}
	}
	if !found {
		return seg, errors.New("no SRv6 SIDs available")
	}
	return seg, nil
}

type SegmentSRMPLS struct {
	Sid uint32 `json:"sid"`
	TTL uint8  `json:"ttl,omitempty"`
	TC  uint8  `json:"tc,omitempty"`
	S   bool   `json:"s,omitempty"`
	// Optional NAI for SR-ERO encoding (RFC8664 4.3.1).
	LocalAddr  netip.Addr `json:"localAddr,omitzero"`
	RemoteAddr netip.Addr `json:"remoteAddr,omitzero"`
}

func (seg SegmentSRMPLS) SidString() string {
	return strconv.Itoa(int(seg.Sid))
}

func (seg SegmentSRMPLS) HasMPLSStackEntryAttrs() bool {
	return seg.TC != 0 || seg.S || seg.TTL != 0
}

func NewSegmentSRMPLS(sid uint32) SegmentSRMPLS {
	return SegmentSRMPLS{
		Sid: sid,
	}
}

// Equal for SegmentSRv6
func (seg SegmentSRv6) Equal(other SegmentSRv6) bool {
	// Compare SID, LocalAddr, and RemoteAddr
	return seg.Sid == other.Sid &&
		seg.LocalAddr == other.LocalAddr &&
		seg.RemoteAddr == other.RemoteAddr
}

// Equal for SegmentSRMPLS
func (seg SegmentSRMPLS) Equal(other SegmentSRMPLS) bool {
	// Compare MPLS SID only: the NAI does not change which hop the label is.
	return seg.Sid == other.Sid
}

// Helper function for Segment interface equality check
func SegmentsEqual(a, b Segment) bool {
	switch sa := a.(type) {
	case SegmentSRv6:
		sb, ok := b.(SegmentSRv6)
		return ok && sa.Equal(sb)
	case SegmentSRMPLS:
		sb, ok := b.(SegmentSRMPLS)
		return ok && sa.Equal(sb)
	default:
		return false
	}
}

// Waypoint represents a loose hop for SR Policy computation.
// SID is optional: if empty, TED lookup will be used to find End SID for that router.
type Waypoint struct {
	RouterID string
	SID      string // optional: fixed SID override
}

type SegmentFamily int

const (
	SegmentUnknown SegmentFamily = iota
	SegmentSRv6Family
	SegmentSRMPLSFamily
)
