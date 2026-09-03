// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// PolicyState represents the state of an SR Policy.
type PolicyState string

const (
	// PolicyDown indicates that the SR Policy is down.
	PolicyDown = PolicyState("down")
	// PolicyUp indicates that the SR Policy is up.
	PolicyUp = PolicyState("up")
	// PolicyActive indicates that the SR Policy is active.
	PolicyActive = PolicyState("active")
	// PolicyUnknown indicates that the SR Policy state is unknown.
	PolicyUnknown = PolicyState("unknown")
)

// PolicyType is the SR Policy candidate path type defined in RFC 9256 §2.4.2.
// The zero value means the type is unknown.
type PolicyType string

const (
	// PolicyTypeExplicit indicates an explicit path SR Policy candidate path.
	PolicyTypeExplicit = PolicyType("explicit")
	// PolicyTypeDynamic indicates a dynamic SR Policy candidate path.
	PolicyTypeDynamic = PolicyType("dynamic")
)

// SRPolicy represents an SR Policy with its path and attributes.
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
	// Type and Metric are only known for policies created by Pola.
	Type   PolicyType `json:"type,omitempty"`
	Metric MetricType `json:"metric,omitempty"`
}

// NewSRPolicy creates a new SR Policy with the given attributes.
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

// PolicyDiff contains SR Policy parameters that can be changed.
type PolicyDiff struct {
	Name        *string
	Color       *uint32
	Preference  *uint32
	SegmentList []Segment
	LSPID       uint16
	State       PolicyState
}

// Update modifies the SR Policy with the attributes specified in the diff.
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

// SRv6SIDBitLength is the bit length of an SRv6 SID (128 bits).
const SRv6SIDBitLength = 128

// Segment is an interface for SR Policy segments (SRv6 or SR-MPLS).
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

// NewSegment creates a Segment from a SID string, which can be either an IPv6 address (SRv6) or a number (SR-MPLS).
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
	// BehaviorReserved is a reserved endpoint behavior value.
	BehaviorReserved uint16 = 0x0000
	// BehaviorEND is the END endpoint behavior.
	BehaviorEND uint16 = 0x0001
	// BehaviorENDX is the End.X endpoint behavior.
	BehaviorENDX uint16 = 0x0005
	// BehaviorUNFirst is the first uN endpoint behavior value.
	BehaviorUNFirst uint16 = 0x002B
	// BehaviorUNLast is the last uN endpoint behavior value.
	BehaviorUNLast uint16 = 0x0032
	// BehaviorUAFirst is the first uA endpoint behavior value.
	BehaviorUAFirst uint16 = 0x0034
	// BehaviorUALast is the last uA endpoint behavior value.
	BehaviorUALast uint16 = 0x003B
	// BehaviorUN is the uN endpoint behavior.
	BehaviorUN uint16 = 0x0030
	// BehaviorUA is the uA endpoint behavior.
	BehaviorUA uint16 = 0x0039
	// BehaviorOpaque represents an unknown endpoint behavior (RFC 9603 §4.3.1).
	BehaviorOpaque uint16 = 0xFFFF
)

// IsUSidBehavior reports whether behavior is a uN or uA behavior.
func IsUSidBehavior(behavior uint16) bool {
	return (behavior >= BehaviorUNFirst && behavior <= BehaviorUNLast) ||
		(behavior >= BehaviorUAFirst && behavior <= BehaviorUALast)
}

// BehaviorToString returns the string representation of an endpoint behavior.
func BehaviorToString(behavior uint16) string {
	switch {
	case behavior == BehaviorReserved:
		return "RESERVED"
	case behavior == BehaviorEND:
		return "END"
	case behavior == BehaviorENDX:
		return "ENDX"
	case behavior >= BehaviorUNFirst && behavior <= BehaviorUNLast:
		return "UN"
	case behavior >= BehaviorUAFirst && behavior <= BehaviorUALast:
		return "UA"
	default:
		return "UNKNOWN"
	}
}

// FirstSIDIndex is the index for the first SID in the SRv6 SID array.
const FirstSIDIndex = 0

// SIDStructureBytes is the [LocalBlock, LocalNode, LocalFunc, LocalArg] length split of an SRv6 SID.
// It marshals as a comma-separated string (e.g. "32,16,0,80").
type SIDStructureBytes []uint8

// MarshalJSON returns the JSON representation of SIDStructureBytes as a comma-separated string.
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

// Validate checks the SID structure lengths.
func (s SIDStructureBytes) Validate() error {
	if len(s) == 0 {
		return nil
	}
	if len(s) != 4 {
		return fmt.Errorf("SID structure must have 4 elements, got %d", len(s))
	}
	sum := int(s[0]) + int(s[1]) + int(s[2]) + int(s[3])
	if sum > SRv6SIDBitLength {
		return fmt.Errorf("SID structure sum %d exceeds %d bits", sum, SRv6SIDBitLength)
	}
	return nil
}

// SegmentSRv6 represents an SRv6 segment.
type SegmentSRv6 struct {
	Sid        netip.Addr        `json:"sid"`
	LocalAddr  netip.Addr        `json:"localAddr,omitzero"`
	RemoteAddr netip.Addr        `json:"remoteAddr,omitzero"`
	Structure  SIDStructureBytes `json:"sidStructure,omitempty"`
	USid       bool              `json:"uSid,omitempty"`
}

// SidString returns the SRv6 SID as a string.
func (seg SegmentSRv6) SidString() string {
	return seg.Sid.String()
}

// Behavior returns the endpoint behavior of the SRv6 segment based on its attributes.
func (seg SegmentSRv6) Behavior() uint16 {
	if !seg.LocalAddr.IsValid() {
		return BehaviorOpaque
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

// NewSegmentSRv6 creates a new SRv6 segment with the given SID.
func NewSegmentSRv6(sid netip.Addr) SegmentSRv6 {
	return SegmentSRv6{
		Sid: sid,
	}
}

// NewSegmentSRv6WithNodeInfo creates a new SRv6 segment with the given SID and enriches it with node information from the TED.
func NewSegmentSRv6WithNodeInfo(sid netip.Addr, n *LsNode) (SegmentSRv6, error) {
	seg := SegmentSRv6{
		Sid: sid,
	}

	var found bool
	for _, srv6SID := range n.SRv6SIDs {
		if len(srv6SID.Sids) == 0 {
			continue
		}

		addr, err := netip.ParseAddr(srv6SID.Sids[FirstSIDIndex])
		if err != nil {
			return seg, fmt.Errorf("SRv6 SID %q is invalid: %w", srv6SID.Sids[FirstSIDIndex], err)
		}
		seg.LocalAddr = addr
		seg.Structure = SIDStructureBytes{
			srv6SID.SIDStructure.LocalBlock,
			srv6SID.SIDStructure.LocalNode,
			srv6SID.SIDStructure.LocalFunc,
			srv6SID.SIDStructure.LocalArg,
		}
		if IsUSidBehavior(srv6SID.EndpointBehavior.Behavior) {
			seg.USid = true
		}
		found = true
		break
	}
	if !found {
		return seg, errors.New("no SRv6 SIDs available")
	}
	return seg, nil
}

// SegmentSRMPLS represents an SR-MPLS segment.
type SegmentSRMPLS struct {
	Sid uint32 `json:"sid"`
	TTL uint8  `json:"ttl,omitempty"`
	TC  uint8  `json:"tc,omitempty"`
	S   bool   `json:"s,omitempty"`
	// SidAbsent indicates that the SID is omitted and the NAI identifies the segment.
	SidAbsent bool `json:"sidAbsent,omitempty"`
	// Optional NAI for SR-ERO encoding (RFC 8664 §4.3.1).
	LocalAddr  netip.Addr `json:"localAddr,omitzero"`
	RemoteAddr netip.Addr `json:"remoteAddr,omitzero"`
}

// SidString returns the SR-MPLS SID as a string.
func (seg SegmentSRMPLS) SidString() string {
	return strconv.Itoa(int(seg.Sid))
}

// HasMPLSStackEntryAttrs reports whether the SR-MPLS segment has any MPLS stack entry attributes set.
func (seg SegmentSRMPLS) HasMPLSStackEntryAttrs() bool {
	return seg.TC != 0 || seg.S || seg.TTL != 0
}

// NewSegmentSRMPLS creates a new SR-MPLS segment with the given SID.
func NewSegmentSRMPLS(sid uint32) SegmentSRMPLS {
	return SegmentSRMPLS{
		Sid: sid,
	}
}

// Equal reports whether this SRv6 segment is equal to another.
func (seg SegmentSRv6) Equal(other SegmentSRv6) bool {
	return seg.Sid == other.Sid &&
		seg.LocalAddr == other.LocalAddr &&
		seg.RemoteAddr == other.RemoteAddr &&
		seg.USid == other.USid &&
		slices.Equal(seg.Structure, other.Structure)
}

// Equal reports whether this SR-MPLS segment is equal to another.
func (seg SegmentSRMPLS) Equal(other SegmentSRMPLS) bool {
	if seg.SidAbsent != other.SidAbsent {
		return false
	}
	if !seg.SidAbsent && seg.Sid != other.Sid {
		return false
	}
	return seg.TTL == other.TTL && seg.TC == other.TC && seg.S == other.S &&
		seg.LocalAddr == other.LocalAddr && seg.RemoteAddr == other.RemoteAddr
}

// SegmentsEqual reports whether two segments are equal.
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

// SegmentFamily is an enumeration for segment types.
type SegmentFamily int

const (
	// SegmentUnknown indicates an unknown segment type.
	SegmentUnknown SegmentFamily = iota
	// SegmentSRv6Family indicates an SRv6 segment type.
	SegmentSRv6Family
	// SegmentSRMPLSFamily indicates an SR-MPLS segment type.
	SegmentSRMPLSFamily
)
