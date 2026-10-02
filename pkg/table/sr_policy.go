// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
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

// DefaultPreference is the default SR Policy candidate path preference (RFC 9256 §2.7).
const DefaultPreference uint32 = 100

// DynamicPath is a candidate path with an optimization objective
// for a specific underlay plane (RFC 9256 §2.2).
type DynamicPath struct {
	Metric MetricType `json:"metric"`
	// Plane is the underlay scope used for TED path computation.
	Plane Plane `json:"plane,omitzero"`
}

// ExplicitPath is a candidate path fully specified as a segment list (RFC 9256 §2.2).
type ExplicitPath struct {
	SegmentList []Segment `json:"segmentList"`
}

// CandidatePath is either Dynamic or Explicit (RFC 9256 §2.2).
// The zero value represents an unknown candidate path type.
type CandidatePath struct {
	// Preference selects the active candidate path (RFC 9256 §2.7).
	Preference uint32        `json:"preference"`
	Dynamic    *DynamicPath  `json:"dynamic,omitempty"`
	Explicit   *ExplicitPath `json:"explicit,omitempty"`
}

// SRPolicy represents an SR Policy with its path and attributes.
type SRPolicy struct {
	// Headend and Endpoint identify the policy (RFC 9256 §2.1).
	Headend  netip.Addr `json:"headend"`
	Endpoint netip.Addr `json:"endpoint"`
	Color    uint32     `json:"color"`
	Name     string     `json:"policyName"`

	// Router IDs are populated for display when resolvable from the TED.
	HeadendRouterID  string `json:"headendRouterId,omitempty"`
	EndpointRouterID string `json:"endpointRouterId,omitempty"`

	// SegmentList is the currently signaled segment list.
	SegmentList []Segment `json:"segmentList"`

	CandidatePath CandidatePath `json:"candidatePath"`

	// PlspID, LSPID, and State are PCEP-assigned state, not policy identity.
	PlspID uint32      `json:"plspId,omitempty"`
	LSPID  uint16      `json:"lspId,omitempty"`
	State  PolicyState `json:"state,omitempty"`
}

// NewSRPolicy creates a new SR Policy with the given attributes.
func NewSRPolicy(
	plspID uint32,
	name string,
	segmentList []Segment,
	headend netip.Addr,
	endpoint netip.Addr,
	color uint32,
	preference uint32,
	lspID uint16,
	state PolicyState,
) *SRPolicy {
	p := &SRPolicy{
		PlspID:        plspID,
		Name:          name,
		SegmentList:   segmentList,
		Headend:       headend,
		Endpoint:      endpoint,
		Color:         color,
		CandidatePath: CandidatePath{Preference: preference},
		LSPID:         lspID,
		State:         state,
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
		p.CandidatePath.Preference = *df.Preference
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
	// Family reports the data plane this segment belongs to.
	Family() DataPlane
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

// SRv6SID is distinct from netip.Addr to prevent accidental mixing of
// full-SIDs, locators, and ordinary IPv6 addresses.
type SRv6SID netip.Addr

// Addr returns sid as a netip.Addr.
func (sid SRv6SID) Addr() netip.Addr { return netip.Addr(sid) }

// String returns the string representation of sid.
func (sid SRv6SID) String() string { return netip.Addr(sid).String() }

// IsValid reports whether sid holds a valid address.
func (sid SRv6SID) IsValid() bool { return netip.Addr(sid).IsValid() }

// ParseSRv6SID parses s as an SRv6 SID and rejects IPv4-mapped IPv6 addresses.
func ParseSRv6SID(s string) (SRv6SID, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return SRv6SID{}, fmt.Errorf("invalid SRv6 SID %q: %w", s, err)
	}

	if !addr.Is6() || addr.Is4In6() {
		return SRv6SID{}, fmt.Errorf("SRv6 SID %q is not a valid IPv6 address", s)
	}

	return SRv6SID(addr), nil
}

// NewSegment creates a Segment from a SID string, which can be either an IPv6 address (SRv6) or a number (SR-MPLS).
func NewSegment(sid string) (Segment, error) {
	if addr, err := netip.ParseAddr(sid); err == nil && addr.Is6() {
		srv6SID, err := ParseSRv6SID(sid)
		if err != nil {
			return nil, err
		}

		return NewSegmentSRv6(srv6SID), nil
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

// SegmentSRv6 represents an SRv6 segment.
type SegmentSRv6 struct {
	Sid        SRv6SID       `json:"sid"`
	LocalAddr  netip.Addr    `json:"localAddr,omitzero"`
	RemoteAddr netip.Addr    `json:"remoteAddr,omitzero"`
	Structure  *SIDStructure `json:"sidStructure,omitempty"`
	USid       bool          `json:"uSid,omitempty"`
	// Behavior is the TED-advertised endpoint behavior (RFC 9603 §4.3.1).
	// Zero means unknown; BehaviorOrDerived derives it from other fields.
	Behavior uint16 `json:"behavior,omitempty"`
	// LocalIfaceID/RemoteIfaceID identify the interface for link-local RemoteAddr
	// in NAI type 6 encoding (RFC 8664/9603 §4.3.1). nil means not advertised.
	LocalIfaceID  *uint32 `json:"localIfaceId,omitempty"`
	RemoteIfaceID *uint32 `json:"remoteIfaceId,omitempty"`
}

// SidString returns the SRv6 SID as a string.
func (seg SegmentSRv6) SidString() string {
	return seg.Sid.String()
}

// Family reports the data plane this segment belongs to.
func (seg SegmentSRv6) Family() DataPlane { return DPSRv6 }

// BehaviorOrDerived returns the TED-advertised endpoint behavior, or derives
// it from the segment's other attributes when the behavior is unknown.
func (seg SegmentSRv6) BehaviorOrDerived() uint16 {
	if seg.Behavior != 0 {
		return seg.Behavior
	}

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
func NewSegmentSRv6(sid SRv6SID) SegmentSRv6 {
	return SegmentSRv6{
		Sid: sid,
	}
}

// NewSegmentSRv6WithNodeInfo creates a new SRv6 segment with the given SID and enriches it with node information from the TED.
func NewSegmentSRv6WithNodeInfo(sid SRv6SID, n *LsNode) (SegmentSRv6, error) {
	seg := SegmentSRv6{
		Sid: sid,
	}

	var found bool

	for _, srv6SID := range n.SRv6SIDs {
		if srv6SID == nil || len(srv6SID.Sids) == 0 {
			continue
		}

		addr, err := netip.ParseAddr(srv6SID.Sids[FirstSIDIndex])
		if err != nil {
			return seg, fmt.Errorf("SRv6 SID %q is invalid: %w", srv6SID.Sids[FirstSIDIndex], err)
		}

		seg.LocalAddr = addr

		seg.Structure = srv6SID.SIDStructure.Clone()
		seg.Behavior = srv6SID.EndpointBehavior.Behavior

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
	// LocalIfaceID/RemoteIfaceID identify the interface for link-local RemoteAddr
	// in NAI type 6 encoding. nil means not advertised.
	LocalIfaceID  *uint32 `json:"localIfaceId,omitempty"`
	RemoteIfaceID *uint32 `json:"remoteIfaceId,omitempty"`
}

// SidString returns the SR-MPLS SID as a string.
func (seg SegmentSRMPLS) SidString() string {
	return strconv.FormatUint(uint64(seg.Sid), 10)
}

// Family reports the data plane this segment belongs to.
func (seg SegmentSRMPLS) Family() DataPlane { return DPSRMPLS }

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
		seg.Structure.Equal(other.Structure)
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
