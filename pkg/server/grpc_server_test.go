// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/table"
)

// localAddr / remoteAddr from the gRPC message must land on the SR-MPLS segment.
func TestNewEnrichedSegmentSRMPLS(t *testing.T) {
	tests := []struct {
		name       string
		segment    *pb.Segment
		wantLocal  string
		wantRemote string
		wantErr    bool
	}{
		{
			name:    "no addresses",
			segment: &pb.Segment{Sid: "16001"},
		},
		{
			name:      "node NAI",
			segment:   &pb.Segment{Sid: "16001", LocalAddr: "10.255.0.1"},
			wantLocal: "10.255.0.1",
		},
		{
			name:       "adjacency NAI",
			segment:    &pb.Segment{Sid: "24001", LocalAddr: "10.0.0.1", RemoteAddr: "10.0.0.2"},
			wantLocal:  "10.0.0.1",
			wantRemote: "10.0.0.2",
		},
		{
			name:    "malformed localAddr",
			segment: &pb.Segment{Sid: "16001", LocalAddr: "10.255.0.300"},
			wantErr: true,
		},
		{
			name:    "malformed remoteAddr",
			segment: &pb.Segment{Sid: "16001", LocalAddr: "10.0.0.1", RemoteAddr: "not-an-addr"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := newEnrichedSegment(tt.segment, false)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("newEnrichedSegment returned an error: %v", err)
			}

			mplsSeg, ok := seg.(table.SegmentSRMPLS)
			if !ok {
				t.Fatalf("segment type: got %T, want table.SegmentSRMPLS", seg)
			}
			if got := addrString(mplsSeg.LocalAddr); got != tt.wantLocal {
				t.Errorf("LocalAddr: got %q, want %q", got, tt.wantLocal)
			}
			if got := addrString(mplsSeg.RemoteAddr); got != tt.wantRemote {
				t.Errorf("RemoteAddr: got %q, want %q", got, tt.wantRemote)
			}
		})
	}
}

// newEnrichedSegment is shared by the SR-MPLS and the SRv6 call paths, so the
// SRv6 extras must keep being applied.
func TestNewEnrichedSegmentSRv6(t *testing.T) {
	segment := &pb.Segment{
		Sid:          "2001:db8:1005::",
		LocalAddr:    "2001:db8::5",
		RemoteAddr:   "2001:db8::6",
		SidStructure: "32,16,0,80",
	}

	for _, usidMode := range []bool{false, true} {
		seg, err := newEnrichedSegment(segment, usidMode)
		if err != nil {
			t.Fatalf("newEnrichedSegment returned an error: %v", err)
		}

		srv6Seg, ok := seg.(table.SegmentSRv6)
		if !ok {
			t.Fatalf("segment type: got %T, want table.SegmentSRv6", seg)
		}
		if got := srv6Seg.Sid.String(); got != "2001:db8:1005::" {
			t.Errorf("Sid: got %q, want %q", got, "2001:db8:1005::")
		}
		if got := addrString(srv6Seg.LocalAddr); got != "2001:db8::5" {
			t.Errorf("LocalAddr: got %q, want %q", got, "2001:db8::5")
		}
		if got := addrString(srv6Seg.RemoteAddr); got != "2001:db8::6" {
			t.Errorf("RemoteAddr: got %q, want %q", got, "2001:db8::6")
		}
		if want := []uint8{32, 16, 0, 80}; !slices.Equal(srv6Seg.Structure, want) {
			t.Errorf("Structure: got %v, want %v", srv6Seg.Structure, want)
		}
		if srv6Seg.USid != usidMode {
			t.Errorf("USid with usidMode=%v: got %v", usidMode, srv6Seg.USid)
		}
	}
}

func TestNewEnrichedSegmentInvalidSID(t *testing.T) {
	if _, err := newEnrichedSegment(&pb.Segment{Sid: "not-a-sid"}, false); err == nil {
		t.Error("expected an error for an unparsable SID, got none")
	}
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

// An SR-MPLS segment carrying a localAddr must be serialized into an SR-ERO
// subobject whose body ends with that address (RFC8664 4.3.1 node NAI).
func TestCreateEroFromSegmentListWithNAI(t *testing.T) {
	seg := table.NewSegmentSRMPLS(16002)
	seg.LocalAddr = netip.MustParseAddr("10.255.0.2")

	ero := createEroFromSegmentList([]table.Segment{seg})
	if len(ero.EroSubobjects) != 1 {
		t.Fatalf("ERO subobject count: got %d, want 1", len(ero.EroSubobjects))
	}

	raw, err := ero.EroSubobjects[0].Serialize()
	if err != nil {
		t.Fatalf("Serialize returned an error: %v", err)
	}
	// Type, Length, NT/Flags (4byte) + SID (4byte) + NAI (4byte)
	if len(raw) != 12 {
		t.Fatalf("serialized size: got %d, want 12", len(raw))
	}
	if nt := raw[2] >> 4; nt != 0x01 {
		t.Errorf("NAI type: got 0x%02x, want 0x01 (IPv4 node ID)", nt)
	}
	if raw[3]&0x08 != 0 {
		t.Error("F flag is set even though the NAI is present")
	}
	if want := seg.LocalAddr.AsSlice(); !bytes.Equal(raw[8:12], want) {
		t.Errorf("NAI: got %v, want %v", raw[8:12], want)
	}
}
