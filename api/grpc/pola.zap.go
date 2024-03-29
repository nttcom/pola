// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package grpc

import (
	"net/netip"

	"go.uber.org/zap/zapcore"
)

// Implements zapcore.ObjectMarshaler interface for SRPolicy
func (x *SRPolicy) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	// Convert IP address slices to netip.Addr
	ssAddr, _ := netip.AddrFromSlice(x.GetPcepSessionAddr())
	enc.AddString("PcepSessionAddr", ssAddr.String())
	srcAddr, _ := netip.AddrFromSlice(x.GetSrcAddr())
	enc.AddString("SrcAddr", srcAddr.String())
	dstAddr, _ := netip.AddrFromSlice(x.GetDstAddr())
	enc.AddString("DstAddr", dstAddr.String())
	if srcRouterID := x.GetSrcRouterID(); srcRouterID != "" {
		enc.AddString("SrcRouterID", srcRouterID)
	}
	if dstRouterID := x.DstRouterID; dstRouterID != "" {
		enc.AddString("DstRouterID", dstRouterID)
	}
	enc.AddUint32("Color", x.GetColor())
	enc.AddUint32("Preference", x.GetPreference())
	enc.AddString("PolicyName", x.GetPolicyName())
	enc.AddString("Type", x.GetType().String())

	if x.GetType() == SRPolicyType_EXPLICIT {
		if err := enc.AddReflected("SegmentList", x.GetSegmentList()); err != nil {
			return err
		}
	} else if x.GetType() == SRPolicyType_DYNAMIC {
		enc.AddString("Metric", x.Metric.String())
	}
	return nil
}

// Implements zapcore.ObjectMarshaler interface for Segment
func (x *Segment) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Sid", x.GetSid())
	return nil
}
