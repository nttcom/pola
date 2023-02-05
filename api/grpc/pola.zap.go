package grpc

import (
	"net/netip"

	"go.uber.org/zap/zapcore"
)

// for zapcore.ObjectMarshaler
func (s *SRPolicy) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	ssAddr, _ := netip.AddrFromSlice(s.GetPcepSessionAddr())
	enc.AddString("PcepSessionAddr", ssAddr.String())
	srcAddr, _ := netip.AddrFromSlice(s.GetSrcAddr())
	enc.AddString("SrcAddr", srcAddr.String())
	dstAddr, _ := netip.AddrFromSlice(s.GetDstAddr())
	enc.AddString("DstAddr", dstAddr.String())
	if srcRouterId := s.GetSrcRouterId(); srcRouterId != "" {
		enc.AddString("SrcRouterId", srcRouterId)
	}
	if dstRouterId := s.DstRouterId; dstRouterId != "" {
		enc.AddString("DstRouterId", dstRouterId)
	}
	enc.AddUint32("Color", s.GetColor())
	enc.AddUint32("Preference", s.GetPreference())
	enc.AddString("PolicyName", s.GetPolicyName())
	enc.AddString("Type", s.GetType().String())

	if srPolicyType := s.GetType().String(); srPolicyType == "EXPLICIT" {
		if err := enc.AddReflected("SegmentList", s.GetSegmentList()); err != nil {
			return err
		}
	} else if srPolicyType == "DYNAMIC" {
		enc.AddString("Metric", s.Metric.String())
	}
	return nil
}

func (s *Segment) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Sid", s.GetSid())
	return nil
}
