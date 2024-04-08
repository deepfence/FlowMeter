package common

import (
	"time"

	"github.com/deepfence/FlowMeter/pkg/constants"
)

type FlowFeatures struct {
	SrcIP                     interface{}
	DstIP                     interface{}
	Protocol                  interface{}
	SrcPort                   interface{}
	DstPort                   interface{}
	FlowDuration              float64
	FlowLength                float64
	FwdFlowLength             float64
	BwdFlowLength             float64
	PacketSizeTotal           float64
	PacketSizeMean            float64
	PacketSizeStd             float64
	PacketSizeMin             float64
	PacketSizeMax             float64
	FwdPacketSizeTotal        float64
	BwdPacketSizeTotal        float64
	FwdPacketSizeMean         float64
	BwdPacketSizeMean         float64
	FwdPacketSizeStd          float64
	BwdPacketSizeStd          float64
	FwdPacketSizeMin          float64
	BwdPacketSizeMin          float64
	FwdPacketSizeMax          float64
	BwdPacketSizeMax          float64
	IATMean                   float64
	IATStd                    float64
	IATMin                    float64
	IATMax                    float64
	FwdIATTotal               float64
	BwdIATTotal               float64
	FwdIATMean                float64
	BwdIATMean                float64
	FwdIATStd                 float64
	BwdIATStd                 float64
	FwdIATMin                 float64
	BwdIATMin                 float64
	FwdIATMax                 float64
	BwdIATMax                 float64
	FlowLengthPerTime         float64
	FwdFlowLengthPerTime      float64
	BwdFlowLengthPerTime      float64
	PacketSizeTotalPerTime    float64
	FwdPacketSizeTotalPerTime float64
	BwdPacketSizeTotalPerTime float64
}

// Create feature struct with appropriate datatypes for features.
func FlowData2FlowFeatures(values constants.FlowData) FlowFeatures {
	flow := FlowFeatures{
		SrcIP:                     values.SrcIP,
		DstIP:                     values.DstIP,
		Protocol:                  values.Protocol,
		SrcPort:                   values.SrcPort,
		DstPort:                   values.DstPort,
		FlowDuration:              float64(values.FlowDuration / time.Nanosecond),
		FlowLength:                float64(values.FlowLength),
		FwdFlowLength:             float64(values.FwdFlowLength),
		BwdFlowLength:             float64(values.BwdFlowLength),
		PacketSizeTotal:           float64(values.PacketSizeTotal),
		PacketSizeMean:            values.PacketSizeMean,
		PacketSizeStd:             values.PacketSizeStd,
		PacketSizeMin:             float64(values.PacketSizeMin),
		PacketSizeMax:             float64(values.PacketSizeMax),
		FwdPacketSizeTotal:        float64(values.FwdPacketSizeTotal),
		BwdPacketSizeTotal:        float64(values.BwdPacketSizeTotal),
		FwdPacketSizeMean:         values.FwdPacketSizeMean,
		BwdPacketSizeMean:         values.BwdPacketSizeMean,
		FwdPacketSizeStd:          values.FwdPacketSizeStd,
		BwdPacketSizeStd:          values.BwdPacketSizeStd,
		FwdPacketSizeMin:          float64(values.FwdPacketSizeMin),
		BwdPacketSizeMin:          float64(values.BwdPacketSizeMin),
		FwdPacketSizeMax:          float64(values.FwdPacketSizeMax),
		BwdPacketSizeMax:          float64(values.BwdPacketSizeMax),
		IATMean:                   float64(values.IATMean / time.Nanosecond),
		IATStd:                    float64(values.IATStd / time.Nanosecond),
		IATMin:                    float64(values.IATMin / time.Nanosecond),
		IATMax:                    float64(values.IATMax / time.Nanosecond),
		FwdIATTotal:               float64(values.FwdIATTotal / time.Nanosecond),
		BwdIATTotal:               float64(values.BwdIATTotal / time.Nanosecond),
		FwdIATMean:                float64(values.FwdIATMean / time.Nanosecond),
		BwdIATMean:                float64(values.BwdIATMean / time.Nanosecond),
		FwdIATStd:                 float64(values.FwdIATStd / time.Nanosecond),
		BwdIATStd:                 float64(values.BwdIATStd / time.Nanosecond),
		FwdIATMin:                 float64(values.FwdIATMin / time.Nanosecond),
		BwdIATMin:                 float64(values.BwdIATMin / time.Nanosecond),
		FwdIATMax:                 float64(values.FwdIATMax / time.Nanosecond),
		BwdIATMax:                 float64(values.BwdIATMax / time.Nanosecond),
		FlowLengthPerTime:         float64(values.FlowLength) / float64(values.FlowDuration/time.Nanosecond),
		FwdFlowLengthPerTime:      float64(values.FwdFlowLength) / float64(values.FlowDuration/time.Nanosecond),
		BwdFlowLengthPerTime:      float64(values.BwdFlowLength) / float64(values.FlowDuration/time.Nanosecond),
		PacketSizeTotalPerTime:    float64(values.PacketSizeTotal) / float64(values.FlowDuration/time.Nanosecond),
		FwdPacketSizeTotalPerTime: float64(values.FwdPacketSizeTotal) / float64(values.FlowDuration/time.Nanosecond),
		BwdPacketSizeTotalPerTime: float64(values.BwdPacketSizeTotal) / float64(values.FlowDuration/time.Nanosecond),
	}

	return flow
}
