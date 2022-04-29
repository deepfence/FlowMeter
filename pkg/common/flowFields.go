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
func FlowData(values []interface{}) FlowFeatures {
	flow := FlowFeatures{
		SrcIP:                     values[constants.MapKeys["srcIP"]],
		DstIP:                     values[constants.MapKeys["dstIP"]],
		Protocol:                  values[constants.MapKeys["protocol"]],
		SrcPort:                   values[constants.MapKeys["srcPort"]],
		DstPort:                   values[constants.MapKeys["dstPort"]],
		FlowDuration:              float64(values[constants.MapKeys["flowDuration"]].(time.Duration) / time.Nanosecond),
		FlowLength:                float64(values[constants.MapKeys["flowLength"]].(int)),
		FwdFlowLength:             float64(values[constants.MapKeys["fwdFlowLength"]].(int)),
		BwdFlowLength:             float64(values[constants.MapKeys["bwdFlowLength"]].(int)),
		PacketSizeTotal:           float64(values[constants.MapKeys["packetSizeTotal"]].(int)),
		PacketSizeMean:            values[constants.MapKeys["packetSizeMean"]].(float64),
		PacketSizeStd:             values[constants.MapKeys["packetSizeStd"]].(float64),
		PacketSizeMin:             float64(values[constants.MapKeys["packetSizeMin"]].(int)),
		PacketSizeMax:             float64(values[constants.MapKeys["packetSizeMax"]].(int)),
		FwdPacketSizeTotal:        float64(values[constants.MapKeys["fwdPacketSizeTotal"]].(int)),
		BwdPacketSizeTotal:        float64(values[constants.MapKeys["bwdPacketSizeTotal"]].(int)),
		FwdPacketSizeMean:         values[constants.MapKeys["fwdPacketSizeMean"]].(float64),
		BwdPacketSizeMean:         values[constants.MapKeys["bwdPacketSizeMean"]].(float64),
		FwdPacketSizeStd:          values[constants.MapKeys["fwdPacketSizeStd"]].(float64),
		BwdPacketSizeStd:          values[constants.MapKeys["bwdPacketSizeStd"]].(float64),
		FwdPacketSizeMin:          float64(values[constants.MapKeys["fwdPacketSizeMin"]].(int)),
		BwdPacketSizeMin:          float64(values[constants.MapKeys["bwdPacketSizeMin"]].(int)),
		FwdPacketSizeMax:          float64(values[constants.MapKeys["fwdPacketSizeMax"]].(int)),
		BwdPacketSizeMax:          float64(values[constants.MapKeys["bwdPacketSizeMax"]].(int)),
		IATMean:                   float64(values[constants.MapKeys["IATMean"]].(time.Duration) / time.Nanosecond),
		IATStd:                    float64(values[constants.MapKeys["IATStd"]].(time.Duration) / time.Nanosecond),
		IATMin:                    float64(values[constants.MapKeys["IATMin"]].(time.Duration) / time.Nanosecond),
		IATMax:                    float64(values[constants.MapKeys["IATMax"]].(time.Duration) / time.Nanosecond),
		FwdIATTotal:               float64(values[constants.MapKeys["fwdIATTotal"]].(time.Duration) / time.Nanosecond),
		BwdIATTotal:               float64(values[constants.MapKeys["bwdIATTotal"]].(time.Duration) / time.Nanosecond),
		FwdIATMean:                float64(values[constants.MapKeys["fwdIATMean"]].(time.Duration) / time.Nanosecond),
		BwdIATMean:                float64(values[constants.MapKeys["bwdIATMean"]].(time.Duration) / time.Nanosecond),
		FwdIATStd:                 float64(values[constants.MapKeys["fwdIATStd"]].(time.Duration) / time.Nanosecond),
		BwdIATStd:                 float64(values[constants.MapKeys["bwdIATStd"]].(time.Duration) / time.Nanosecond),
		FwdIATMin:                 float64(values[constants.MapKeys["fwdIATMin"]].(time.Duration) / time.Nanosecond),
		BwdIATMin:                 float64(values[constants.MapKeys["bwdIATMin"]].(time.Duration) / time.Nanosecond),
		FwdIATMax:                 float64(values[constants.MapKeys["fwdIATMax"]].(time.Duration) / time.Nanosecond),
		BwdIATMax:                 float64(values[constants.MapKeys["bwdIATMax"]].(time.Duration) / time.Nanosecond),
		FlowLengthPerTime:         float64(values[constants.MapKeys["flowLength"]].(int)) / float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond),
		FwdFlowLengthPerTime:      float64(values[constants.MapKeys["fwdFlowLength"]].(int)) / float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond),
		BwdFlowLengthPerTime:      float64(values[constants.MapKeys["bwdFlowLength"]].(int)) / float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond),
		PacketSizeTotalPerTime:    float64(values[constants.MapKeys["packetSizeTotal"]].(int)) / float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond),
		FwdPacketSizeTotalPerTime: float64(values[constants.MapKeys["fwdPacketSizeTotal"]].(int)) / float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond),
		BwdPacketSizeTotalPerTime: float64(values[constants.MapKeys["bwdPacketSizeTotal"]].(int)) / float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond),
	}

	return flow
}
