package constants

import (
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	Device             string        = "eth0"
	SnapshotLen        int32         = 1024
	Promiscuous        bool          = false
	Timeout            time.Duration = 30 * time.Second
	MinPacketPerFlow   int           = 15 //24 //80 //10  //80
	MaxPacketPerFlow   int           = 82 //100 //82
	MinTimeDuration    time.Duration = 0 * time.Millisecond
	PcapFile           string        = ".pcap"
	WeightsFile        string        = "weights.txt"
	InterceptFile      string        = "intercept.txt"
	MeansFile          string        = "mean.txt"
	StdFile            string        = "std.txt"
	Verbose            bool          = false
	IfFlowStatsVerbose bool          = false
)

var (
	Handle *pcap.Handle

	Err error

	SaveIntervals = []int{1500000, 2500000, 3000000, 4000000, 5000000, 7000000}

	MapKeys = map[string]int{"srcIP": 0, "dstIP": 1, "protocol": 2, "srcPort": 3, "dstPort": 4, "flowDuration": 5, "flowLength": 6, "fwdFlowLength": 7, "bwdFlowLength": 8, "packetSizeTotal": 9, "packetSizeMean": 10, "packetSizeStd": 11, "packetSizeMin": 12, "packetSizeMax": 13, "fwdPacketSizeTotal": 14, "bwdPacketSizeTotal": 15, "fwdPacketSizeMean": 17, "bwdPacketSizeMean": 17, "fwdPacketSizeStd": 18, "bwdPacketSizeStd": 19, "fwdPacketSizeMin": 20, "bwdPacketSizeMin": 21, "fwdPacketSizeMax": 22, "bwdPacketSizeMax": 23, "IATTotal": 24, "IATMean": 25, "IATStd": 26, "IATMin": 27, "IATMax": 28, "fwdIATTotal": 29, "bwdIATTotal": 30, "fwdIATMean": 31, "bwdIATMean": 32, "fwdIATStd": 33, "bwdIATStd": 34, "fwdIATMin": 35, "bwdIATMin": 36, "fwdIATMax": 37, "bwdIATMax": 38, "flowStartTime": 39, "flowPrevTime": 40, "fwdFlowPrevTime": 41, "bwdFlowPrevTime": 42, "minPacketsBool": 43, "fwdPacketSizeArr": 44, "bwdPacketSizeArr": 45, "fwdIATArr": 46, "bwdIATArr": 47, "IATArr": 48, "packetSizeArr": 49}

	MapLabels = map[int]string{0: "Source IP", 1: "Dest IP", 2: "Protocol", 3: "Source Port", 4: "Dest Port", 5: "Flow Duration", 6: "Flow Length", 7: "Fwd Flow Length", 8: "Bwd Flow Length", 9: "Packet Size Total", 10: "Packet Size Mean", 11: "Packet Size Std", 12: "Packet Size Min", 13: "Packet Size Max", 14: "Fwd Packet Size Total", 15: "Bwd Packet Size Total", 16: "Fwd Packet Size Mean", 17: "Bwd Packet Size Mean", 18: "Fwd Packet Size Std", 19: "Bwd Packet Size Std", 20: "Fwd Packet Size Min", 21: "Bwd Packet Size Min", 22: "Fwd Packet Size Max", 23: "Bwd Packet Size Max", 24: "IAT Total", 25: "IAT Mean", 26: "IAT Std", 27: "IAT Min", 28: "IAT Max", 29: "Fwd IAT Total", 30: "Bwd IAT Total", 31: "Fwd IAT Mean", 32: "Bwd IAT Mean", 33: "Fwd IAT Std", 34: "Bwd IAT Std", 35: "Fwd IAT Min", 36: "Bwd IAT Min", 37: "Fwd IAT Max", 38: "Bwd IAT Max", 39: "Flow Start Time", 40: "Flow Latest Time"}
)
