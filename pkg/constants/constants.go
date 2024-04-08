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
	MinPacketsPerFlow  int           = 15
	MaxPacketsPerFlow  int           = 82
	MinTimeDuration    time.Duration = 0 * time.Millisecond
	PacketFileType     string        = ".pcap"
	WeightsFile        string        = "ml/parameters/weights.txt"
	InterceptFile      string        = "ml/parameters/intercept.txt"
	MeansFile          string        = "ml/parameters/mean.txt"
	StdFile            string        = "ml/parameters/std.txt"
	Verbose            bool          = false
	IfFlowStatsVerbose bool          = true
	PacketFolder       string        = "packets"
	FlowOutputFolder   string        = "flowOutput"
)

var (
	Handle *pcap.Handle

	Err error

	SaveIntervals = []int{100000, 500000, 1000000, 1500000, 2500000, 3000000, 4000000, 5000000}

	MapLabels = map[int]string{0: "Source IP", 1: "Dest IP", 2: "Protocol", 3: "Source Port", 4: "Dest Port", 5: "Flow Duration", 6: "Flow Length", 7: "Forward Flow Length", 8: "Backward Flow Length", 9: "Packet Size Total", 10: "Packet Size Mean", 11: "Packet Size Std", 12: "Packet Size Min", 13: "Packet Size Max", 14: "Forward Packet Size Total", 15: "Backward Packet Size Total", 16: "Forward Packet Size Mean", 17: "Backward Packet Size Mean", 18: "Forward Packet Size Std", 19: "Backward Packet Size Std", 20: "Forward Packet Size Min", 21: "Backward Packet Size Min", 22: "Forward Packet Size Max", 23: "Backward Packet Size Max", 24: "IAT Total", 25: "IAT Mean", 26: "IAT Std", 27: "IAT Min", 28: "IAT Max", 29: "Forward IAT Total", 30: "Backward IAT Total", 31: "Forward IAT Mean", 32: "Backward IAT Mean", 33: "Forward IAT Std", 34: "Backward IAT Std", 35: "Forward IAT Min", 36: "Backward IAT Min", 37: "Forward IAT Max", 38: "Backward IAT Max", 39: "Flow Start Time", 40: "Flow Latest Time"}
)

type FlowData struct {
	SrcIP              string
	DstIP              string
	Protocol           string
	SrcPort            string
	DstPort            string
	FlowDuration       time.Duration
	FlowLength         int
	FwdFlowLength      int
	BwdFlowLength      int
	PacketSizeTotal    int
	PacketSizeMean     float64
	PacketSizeStd      float64
	PacketSizeMin      int
	PacketSizeMax      int
	FwdPacketSizeTotal int
	BwdPacketSizeTotal int
	FwdPacketSizeMean  float64
	BwdPacketSizeMean  float64
	FwdPacketSizeStd   float64
	BwdPacketSizeStd   float64
	FwdPacketSizeMin   int
	BwdPacketSizeMin   int
	FwdPacketSizeMax   int
	BwdPacketSizeMax   int
	IATTotal           time.Duration
	IATMean            time.Duration
	IATStd             time.Duration
	IATMin             time.Duration
	IATMax             time.Duration
	FwdIATTotal        time.Duration
	BwdIATTotal        time.Duration
	FwdIATMean         time.Duration
	BwdIATMean         time.Duration
	FwdIATStd          time.Duration
	BwdIATStd          time.Duration
	FwdIATMin          time.Duration
	BwdIATMin          time.Duration
	FwdIATMax          time.Duration
	BwdIATMax          time.Duration
	FlowStartTime      time.Time
	FlowPrevTime       time.Time
	FwdFlowPrevTime    time.Time
	BwdFlowPrevTime    time.Time
	MinPacketsBool     bool
	FwdPacketSizeArr   []int
	BwdPacketSizeArr   []int
	FwdIATArr          []time.Duration
	BwdIATArr          []time.Duration
	IATArr             []time.Duration
	PacketSizeArr      []int
}
