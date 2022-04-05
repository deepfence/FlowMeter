package constants

import (
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	Device           string        = "eth0"
	SnapshotLen      int32         = 1024
	Promiscuous      bool          = false
	Timeout          time.Duration = 30 * time.Second
	MinPacketPerFlow int           = 15 //24 //80 //10  //80
	MaxPacketPerFlow int           = 82 //100 //82
	MinTimeDuration  time.Duration = 0 * time.Millisecond
	PcapFile         string        = ".pcap"
	WeightsFile      string        = "weights.txt"
	InterceptFile    string        = "intercept.txt"
	MeansFile        string        = "mean.txt"
	StdFile          string        = "std.txt"
)

var (
	Handle        *pcap.Handle
	Err           error
	SaveIntervals = []int{1500000, 2500000, 3000000, 4000000, 5000000, 7000000}
	//SaveIntervals = []int{5000}
)
