package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/deepfence/FlowMeter/pkg/constants"
	"github.com/deepfence/FlowMeter/pkg/packetAnalyzer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/sirupsen/logrus"
)

func main() {
	ch := make(chan gopacket.Packet)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)

	// Command line arguments.
	ifLiveCapturePtr := flag.Bool("ifLiveCapture", false, "a bool")
	filenamePtr := flag.String("fname", "foo", "a string")
	maxNumPacketsPtr := flag.Int("maxNumPackets", 1024, "an int")
	ifLocalIPKnownPtr := flag.Bool("ifLocalIPKnown", false, "a bool")
	localIPPtr := flag.String("localIP", "143.198.72.237", "a string")

	flag.Parse()

	ifLiveCapture := *ifLiveCapturePtr
	filename := *filenamePtr
	maxNumPackets := *maxNumPacketsPtr
	ifLocalIPKnown := *ifLocalIPKnownPtr
	localIP := *localIPPtr

	logrus.Info("Live Capture: ", ifLiveCapture)
	logrus.Info("Target max number packets: ", maxNumPackets)

	logrus.Info("Start Main method")

	if ifLiveCapture {
		// Open device
		constants.Handle, constants.Err = pcap.OpenLive(constants.Device, constants.SnapshotLen, constants.Promiscuous, constants.Timeout)
		localIP = packetAnalyzer.GetOutboundIP().String()
		ifLocalIPKnown = true
		logrus.Info("Live capture of packets.")
	} else {
		// Open file instead of device
		constants.Handle, constants.Err = pcap.OpenOffline(constants.PacketFolder + "/" + filename + constants.PacketFileType)

		if !ifLocalIPKnown {
			localIP = ""
		}

		logrus.Info("Analyzing offline pcap files.")
	}

	if constants.Err != nil {
		log.Fatal(constants.Err)
	}

	go packetAnalyzer.FlowMeter(ctx, ch, cancel, maxNumPackets, localIP, ifLocalIPKnown, filename)

	defer constants.Handle.Close()

	packetSource := gopacket.NewPacketSource(constants.Handle, constants.Handle.LinkType())

	for packet := range packetSource.Packets() {
		select {
		case ch <- packet:
		case <-ctx.Done():
			return
		}
	}
	close(ch)
	<-ctx.Done()
}
