package main

import (

	//"flowmeter/constants"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/deepfence/deepfence_flowmeter/constants"
	"github.com/deepfence/deepfence_flowmeter/packetAnalyzer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	ch := make(chan gopacket.Packet)
	done := make(chan struct{}) // signal channel

	ifLiveCapture, _ := strconv.ParseBool(os.Args[1])
	filename := os.Args[2]
	maxNumPackets, _ := strconv.Atoi(os.Args[3])
	ifLocalIPKnown, _ := strconv.ParseBool(os.Args[4])
	localIP := ""

	fmt.Println("Live Capure: ", ifLiveCapture)
	fmt.Println("Target max number packets: ", maxNumPackets)

	fmt.Println("Start Main method")

	if ifLiveCapture {
		// Open device
		constants.Handle, constants.Err = pcap.OpenLive(constants.Device, constants.SnapshotLen, constants.Promiscuous, constants.Timeout)
		localIP = packetAnalyzer.GetOutboundIP().String()
		ifLocalIPKnown = true
		fmt.Println("Live capture of packets.")
	} else {
		// Open file instead of device
		constants.Handle, constants.Err = pcap.OpenOffline(filename + constants.PcapFile)

		if ifLocalIPKnown {
			localIP = "143.198.72.237" //"192.168.1.4" //"164.90.157.161" //"138.68.177.159" //"164.90.157.161" //"143.198.73.70" // Picked this from one of the Agent VMs.
		} else {
			localIP = ""
		}

		fmt.Println("Analyzing offline pcap files.")
	}

	//Just give 40 bytes per packet - continuous by default read only enough

	go packetAnalyzer.FlowMeter(ch, done, maxNumPackets, localIP, ifLocalIPKnown, filename)

	if constants.Err != nil {
		log.Fatal(constants.Err)
	}
	defer constants.Handle.Close()

	packetSource := gopacket.NewPacketSource(constants.Handle, constants.Handle.LinkType())

loop:
	for packet := range packetSource.Packets() {
		select {
		case ch <- packet:
		case <-done:
			close(ch)
			close(done)
			break loop
		}
		//fmt.Println("Closing.")

	}

}
