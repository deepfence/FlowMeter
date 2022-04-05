package packetAnalyzer

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Function to get information from packet layers.
func PacketInfo(packet gopacket.Packet) (string, string, int, time.Time) {

	var connection string = ""

	packetData := strings.Split(packet.String(), "\n")[0]

	layout := "2006-01-02 15:04:05 -0700 MST"

	packetSize, _ := strconv.Atoi(strings.Split(strings.Split(strings.Split(packetData, ":")[1], ",")[0], " ")[1])
	packetTime, _ := time.Parse(layout, strings.Split(packetData, "@")[1][1:])

	// Let's see if the packet is an ethernet packet
	// ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	// if ethernetLayer != nil {
	// 	fmt.Println("Ethernet layer detected.")
	// 	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	// 	fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
	// 	fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
	// 	// Ethernet type is typically IPv4 but could be ARP or other
	// 	fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
	// 	fmt.Println()
	// }

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	protocol := ""
	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		connection += ip.SrcIP.String() + "--" + ip.DstIP.String() + "--" + ip.Protocol.String()
		protocol = ip.Protocol.String()

	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		//fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		connection += "--" + tcp.SrcPort.String() + "--" + tcp.DstPort.String()

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		// fmt.Println("Sequence number: ", tcp.Seq)
	}

	// Let's see if the packet is TCP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		//fmt.Println("UDP layer detected.")
		udp, _ := udpLayer.(*layers.UDP)

		connection += "--" + udp.SrcPort.String() + "--" + udp.DstPort.String()

		// UDP layer variables:
		// SrcPort, DstPort, Length, Checksum

	}

	// // Iterate over all layers, printing out each layer type
	// fmt.Println("All packet layers:")
	// for _, layer := range packet.Layers() {
	// 	fmt.Println("- ", layer.LayerType())
	// }

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// fmt.Println("Application layer/Payload found. ", applicationLayer.Payload())
		// fmt.Printf("%s\n", applicationLayer.Payload())

		// 	// Search for a string inside the payload
		// 	if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		// 		fmt.Println("HTTP found!")
		// 	}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

	// if (connection == "192.168.1.191--178.249.101.23--TCP--42066--443(https)") || (connection == "178.249.101.23--192.168.1.191--TCP--443(https)--42066") {
	// 	fmt.Println(" ")
	// 	fmt.Println("Debug: ", connection, " ", packetTime.String()[0:19])
	// 	fmt.Println(" ")
	// 	fmt.Println(" ")
	// }

	// Return if protocol=TCP/UDP and if packets have correct time stamps.

	if (protocol == "TCP") || (protocol == "UDP") && (packetTime.String()[0:19] != "0001-01-01 00:00:00") {
		return connection, Reverse5Tuple(connection), packetSize, packetTime
	} else {
		return connection, "nil", packetSize, packetTime
	}

}

// GetOutboundIP: Get preferred outbound ip of this machine.
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// Reverse a 5 tuple.
func Reverse5Tuple(fTuple string) string {
	srcIP, dstIP, protocol, srcPort, dstPort := strings.Split(fTuple, "--")[0], strings.Split(fTuple, "--")[1], strings.Split(fTuple, "--")[2], strings.Split(fTuple, "--")[3], strings.Split(fTuple, "--")[4]

	return dstIP + "--" + srcIP + "--" + protocol + "--" + dstPort + "--" + srcPort
}
