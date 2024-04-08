package packetAnalyzer

import (
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// Function to get information from packet layers.
func PacketInfo(packet gopacket.Packet, decoded []gopacket.LayerType, ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP, udp *layers.UDP) (string, string, int, time.Time) {
	var connection string = ""
	packetData := strings.Split(packet.String(), "\n")[0]

	layout := "2006-01-02 15:04:05 -0700 MST"

	packetSize, _ := strconv.Atoi(strings.Split(strings.Split(strings.Split(packetData, ":")[1], ",")[0], " ")[1])
	packetTime, _ := time.Parse(layout, strings.Split(packetData, "@")[1][1:])

	// Let's see if the packet is an ethernet packet
	// ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	// if ethernetLayer != nil {
	// 	logrus.Info("Ethernet layer detected.")
	// 	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	// 	logrus.Info("Source MAC: ", ethernetPacket.SrcMAC)
	// 	logrus.Info("Destination MAC: ", ethernetPacket.DstMAC)
	// 	// Ethernet type is typically IPv4 but could be ARP or other
	// 	logrus.Info("Ethernet type: ", ethernetPacket.EthernetType)
	// 	logrus.Info()
	// }

	// Let's see if the packet is IP (even though the ether type told us)

	// IP layer variables:
	// Version (Either 4 or 6)
	// IHL (IP Header Length in 32-bit words)
	// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
	// Checksum, SrcIP, DstIP
	if slices.Contains(decoded, layers.LayerTypeIPv4) {

		connection += ip4.SrcIP.String() + "--" + ip4.DstIP.String() + "--" + ip4.Protocol.String()
	} else if slices.Contains(decoded, layers.LayerTypeIPv6) {

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		connection += ip6.SrcIP.String() + "--" + ip6.DstIP.String() + "--" + ip6.NextHeader.String()
	} else {
		// Return early
		return connection, "nil", packetSize, packetTime
	}

	// Let's see if the packet is TCP
	if slices.Contains(decoded, layers.LayerTypeTCP) {
		//logrus.Info("TCP layer detected.")
		connection += "--" + tcp.SrcPort.String() + "--" + tcp.DstPort.String()

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		// logrus.Info("Sequence number: ", tcp.Seq)
	} else if slices.Contains(decoded, layers.LayerTypeUDP) {
		//logrus.Info("UDP layer detected.")
		connection += "--" + udp.SrcPort.String() + "--" + udp.DstPort.String()

		// UDP layer variables:
		// SrcPort, DstPort, Length, Checksum
	} else {
		// Return early
		return connection, "nil", packetSize, packetTime
	}

	// // Iterate over all layers, printing out each layer type
	// logrus.Info("All packet layers:")
	// for _, layer := range packet.Layers() {
	// 	logrus.Info("- ", layer.LayerType())
	// }

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload

	applicationLayer := packet.ApplicationLayer()

	if applicationLayer != nil {
		// logrus.Info("Application layer/Payload found. ", applicationLayer.Payload())
		// logrus.Info("%s\n", applicationLayer.Payload())

		// 	// Search for a string inside the payload
		// 	if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		// 		logrus.Info("HTTP found!")
		// 	}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {

		logrus.Info("Error decoding some part of the packet:", err)
		for _, l := range packet.Layers() {
			layer := gopacket.LayerString(l)
			logrus.Info("Error decoding some part of the packet:", layer)
		}
	}

	// Return if protocol=TCP/UDP and if packets have correct time stamps.
	if packetTime.String()[0:19] != "0001-01-01 00:00:00" {
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
