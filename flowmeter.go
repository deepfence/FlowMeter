package main

import (

	//"flowmeter/constants"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deepfence/deepfence_flowmeter/common"
	"github.com/deepfence/deepfence_flowmeter/constants"
	"github.com/deepfence/deepfence_flowmeter/fileProcess"
	"github.com/deepfence/deepfence_flowmeter/ml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
		localIP = GetOutboundIP().String()
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

	go flowMeter(ch, done, maxNumPackets, localIP, ifLocalIPKnown, filename)

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

// This go routine communicates through channels and computes flow stats
func flowMeter(ch chan gopacket.Packet, done chan struct{}, maxNumPackets int, localIP string, ifLocalIPKnown bool, fname string) {

	//saveIntervals := []int{4294000, 4294500, 4295000} //for stratosphere malicious
	//saveIntervals := []int{9500000, 9600000, 9700000, 9800000, 9900000, 10000000, 11000000, 12000000, 15000000, 17000000, 20000000, 22000000}
	saveIntervals := []int{1500000, 2500000, 3000000, 4000000, 5000000, 7000000}

	flowDict := make(map[string][]interface{})
	flowSave := make(map[string][]interface{})

	ifFlowStatsShow := true

	mapKeys := make(map[string]int)
	mapKeys["srcIP"], mapKeys["dstIP"], mapKeys["protocol"], mapKeys["srcPort"], mapKeys["dstPort"], mapKeys["flowDuration"], mapKeys["flowLength"], mapKeys["fwdFlowLength"], mapKeys["bwdFlowLength"], mapKeys["packetSizeTotal"], mapKeys["packetSizeMean"], mapKeys["packetSizeStd"], mapKeys["packetSizeMin"], mapKeys["packetSizeMax"], mapKeys["fwdPacketSizeTotal"], mapKeys["bwdPacketSizeTotal"], mapKeys["fwdPacketSizeMean"], mapKeys["bwdPacketSizeMean"], mapKeys["fwdPacketSizeStd"], mapKeys["bwdPacketSizeStd"], mapKeys["fwdPacketSizeMin"], mapKeys["bwdPacketSizeMin"], mapKeys["fwdPacketSizeMax"], mapKeys["bwdPacketSizeMax"], mapKeys["IATTotal"], mapKeys["IATMean"], mapKeys["IATStd"], mapKeys["IATMin"], mapKeys["IATMax"], mapKeys["fwdIATTotal"], mapKeys["bwdIATTotal"], mapKeys["fwdIATMean"], mapKeys["bwdIATMean"], mapKeys["fwdIATStd"], mapKeys["bwdIATStd"], mapKeys["fwdIATMin"], mapKeys["bwdIATMin"], mapKeys["fwdIATMax"], mapKeys["bwdIATMax"], mapKeys["flowStartTime"], mapKeys["flowPrevTime"], mapKeys["fwdFlowPrevTime"], mapKeys["bwdFlowPrevTime"], mapKeys["minPacketsBool"], mapKeys["fwdPacketSizeArr"], mapKeys["bwdPacketSizeArr"], mapKeys["fwdIATArr"], mapKeys["bwdIATArr"], mapKeys["IATArr"], mapKeys["packetSizeArr"] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49

	mapLabels := make(map[int]string)
	mapLabels[0], mapLabels[1], mapLabels[2], mapLabels[3], mapLabels[4], mapLabels[5], mapLabels[6], mapLabels[7], mapLabels[8], mapLabels[9], mapLabels[10], mapLabels[11], mapLabels[12], mapLabels[13], mapLabels[14], mapLabels[15], mapLabels[16], mapLabels[17], mapLabels[18], mapLabels[19], mapLabels[20], mapLabels[21], mapLabels[22], mapLabels[23], mapLabels[24], mapLabels[25], mapLabels[26], mapLabels[27], mapLabels[28], mapLabels[29], mapLabels[30], mapLabels[31], mapLabels[32], mapLabels[33], mapLabels[34], mapLabels[35], mapLabels[36], mapLabels[37], mapLabels[38], mapLabels[39], mapLabels[40] = "Source IP", "Dest IP", "Protocol", "Source Port", "Dest Port", "Flow Duration", "Flow Length", "Fwd Flow Length", "Bwd Flow Length", "Packet Size Total", "Packet Size Mean", "Packet Size Std", "Packet Size Min", "Packet Size Max", "Fwd Packet Size Total", "Bwd Packet Size Total", "Fwd Packet Size Mean", "Bwd Packet Size Mean", "Fwd Packet Size Std", "Bwd Packet Size Std", "Fwd Packet Size Min", "Bwd Packet Size Min", "Fwd Packet Size Max", "Bwd Packet Size Max", "IAT Total", "IAT Mean", "IAT Std", "IAT Min", "IAT Max", "Fwd IAT Total", "Bwd IAT Total", "Fwd IAT Mean", "Bwd IAT Mean", "Fwd IAT Std", "Bwd IAT Std", "Fwd IAT Min", "Bwd IAT Min", "Fwd IAT Max", "Bwd IAT Max", "Flow Start Time", "Flow Latest Time"

	// Import model parameters (weight, scaling - mean, standard deviations)
	wt, intercept, meanScale, stdScale := ml.ModelParameters()

	numPackets := 0

	for packet := range ch {
		numPackets++

		// if numPackets > 0 {
		// 	fmt.Println("Num packets: ", numPackets)
		// 	fmt.Println(" ")
		// }

		packet5Tuple, reverseTuple, packetSize, packetTime := packetInfo(packet)

		if reverseTuple != "nil" {

			ok, ok1, ok2 := true, true, true
			direction := ""

			// Ascertain directionality.
			if ifLocalIPKnown {
				if strings.Split(packet5Tuple, "--")[0] == localIP {
					_, ok = flowDict[packet5Tuple] //If packet5Tuple is localIP. Check if flow key for this already exists.
					direction = "fwd"
				} else {
					_, ok = flowDict[reverseTuple] //If packetReverse5Tuple is localIP. Check if flow key for this already exists.
					packet5Tuple = reverseTuple
					direction = "bwd"
				}
			} else {
				_, ok1 = flowDict[packet5Tuple]
				_, ok2 = flowDict[reverseTuple]

				ok = ok1 || ok2

				if (ok1 == false) && (ok2 == false) {
					direction = "fwd"
				} else if (ok1 == true) && (ok2 == false) {
					direction = "fwd"
				} else if (ok1 == false) && (ok2 == true) {
					packet5Tuple = reverseTuple
					direction = "bwd"
				} else {
					fmt.Println("We shouldn't have keys for flow-five-tuple and reverse-five-tuple. Error in code.")
				}

			}

			dstIPFlow, srcIPFlow, protocolFlow, dstPortFlow, srcPortFlow := strings.Split(packet5Tuple, "--")[0], strings.Split(packet5Tuple, "--")[1], strings.Split(packet5Tuple, "--")[2], strings.Split(packet5Tuple, "--")[3], strings.Split(packet5Tuple, "--")[4]

			fwdPacketSize, bwdPacketSize := 0, 0

			if !ok {

				flowDict[packet5Tuple] = []interface{}{srcIPFlow, dstIPFlow, protocolFlow, srcPortFlow, dstPortFlow, 0 * time.Microsecond, 1, 0, 0, packetSize, float64(packetSize), 0.0, packetSize, packetSize, fwdPacketSize, bwdPacketSize, 0.0, 0.0, 0.0, 0.0, 0, 0, 0, 0, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, packetTime, packetTime, packetTime, packetTime, false, []int{}, []int{}, []time.Duration{}, []time.Duration{}, []time.Duration{}, []int{packetSize}}

				//Some debugging line
				if packet5Tuple == "192.168.1.191--178.249.101.23--TCP--42066--443(https)" {
					fmt.Println("Debugging", flowDict[packet5Tuple][mapKeys["flowDuration"]], flowDict[packet5Tuple][mapKeys["flowLength"]])
				}

				if direction == "fwd" {
					fwdPacketSize, bwdPacketSize = 1.0*packetSize, 0.0

					flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]] = append(flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]].([]int), fwdPacketSize)
					flowDict[packet5Tuple][mapKeys["fwdPacketSizeTotal"]] = fwdPacketSize
					flowDict[packet5Tuple][mapKeys["fwdPacketSizeMean"]] = float64(fwdPacketSize)
					flowDict[packet5Tuple][mapKeys["fwdFlowLength"]] = 1
				} else {
					fwdPacketSize, bwdPacketSize = 0.0, 1.0*packetSize

					flowDict[packet5Tuple][mapKeys["bwdPacketSizeArr"]] = append(flowDict[packet5Tuple][mapKeys["bwdPacketSizeArr"]].([]int), bwdPacketSize)
					flowDict[packet5Tuple][mapKeys["bwdPacketSizeTotal"]] = bwdPacketSize
					flowDict[packet5Tuple][mapKeys["bwdPacketSizeMean"]] = float64(bwdPacketSize)
					flowDict[packet5Tuple][mapKeys["bwdFlowLength"]] = 1
				}

			} else {

				if flowDict[packet5Tuple][mapKeys["flowLength"]].(int) <= constants.MaxPacketPerFlow {
					currIAT := packetTime.Sub(flowDict[packet5Tuple][mapKeys["flowPrevTime"]].(time.Time))
					flowDict[packet5Tuple][mapKeys["IATArr"]] = append(flowDict[packet5Tuple][mapKeys["IATArr"]].([]time.Duration), currIAT)

					if direction == "fwd" {
						fwdPacketSize, bwdPacketSize = packetSize, 0

						flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]] = append(flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]].([]int), fwdPacketSize)
						flowDict[packet5Tuple][mapKeys["packetSizeArr"]] = append(flowDict[packet5Tuple][mapKeys["packetSizeArr"]].([]int), fwdPacketSize)
						flowDict[packet5Tuple][mapKeys["fwdFlowLength"]] = flowDict[packet5Tuple][mapKeys["fwdFlowLength"]].(int) + 1

						if flowDict[packet5Tuple][mapKeys["fwdFlowLength"]] == 1 {
							flowDict[packet5Tuple][mapKeys["fwdFlowPrevTime"]] = packetTime
						} else {
							currFwdIAT := packetTime.Sub(flowDict[packet5Tuple][mapKeys["fwdFlowPrevTime"]].(time.Time))

							flowDict[packet5Tuple][mapKeys["fwdIATTotal"]] = flowDict[packet5Tuple][mapKeys["fwdIATTotal"]].(time.Duration) + currFwdIAT
							flowDict[packet5Tuple][mapKeys["fwdIATArr"]] = append(flowDict[packet5Tuple][mapKeys["fwdIATArr"]].([]time.Duration), currFwdIAT)
							fwdIATMin, fwdIATMax := common.MinMaxTimeDuration(flowDict[packet5Tuple][mapKeys["fwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][mapKeys["fwdIATMean"]] = common.MeanTimeDuration(flowDict[packet5Tuple][mapKeys["fwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][mapKeys["fwdIATStd"]] = common.StdDevTimeDuration(flowDict[packet5Tuple][mapKeys["fwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][mapKeys["fwdIATMin"]] = fwdIATMin
							flowDict[packet5Tuple][mapKeys["fwdIATMax"]] = fwdIATMax
							flowDict[packet5Tuple][mapKeys["fwdFlowPrevTime"]] = packetTime
						}

					}

					if direction == "bwd" {
						fwdPacketSize, bwdPacketSize = 0, packetSize
						flowDict[packet5Tuple][mapKeys["bwdPacketSizeArr"]] = append(flowDict[packet5Tuple][mapKeys["bwdPacketSizeArr"]].([]int), bwdPacketSize)
						flowDict[packet5Tuple][mapKeys["packetSizeArr"]] = append(flowDict[packet5Tuple][mapKeys["packetSizeArr"]].([]int), bwdPacketSize)
						flowDict[packet5Tuple][mapKeys["bwdFlowLength"]] = flowDict[packet5Tuple][mapKeys["bwdFlowLength"]].(int) + 1

						if flowDict[packet5Tuple][mapKeys["bwdFlowLength"]] == 1 {
							flowDict[packet5Tuple][mapKeys["bwdFlowPrevTime"]] = packetTime
						} else {

							currBwdIAT := packetTime.Sub(flowDict[packet5Tuple][mapKeys["bwdFlowPrevTime"]].(time.Time))

							flowDict[packet5Tuple][mapKeys["bwdIATTotal"]] = flowDict[packet5Tuple][mapKeys["bwdIATTotal"]].(time.Duration) + currBwdIAT
							flowDict[packet5Tuple][mapKeys["bwdIATArr"]] = append(flowDict[packet5Tuple][mapKeys["bwdIATArr"]].([]time.Duration), currBwdIAT)
							bwdIATMin, bwdIATMax := common.MinMaxTimeDuration(flowDict[packet5Tuple][mapKeys["bwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][mapKeys["bwdIATMean"]] = common.MeanTimeDuration(flowDict[packet5Tuple][mapKeys["bwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][mapKeys["bwdIATStd"]] = common.StdDevTimeDuration(flowDict[packet5Tuple][mapKeys["bwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][mapKeys["bwdIATMin"]] = bwdIATMin
							flowDict[packet5Tuple][mapKeys["bwdIATMax"]] = bwdIATMax
							flowDict[packet5Tuple][mapKeys["bwdFlowPrevTime"]] = packetTime
						}

					}

					flowDict[packet5Tuple][mapKeys["flowDuration"]] = packetTime.Sub(flowDict[packet5Tuple][mapKeys["flowStartTime"]].(time.Time))

					// if packet5Tuple == "192.168.1.191--178.249.101.23--TCP--42066--443(https)" {
					// 	fmt.Println("Not start", flowDict[packet5Tuple][mapKeys["flowDuration"]], flowDict[packet5Tuple][mapKeys["flowLength"]], flowDict[packet5Tuple][mapKeys["flowStartTime"]], packetTime)
					// }

					flowDict[packet5Tuple][mapKeys["flowLength"]] = flowDict[packet5Tuple][mapKeys["flowLength"]].(int) + 1

					IATArr := append(flowDict[packet5Tuple][mapKeys["fwdIATArr"]].([]time.Duration), flowDict[packet5Tuple][mapKeys["bwdIATArr"]].([]time.Duration)...)
					//flowDict[packet5Tuple][mapKeys["IATTotal"]] = flowDict[packet5Tuple][mapKeys["IATTotal"]].(time.Duration) + currIAT
					flowDict[packet5Tuple][mapKeys["IATTotal"]] = flowDict[packet5Tuple][mapKeys["fwdIATTotal"]].(time.Duration) + flowDict[packet5Tuple][mapKeys["bwdIATTotal"]].(time.Duration)
					IATMin, IATMax := common.MinMaxTimeDuration(IATArr)
					flowDict[packet5Tuple][mapKeys["IATMin"]] = IATMin
					flowDict[packet5Tuple][mapKeys["IATMax"]] = IATMax
					flowDict[packet5Tuple][mapKeys["IATMean"]] = common.MeanTimeDuration(IATArr)
					if len(IATArr) > 1 {
						flowDict[packet5Tuple][mapKeys["IATStd"]] = common.StdDevTimeDuration(IATArr)
					}

					// fmt.Println("AA1: ", flowDict[packet5Tuple][mapKeys["fwdIATArr"]], common.SumTimeDuration(flowDict[packet5Tuple][mapKeys["fwdIATArr"]].([]time.Duration)), flowDict[packet5Tuple][mapKeys["fwdIATTotal"]])
					// fmt.Println("AA2: ", flowDict[packet5Tuple][mapKeys["bwdIATArr"]], common.SumTimeDuration(flowDict[packet5Tuple][mapKeys["bwdIATArr"]].([]time.Duration)), flowDict[packet5Tuple][mapKeys["bwdIATTotal"]])
					// fmt.Println("AA3: ", IATArr, common.SumTimeDuration(flowDict[packet5Tuple][mapKeys["IATArr"]].([]time.Duration)), flowDict[packet5Tuple][mapKeys["IATTotal"]])
					// fmt.Println(" ")
					// fmt.Println(" ")

					flowDict[packet5Tuple][mapKeys["flowPrevTime"]] = packetTime

					fwdPacketSizeMin, fwdPacketSizeMax := common.MinMax(flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]].([]int))
					bwdPacketSizeMin, bwdPacketSizeMax := common.MinMax(flowDict[packet5Tuple][mapKeys["bwdPacketSizeArr"]].([]int))

					flowDict[packet5Tuple][mapKeys["fwdPacketSizeTotal"]] = flowDict[packet5Tuple][mapKeys["fwdPacketSizeTotal"]].(int) + fwdPacketSize
					flowDict[packet5Tuple][mapKeys["bwdPacketSizeTotal"]] = flowDict[packet5Tuple][mapKeys["bwdPacketSizeTotal"]].(int) + bwdPacketSize

					flowDict[packet5Tuple][mapKeys["fwdPacketSizeMean"]] = common.Mean(flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]].([]int))
					flowDict[packet5Tuple][mapKeys["bwdPacketSizeMean"]] = common.Mean(flowDict[packet5Tuple][mapKeys["bwdPacketSizeArr"]].([]int))

					flowDict[packet5Tuple][mapKeys["fwdPacketSizeStd"]] = common.StdDev(flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]].([]int))
					flowDict[packet5Tuple][mapKeys["bwdPacketSizeStd"]] = common.StdDev(flowDict[packet5Tuple][mapKeys["bwdPacketSizeArr"]].([]int))

					flowDict[packet5Tuple][mapKeys["fwdPacketSizeMin"]] = fwdPacketSizeMin
					flowDict[packet5Tuple][mapKeys["bwdPacketSizeMin"]] = bwdPacketSizeMin

					flowDict[packet5Tuple][mapKeys["fwdPacketSizeMax"]] = fwdPacketSizeMax
					flowDict[packet5Tuple][mapKeys["bwdPacketSizeMax"]] = bwdPacketSizeMax

					// flowDict[packet5Tuple][mapKeys["packetSizeArr"]]
					flowDict[packet5Tuple][mapKeys["packetSizeTotal"]] = flowDict[packet5Tuple][mapKeys["fwdPacketSizeTotal"]].(int) + flowDict[packet5Tuple][mapKeys["bwdPacketSizeTotal"]].(int)
					//packetSizeArr := append(flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]].([]int), flowDict[packet5Tuple][mapKeys["fwdPacketSizeArr"]].([]int)...)
					packetSizeMin, packetSizeMax := common.MinMax(flowDict[packet5Tuple][mapKeys["packetSizeArr"]].([]int))
					flowDict[packet5Tuple][mapKeys["packetSizeMin"]] = packetSizeMin
					flowDict[packet5Tuple][mapKeys["packetSizeMax"]] = packetSizeMax
					flowDict[packet5Tuple][mapKeys["packetSizeMean"]] = common.Mean(flowDict[packet5Tuple][mapKeys["packetSizeArr"]].([]int))
					flowDict[packet5Tuple][mapKeys["packetSizeStd"]] = common.StdDev(flowDict[packet5Tuple][mapKeys["packetSizeArr"]].([]int))

					if flowDict[packet5Tuple][mapKeys["flowLength"]].(int) >= constants.MinPacketPerFlow {
						flowDict[packet5Tuple][mapKeys["minPacketsBool"]] = true
					}
				}

			}

			_, ifSave := common.IfPresentInSlice(saveIntervals, numPackets)

			if ifSave {
				// if flowDict[packet5Tuple][mapKeys["flowLength"]].(int) <= constants.MaxPacketPerFlow {

				if len(flowDict) > 0 {
					for flow5Tuple, values := range flowDict {

						features := []float64{}

						// fmt.Println(flow5Tuple, flowDict[flow5Tuple][mapKeys["flowLength"]], constants.MinPacketPerFlow, numPackets, " - Flow stats.")

						if (flowDict[flow5Tuple][mapKeys["flowLength"]].(int) >= constants.MinPacketPerFlow) && (flowDict[flow5Tuple][mapKeys["flowDuration"]].(time.Duration) >= constants.MinTimeDuration) {
							// Pupulate flowSave map with flows for which number of packets is beyond a given threshold
							flowSave[flow5Tuple] = values

							// Create feature array for machine learning (ML) analysis
							features = append(features, values[mapKeys["packetSizeMean"]].(float64), values[mapKeys["packetSizeStd"]].(float64), float64(values[mapKeys["packetSizeMin"]].(int)), float64(values[mapKeys["packetSizeMax"]].(int)), values[mapKeys["fwdPacketSizeMean"]].(float64), values[mapKeys["bwdPacketSizeMean"]].(float64), values[mapKeys["fwdPacketSizeStd"]].(float64), values[mapKeys["bwdPacketSizeStd"]].(float64), float64(values[mapKeys["fwdPacketSizeMin"]].(int)), float64(values[mapKeys["bwdPacketSizeMin"]].(int)), float64(values[mapKeys["fwdPacketSizeMax"]].(int)), float64(values[mapKeys["bwdPacketSizeMax"]].(int)), float64(flowDict[flow5Tuple][mapKeys["flowLength"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][mapKeys["fwdFlowLength"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][mapKeys["bwdFlowLength"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][mapKeys["packetSizeTotal"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][mapKeys["fwdPacketSizeTotal"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][mapKeys["bwdPacketSizeTotal"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Nanosecond))

							if ifFlowStatsShow {

								// Scaling of array and ML prediction
								scaledFeature := ml.StdScaler(features, meanScale, stdScale)
								yPred := ml.GetCategory(ml.BinaryClassifier(ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature))))

								fmt.Println(flow5Tuple, ": ", yPred, ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature)))
								fmt.Println(" ")

								// Print flow statistics
								for j := 0; j < 41; j++ {
									fmt.Println(mapLabels[j], ": ", flowDict[flow5Tuple][j])
								}
								fmt.Println("Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][mapKeys["flowLength"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Fwd Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][mapKeys["fwdFlowLength"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Bwd Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][mapKeys["bwdFlowLength"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][mapKeys["packetSizeTotal"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Fwd Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][mapKeys["fwdPacketSizeTotal"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Bwd Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][mapKeys["bwdPacketSizeTotal"]].(int))/float64(values[mapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println(" ")
								fmt.Println(" ")
							}

							// fmt.Println("Number of saved flows:", len(flowSave))

							// Delete flow key if flow is benign
							// delete(flowDict, flow5Tuple)

							// fmt.Println(" ")
							// fmt.Println(" ")

						}

					}

				}

				fmt.Println("Saving3", numPackets)
				fileProcess.FileSave(flowSave, mapKeys, fname+"_flow_stats")
			}
		}

		if numPackets == maxNumPackets {
			print("Target number packets reached.")
			done <- struct{}{}
			return
		}

	}

}

// Function to analyze packets
func packetInfo(packet gopacket.Packet) (string, string, int, time.Time) {

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
		return connection, reverse5Tuple(connection), packetSize, packetTime
	} else {
		return connection, "nil", packetSize, packetTime
	}

}

// GetOutboundIP: Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// Reverse a 5 tuple
func reverse5Tuple(fTuple string) string {
	srcIP, dstIP, protocol, srcPort, dstPort := strings.Split(fTuple, "--")[0], strings.Split(fTuple, "--")[1], strings.Split(fTuple, "--")[2], strings.Split(fTuple, "--")[3], strings.Split(fTuple, "--")[4]

	return dstIP + "--" + srcIP + "--" + protocol + "--" + dstPort + "--" + srcPort
}
