package packetAnalyzer

import (
	"fmt"
	"strings"
	"time"

	"github.com/deepfence/deepfence_flowmeter/common"
	"github.com/deepfence/deepfence_flowmeter/constants"
	"github.com/deepfence/deepfence_flowmeter/ml"
	"github.com/google/gopacket"
)

// This go routine communicates through channels and computes flow stats
func FlowMeter(ch chan gopacket.Packet, done chan struct{}, maxNumPackets int, localIP string, ifLocalIPKnown bool, fname string) {
	flowDict := make(map[string][]interface{})
	flowSave := make(map[string][]interface{})

	// Import model parameters (weight, scaling - mean, standard deviations)
	wt, intercept, meanScale, stdScale := ml.ModelParameters()

	numPackets := 0

	for packet := range ch {
		numPackets++

		if constants.Verbose {
			if numPackets > 0 {
				fmt.Println("Num packets: ", numPackets)
				fmt.Println(" ")
			}
		}

		packet5Tuple, reverseTuple, packetSize, packetTime := PacketInfo(packet)

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

				if (!ok1) && (!ok2) {
					direction = "fwd"
				} else if (ok1) && (!ok2) {
					direction = "fwd"
				} else if (!ok1) && (ok2) {
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
					fmt.Println("Debugging", flowDict[packet5Tuple][constants.MapKeys["flowDuration"]], flowDict[packet5Tuple][constants.MapKeys["flowLength"]])
				}

				if direction == "fwd" {
					fwdPacketSize, bwdPacketSize = 1.0*packetSize, 0.0

					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]].([]int), fwdPacketSize)
					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeTotal"]] = fwdPacketSize
					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeMean"]] = float64(fwdPacketSize)
					flowDict[packet5Tuple][constants.MapKeys["fwdFlowLength"]] = 1
				} else {
					fwdPacketSize, bwdPacketSize = 0.0, 1.0*packetSize

					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeArr"]].([]int), bwdPacketSize)
					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeTotal"]] = bwdPacketSize
					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeMean"]] = float64(bwdPacketSize)
					flowDict[packet5Tuple][constants.MapKeys["bwdFlowLength"]] = 1
				}

			} else {

				if flowDict[packet5Tuple][constants.MapKeys["flowLength"]].(int) <= constants.MaxPacketPerFlow {
					currIAT := packetTime.Sub(flowDict[packet5Tuple][constants.MapKeys["flowPrevTime"]].(time.Time))
					flowDict[packet5Tuple][constants.MapKeys["IATArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["IATArr"]].([]time.Duration), currIAT)

					if direction == "fwd" {
						fwdPacketSize, bwdPacketSize = packetSize, 0

						flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]].([]int), fwdPacketSize)
						flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]].([]int), fwdPacketSize)
						flowDict[packet5Tuple][constants.MapKeys["fwdFlowLength"]] = flowDict[packet5Tuple][constants.MapKeys["fwdFlowLength"]].(int) + 1

						if flowDict[packet5Tuple][constants.MapKeys["fwdFlowLength"]] == 1 {
							flowDict[packet5Tuple][constants.MapKeys["fwdFlowPrevTime"]] = packetTime
						} else {
							currFwdIAT := packetTime.Sub(flowDict[packet5Tuple][constants.MapKeys["fwdFlowPrevTime"]].(time.Time))

							flowDict[packet5Tuple][constants.MapKeys["fwdIATTotal"]] = flowDict[packet5Tuple][constants.MapKeys["fwdIATTotal"]].(time.Duration) + currFwdIAT
							flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]].([]time.Duration), currFwdIAT)
							fwdIATMin, fwdIATMax := common.MinMaxTimeDuration(flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][constants.MapKeys["fwdIATMean"]] = common.MeanTimeDuration(flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][constants.MapKeys["fwdIATStd"]] = common.StdDevTimeDuration(flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][constants.MapKeys["fwdIATMin"]] = fwdIATMin
							flowDict[packet5Tuple][constants.MapKeys["fwdIATMax"]] = fwdIATMax
							flowDict[packet5Tuple][constants.MapKeys["fwdFlowPrevTime"]] = packetTime
						}

					}

					if direction == "bwd" {
						fwdPacketSize, bwdPacketSize = 0, packetSize
						flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeArr"]].([]int), bwdPacketSize)
						flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]].([]int), bwdPacketSize)
						flowDict[packet5Tuple][constants.MapKeys["bwdFlowLength"]] = flowDict[packet5Tuple][constants.MapKeys["bwdFlowLength"]].(int) + 1

						if flowDict[packet5Tuple][constants.MapKeys["bwdFlowLength"]] == 1 {
							flowDict[packet5Tuple][constants.MapKeys["bwdFlowPrevTime"]] = packetTime
						} else {

							currBwdIAT := packetTime.Sub(flowDict[packet5Tuple][constants.MapKeys["bwdFlowPrevTime"]].(time.Time))

							flowDict[packet5Tuple][constants.MapKeys["bwdIATTotal"]] = flowDict[packet5Tuple][constants.MapKeys["bwdIATTotal"]].(time.Duration) + currBwdIAT
							flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]] = append(flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]].([]time.Duration), currBwdIAT)
							bwdIATMin, bwdIATMax := common.MinMaxTimeDuration(flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][constants.MapKeys["bwdIATMean"]] = common.MeanTimeDuration(flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][constants.MapKeys["bwdIATStd"]] = common.StdDevTimeDuration(flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]].([]time.Duration))
							flowDict[packet5Tuple][constants.MapKeys["bwdIATMin"]] = bwdIATMin
							flowDict[packet5Tuple][constants.MapKeys["bwdIATMax"]] = bwdIATMax
							flowDict[packet5Tuple][constants.MapKeys["bwdFlowPrevTime"]] = packetTime
						}

					}

					flowDict[packet5Tuple][constants.MapKeys["flowDuration"]] = packetTime.Sub(flowDict[packet5Tuple][constants.MapKeys["flowStartTime"]].(time.Time))

					// if packet5Tuple == "192.168.1.191--178.249.101.23--TCP--42066--443(https)" {
					// 	fmt.Println("Not start", flowDict[packet5Tuple][constants.MapKeys["flowDuration"]], flowDict[packet5Tuple][constants.MapKeys["flowLength"]], flowDict[packet5Tuple][constants.MapKeys["flowStartTime"]], packetTime)
					// }

					flowDict[packet5Tuple][constants.MapKeys["flowLength"]] = flowDict[packet5Tuple][constants.MapKeys["flowLength"]].(int) + 1

					IATArr := append(flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]].([]time.Duration), flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]].([]time.Duration)...)
					//flowDict[packet5Tuple][constants.MapKeys["IATTotal"]] = flowDict[packet5Tuple][constants.MapKeys["IATTotal"]].(time.Duration) + currIAT
					flowDict[packet5Tuple][constants.MapKeys["IATTotal"]] = flowDict[packet5Tuple][constants.MapKeys["fwdIATTotal"]].(time.Duration) + flowDict[packet5Tuple][constants.MapKeys["bwdIATTotal"]].(time.Duration)
					IATMin, IATMax := common.MinMaxTimeDuration(IATArr)
					flowDict[packet5Tuple][constants.MapKeys["IATMin"]] = IATMin
					flowDict[packet5Tuple][constants.MapKeys["IATMax"]] = IATMax
					flowDict[packet5Tuple][constants.MapKeys["IATMean"]] = common.MeanTimeDuration(IATArr)
					if len(IATArr) > 1 {
						flowDict[packet5Tuple][constants.MapKeys["IATStd"]] = common.StdDevTimeDuration(IATArr)
					}

					// fmt.Println("AA1: ", flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]], common.SumTimeDuration(flowDict[packet5Tuple][constants.MapKeys["fwdIATArr"]].([]time.Duration)), flowDict[packet5Tuple][constants.MapKeys["fwdIATTotal"]])
					// fmt.Println("AA2: ", flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]], common.SumTimeDuration(flowDict[packet5Tuple][constants.MapKeys["bwdIATArr"]].([]time.Duration)), flowDict[packet5Tuple][constants.MapKeys["bwdIATTotal"]])
					// fmt.Println("AA3: ", IATArr, common.SumTimeDuration(flowDict[packet5Tuple][constants.MapKeys["IATArr"]].([]time.Duration)), flowDict[packet5Tuple][constants.MapKeys["IATTotal"]])
					// fmt.Println(" ")
					// fmt.Println(" ")

					flowDict[packet5Tuple][constants.MapKeys["flowPrevTime"]] = packetTime

					fwdPacketSizeMin, fwdPacketSizeMax := common.MinMax(flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]].([]int))
					bwdPacketSizeMin, bwdPacketSizeMax := common.MinMax(flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeArr"]].([]int))

					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeTotal"]] = flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeTotal"]].(int) + fwdPacketSize
					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeTotal"]] = flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeTotal"]].(int) + bwdPacketSize

					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeMean"]] = common.Mean(flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]].([]int))
					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeMean"]] = common.Mean(flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeArr"]].([]int))

					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeStd"]] = common.StdDev(flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]].([]int))
					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeStd"]] = common.StdDev(flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeArr"]].([]int))

					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeMin"]] = fwdPacketSizeMin
					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeMin"]] = bwdPacketSizeMin

					flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeMax"]] = fwdPacketSizeMax
					flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeMax"]] = bwdPacketSizeMax

					// flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]]
					flowDict[packet5Tuple][constants.MapKeys["packetSizeTotal"]] = flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeTotal"]].(int) + flowDict[packet5Tuple][constants.MapKeys["bwdPacketSizeTotal"]].(int)
					//packetSizeArr := append(flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]].([]int), flowDict[packet5Tuple][constants.MapKeys["fwdPacketSizeArr"]].([]int)...)
					packetSizeMin, packetSizeMax := common.MinMax(flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]].([]int))
					flowDict[packet5Tuple][constants.MapKeys["packetSizeMin"]] = packetSizeMin
					flowDict[packet5Tuple][constants.MapKeys["packetSizeMax"]] = packetSizeMax
					flowDict[packet5Tuple][constants.MapKeys["packetSizeMean"]] = common.Mean(flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]].([]int))
					flowDict[packet5Tuple][constants.MapKeys["packetSizeStd"]] = common.StdDev(flowDict[packet5Tuple][constants.MapKeys["packetSizeArr"]].([]int))

					if flowDict[packet5Tuple][constants.MapKeys["flowLength"]].(int) >= constants.MinPacketPerFlow {
						flowDict[packet5Tuple][constants.MapKeys["minPacketsBool"]] = true
					}
				}

			}

			//fmt.Println("SaveInterval: ", constants.SaveIntervals)
			_, ifSave := common.IfPresentInSlice(constants.SaveIntervals, numPackets)

			if ifSave {
				// if flowDict[packet5Tuple][constants.MapKeys["flowLength"]].(int) <= constants.MaxPacketPerFlow {

				if len(flowDict) > 0 {
					for flow5Tuple, values := range flowDict {

						features := []float64{}

						// fmt.Println(flow5Tuple, flowDict[flow5Tuple][constants.MapKeys["flowLength"]], constants.MinPacketPerFlow, numPackets, " - Flow stats.")

						if (flowDict[flow5Tuple][constants.MapKeys["flowLength"]].(int) >= constants.MinPacketPerFlow) && (flowDict[flow5Tuple][constants.MapKeys["flowDuration"]].(time.Duration) >= constants.MinTimeDuration) {
							// Pupulate flowSave map with flows for which number of packets is beyond a given threshold
							flowSave[flow5Tuple] = values

							// Create feature array for machine learning (ML) analysis
							features = append(features, values[constants.MapKeys["packetSizeMean"]].(float64), values[constants.MapKeys["packetSizeStd"]].(float64), float64(values[constants.MapKeys["packetSizeMin"]].(int)), float64(values[constants.MapKeys["packetSizeMax"]].(int)), values[constants.MapKeys["fwdPacketSizeMean"]].(float64), values[constants.MapKeys["bwdPacketSizeMean"]].(float64), values[constants.MapKeys["fwdPacketSizeStd"]].(float64), values[constants.MapKeys["bwdPacketSizeStd"]].(float64), float64(values[constants.MapKeys["fwdPacketSizeMin"]].(int)), float64(values[constants.MapKeys["bwdPacketSizeMin"]].(int)), float64(values[constants.MapKeys["fwdPacketSizeMax"]].(int)), float64(values[constants.MapKeys["bwdPacketSizeMax"]].(int)), float64(flowDict[flow5Tuple][constants.MapKeys["flowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][constants.MapKeys["fwdFlowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][constants.MapKeys["bwdFlowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][constants.MapKeys["packetSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][constants.MapKeys["fwdPacketSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond), float64(flowDict[flow5Tuple][constants.MapKeys["bwdPacketSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Nanosecond))

							if constants.IfFlowStatsVerbose {

								// Scaling of array and ML prediction
								scaledFeature := ml.StdScaler(features, meanScale, stdScale)
								yPred := ml.GetCategory(ml.BinaryClassifier(ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature))))

								fmt.Println(flow5Tuple, ": ", yPred, ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature)))
								fmt.Println(" ")

								// Print flow statistics
								for j := 0; j < 41; j++ {
									fmt.Println(constants.MapLabels[j], ": ", flowDict[flow5Tuple][j])
								}
								fmt.Println("Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["flowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Fwd Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["fwdFlowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Bwd Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["bwdFlowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["packetSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Fwd Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["fwdPacketSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								fmt.Println("Bwd Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["bwdPacketSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
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

				fmt.Println("Saving3", numPackets, " ", constants.Kk1)
				//fileProcess.FileSave(flowSave, constants.MapKeys, fname+"_flow_stats")
			}
		}

		if numPackets == maxNumPackets {
			print("Target number packets reached.")
			done <- struct{}{}
			return
		}

	}

}
