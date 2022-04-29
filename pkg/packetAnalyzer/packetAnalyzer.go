package packetAnalyzer

import (
	"os"
	"strings"
	"time"

	"github.com/deepfence/FlowMeter/pkg/common"
	"github.com/deepfence/FlowMeter/pkg/constants"
	"github.com/deepfence/FlowMeter/pkg/fileProcess"
	"github.com/deepfence/FlowMeter/pkg/ml"
	"github.com/google/gopacket"
	"github.com/sirupsen/logrus"
)

// This go routine communicates through channels and computes flow stats
func FlowMeter(ch chan gopacket.Packet, done chan struct{}, maxNumPackets int, localIP string, ifLocalIPKnown bool, fname string) error {
	flowDict := make(map[string][]interface{})
	flowSave := make(map[string][]interface{})

	// Import model parameters (weight, scaling - mean, standard deviations)
	wt, intercept, meanScale, stdScale := ml.ModelParameters()

	numPackets := 0

	err := os.MkdirAll(constants.FlowOutputFolder, 0777)
	if err != nil {
		logrus.Error(err)
		return err
	}

	for packet := range ch {
		numPackets++

		if constants.Verbose {
			if numPackets > 0 {
				logrus.Info("Num packets: ", numPackets)
				logrus.Info(" ")
			}
		}

		packet5Tuple, reverseTuple, packetSize, packetTime := PacketInfo(packet)

		if reverseTuple != "nil" {
			ok, ok1, ok2 := true, true, true
			direction := ""

			// Ascertain directionality.
			if ifLocalIPKnown {
				if strings.Split(packet5Tuple, "--")[0] == localIP {
					//If packet5Tuple is localIP. Check if flow key for this already exists.
					_, ok = flowDict[packet5Tuple]
					direction = "fwd"
				} else {
					//If packetReverse5Tuple is localIP. Check if flow key for this already exists.
					_, ok = flowDict[reverseTuple]
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
					logrus.Info("We shouldn't have keys for flow-five-tuple and reverse-five-tuple. Error in code.")
				}

			}

			dstIPFlow, srcIPFlow, protocolFlow, dstPortFlow, srcPortFlow := strings.Split(packet5Tuple, "--")[0], strings.Split(packet5Tuple, "--")[1], strings.Split(packet5Tuple, "--")[2], strings.Split(packet5Tuple, "--")[3], strings.Split(packet5Tuple, "--")[4]

			fwdPacketSize, bwdPacketSize := 0, 0

			if !ok {
				flowDict[packet5Tuple] = []interface{}{srcIPFlow, dstIPFlow, protocolFlow, srcPortFlow, dstPortFlow, 0 * time.Microsecond, 1, 0, 0, packetSize, float64(packetSize), 0.0, packetSize, packetSize, fwdPacketSize, bwdPacketSize, 0.0, 0.0, 0.0, 0.0, 0, 0, 0, 0, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, 0 * time.Microsecond, packetTime, packetTime, packetTime, packetTime, false, []int{}, []int{}, []time.Duration{}, []time.Duration{}, []time.Duration{}, []int{packetSize}}

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
				if flowDict[packet5Tuple][constants.MapKeys["flowLength"]].(int) <= constants.MaxPacketsPerFlow {
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

					if flowDict[packet5Tuple][constants.MapKeys["flowLength"]].(int) >= constants.MinPacketsPerFlow {
						flowDict[packet5Tuple][constants.MapKeys["minPacketsBool"]] = true
					}
				}

			}

			//logrus.Info("SaveInterval: ", constants.SaveIntervals)
			_, ifSave := common.IfPresentInSlice(constants.SaveIntervals, numPackets)

			if ifSave {
				// if flowDict[packet5Tuple][constants.MapKeys["flowLength"]].(int) <= constants.MaxPacketsPerFlow {

				if len(flowDict) > 0 {
					for flow5Tuple, values := range flowDict {
						features := []float64{}

						// logrus.Info(flow5Tuple, flowDict[flow5Tuple][constants.MapKeys["flowLength"]], constants.MinPacketsPerFlow, numPackets, " - Flow stats.")

						if (flowDict[flow5Tuple][constants.MapKeys["flowLength"]].(int) >= constants.MinPacketsPerFlow) && (flowDict[flow5Tuple][constants.MapKeys["flowDuration"]].(time.Duration) >= constants.MinTimeDuration) {
							// Populate flowSave map with flows for which number of packets is beyond a given threshold.
							flowSave[flow5Tuple] = values

							// Create feature struct with float64 datatypes for features.
							flow := common.FlowData(values)

							// Create feature array for machine learning (ML) analysis.
							features = append(features, flow.FlowDuration, flow.FlowLength, flow.FwdFlowLength, flow.BwdFlowLength, flow.PacketSizeTotal, flow.PacketSizeMean, flow.PacketSizeStd, flow.PacketSizeMin, flow.PacketSizeMax, flow.FwdPacketSizeTotal, flow.BwdPacketSizeTotal, flow.FwdPacketSizeMean, flow.BwdPacketSizeMean, flow.FwdPacketSizeStd, flow.BwdPacketSizeStd, flow.FwdPacketSizeMin, flow.BwdPacketSizeMin, flow.FwdPacketSizeMax, flow.BwdPacketSizeMax, flow.IATMean, flow.IATStd, flow.IATMin, flow.IATMax, flow.FwdIATTotal, flow.BwdIATTotal, flow.FwdIATMean, flow.BwdIATMean, flow.FwdIATStd, flow.BwdIATStd, flow.FwdIATMin, flow.BwdIATMin, flow.FwdIATMax, flow.BwdIATMax, flow.FlowLengthPerTime, flow.FwdFlowLengthPerTime, flow.BwdFlowLengthPerTime, flow.PacketSizeTotalPerTime, flow.FwdPacketSizeTotalPerTime, flow.BwdPacketSizeTotalPerTime)

							if constants.IfFlowStatsVerbose {
								// Scaling of array and ML prediction
								scaledFeature := ml.StdScaler(features, meanScale, stdScale)
								yPred := ml.GetCategory(ml.BinaryClassifier(ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature))))

								logrus.Info(flow5Tuple, ": ", yPred, " ", ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature)))
								logrus.Info(" ")

								// Print flow statistics.
								for j := 0; j < 41; j++ {
									logrus.Info(constants.MapLabels[j], ": ", flowDict[flow5Tuple][j])
								}
								logrus.Info("Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["flowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								logrus.Info("Forward Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["fwdFlowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								logrus.Info("Backward Flow Length Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["bwdFlowLength"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								logrus.Info("Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["packetSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								logrus.Info("Forward Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["fwdPacketSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								logrus.Info("Backward Packet Size Per Time(ms) : ", float64(flowDict[flow5Tuple][constants.MapKeys["bwdPacketSizeTotal"]].(int))/float64(values[constants.MapKeys["flowDuration"]].(time.Duration)/time.Millisecond))
								logrus.Info(" ")
								logrus.Info(" ")
							}
						}

					}

				}

				fileProcess.FileSave(flowSave, constants.MapKeys, constants.FlowOutputFolder+"/"+fname+"_flow_stats")
			}
		}
		if numPackets == maxNumPackets {
			logrus.Info("Target number packets reached.")
			done <- struct{}{}
			return nil
		}
	}
	return nil
}
