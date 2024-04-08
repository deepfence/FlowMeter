package packetAnalyzer

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/deepfence/FlowMeter/pkg/common"
	"github.com/deepfence/FlowMeter/pkg/constants"
	"github.com/deepfence/FlowMeter/pkg/fileProcess"
	"github.com/deepfence/FlowMeter/pkg/ml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// This go routine communicates through channels and computes flow stats
func FlowMeter(ctx context.Context, ch chan gopacket.Packet, cancel context.CancelFunc, maxNumPackets int, localIP string, ifLocalIPKnown bool, fname string) error {
	flowDict := make(map[string]constants.FlowData)
	flowSave := make(map[string]common.FlowFeatures)

	numPackets := 0

	err := os.MkdirAll(constants.FlowOutputFolder, 0777)
	if err != nil {
		logrus.Error(err)
		return err
	}

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		tcp     layers.TCP
		udp     layers.UDP
		ip6     layers.IPv6
		payload gopacket.Payload
		tls     layers.TLS
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &ip4, &ip6, &tcp, &udp, &tls, &payload, &tls)
	decodedUnderlying := [4]gopacket.LayerType{}
	decoded := decodedUnderlying[:0]

	defer cancel()

	var (
		packet gopacket.Packet
		open   bool
	)

	for {

		select {
		case packet, open = <-ch:
		case <-ctx.Done():
			return nil
		}
		if !open {
			break
		}
		numPackets++

		if constants.Verbose {
			if numPackets > 0 {
				logrus.Info("Num packets: ", numPackets)
				logrus.Info(" ")
			}
		}

		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			logrus.Debug(err)
		}
		packet5Tuple, reverseTuple, packetSize, packetTime := PacketInfo(packet, decoded, &ip4, &ip6, &tcp, &udp)

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
				flowData := constants.FlowData{
					SrcIP:              srcIPFlow,
					DstIP:              dstIPFlow,
					Protocol:           protocolFlow,
					SrcPort:            srcPortFlow,
					DstPort:            dstPortFlow,
					FlowDuration:       0 * time.Microsecond,
					FlowLength:         1,
					FwdFlowLength:      0,
					BwdFlowLength:      0,
					PacketSizeTotal:    packetSize,
					PacketSizeMean:     float64(packetSize),
					PacketSizeStd:      0.0,
					PacketSizeMin:      packetSize,
					PacketSizeMax:      packetSize,
					FwdPacketSizeTotal: fwdPacketSize,
					BwdPacketSizeTotal: bwdPacketSize,
					FwdPacketSizeMean:  0.0,
					BwdPacketSizeMean:  0.0,
					FwdPacketSizeStd:   0.0,
					BwdPacketSizeStd:   0.0,
					FwdPacketSizeMin:   0,
					BwdPacketSizeMin:   0,
					FwdPacketSizeMax:   0,
					BwdPacketSizeMax:   0,
					IATTotal:           0 * time.Microsecond,
					IATMean:            0 * time.Microsecond,
					IATStd:             0 * time.Microsecond,
					IATMin:             0 * time.Microsecond,
					IATMax:             0 * time.Microsecond,
					FwdIATTotal:        0 * time.Microsecond,
					BwdIATTotal:        0 * time.Microsecond,
					FwdIATMean:         0 * time.Microsecond,
					BwdIATMean:         0 * time.Microsecond,
					FwdIATStd:          0 * time.Microsecond,
					BwdIATStd:          0 * time.Microsecond,
					FwdIATMin:          0 * time.Microsecond,
					BwdIATMin:          0 * time.Microsecond,
					FwdIATMax:          0 * time.Microsecond,
					BwdIATMax:          0 * time.Microsecond,
					FlowStartTime:      packetTime,
					FlowPrevTime:       packetTime,
					FwdFlowPrevTime:    packetTime,
					BwdFlowPrevTime:    packetTime,
					MinPacketsBool:     false,
					FwdPacketSizeArr:   []int{},
					BwdPacketSizeArr:   []int{},
					FwdIATArr:          []time.Duration{},
					BwdIATArr:          []time.Duration{},
					IATArr:             []time.Duration{},
					PacketSizeArr:      []int{packetSize},
				}

				if direction == "fwd" {
					fwdPacketSize, bwdPacketSize = 1.0*packetSize, 0.0

					flowData.FwdPacketSizeArr = append(flowData.FwdPacketSizeArr, fwdPacketSize)
					flowData.FwdPacketSizeTotal = fwdPacketSize
					flowData.FwdPacketSizeMean = float64(fwdPacketSize)
					flowData.FwdFlowLength = 1
				} else {
					fwdPacketSize, bwdPacketSize = 0.0, 1.0*packetSize

					flowData.BwdPacketSizeArr = append(flowData.BwdPacketSizeArr, bwdPacketSize)
					flowData.BwdPacketSizeTotal = bwdPacketSize
					flowData.BwdPacketSizeMean = float64(bwdPacketSize)
					flowData.BwdFlowLength = 1
				}

				flowDict[packet5Tuple] = flowData

			} else {

				flowData := flowDict[packet5Tuple]
				if flowData.FlowLength <= constants.MaxPacketsPerFlow {
					currIAT := packetTime.Sub(flowData.FlowPrevTime)
					flowData.IATArr = append(flowData.IATArr, currIAT)

					if direction == "fwd" {
						fwdPacketSize, bwdPacketSize = packetSize, 0

						flowData.FwdPacketSizeArr = append(flowData.FwdPacketSizeArr, fwdPacketSize)
						flowData.PacketSizeArr = append(flowData.PacketSizeArr, fwdPacketSize)
						flowData.FwdFlowLength = flowData.FwdFlowLength + 1

						if flowData.FwdFlowLength == 1 {
							flowData.FwdFlowPrevTime = packetTime
						} else {
							currFwdIAT := packetTime.Sub(flowData.FwdFlowPrevTime)

							flowData.FwdIATTotal = flowData.FwdIATTotal + currFwdIAT
							flowData.FwdIATArr = append(flowData.FwdIATArr, currFwdIAT)
							fwdIATMin, fwdIATMax := common.MinMaxTimeDuration(flowData.FwdIATArr)
							flowData.FwdIATMean = common.MeanTimeDuration(flowData.FwdIATArr)
							flowData.FwdIATStd = common.StdDevTimeDuration(flowData.FwdIATArr)
							flowData.FwdIATMin = fwdIATMin
							flowData.FwdIATMax = fwdIATMax
							flowData.FwdFlowPrevTime = packetTime
						}

					}
					if direction == "bwd" {
						fwdPacketSize, bwdPacketSize = 0, packetSize
						flowData.BwdPacketSizeArr = append(flowData.BwdPacketSizeArr, bwdPacketSize)
						flowData.PacketSizeArr = append(flowData.PacketSizeArr, bwdPacketSize)
						flowData.BwdFlowLength = flowData.BwdFlowLength + 1

						if flowData.BwdFlowLength == 1 {
							flowData.BwdFlowPrevTime = packetTime
						} else {
							currBwdIAT := packetTime.Sub(flowData.BwdFlowPrevTime)

							flowData.BwdIATTotal = flowData.BwdIATTotal + currBwdIAT
							flowData.BwdIATArr = append(flowData.BwdIATArr, currBwdIAT)
							bwdIATMin, bwdIATMax := common.MinMaxTimeDuration(flowData.BwdIATArr)
							flowData.BwdIATMean = common.MeanTimeDuration(flowData.BwdIATArr)
							flowData.BwdIATStd = common.StdDevTimeDuration(flowData.BwdIATArr)
							flowData.BwdIATMin = bwdIATMin
							flowData.BwdIATMax = bwdIATMax
							flowData.BwdFlowPrevTime = packetTime
						}

					}
					flowData.FlowDuration = packetTime.Sub(flowData.FlowStartTime)

					flowData.FlowLength = flowData.FlowLength + 1

					IATArr := append(flowData.FwdIATArr, flowData.BwdIATArr...)
					//flowData.IATTotal = flowData.IATTotal.(time.Duration) + currIAT
					flowData.IATTotal = flowData.FwdIATTotal + flowData.BwdIATTotal
					IATMin, IATMax := common.MinMaxTimeDuration(IATArr)
					flowData.IATMin = IATMin
					flowData.IATMax = IATMax
					flowData.IATMean = common.MeanTimeDuration(IATArr)
					if len(IATArr) > 1 {
						flowData.IATStd = common.StdDevTimeDuration(IATArr)
					}

					flowData.FlowPrevTime = packetTime

					fwdPacketSizeMin, fwdPacketSizeMax := common.MinMax(flowData.FwdPacketSizeArr)
					bwdPacketSizeMin, bwdPacketSizeMax := common.MinMax(flowData.BwdPacketSizeArr)

					flowData.FwdPacketSizeTotal = flowData.FwdPacketSizeTotal + fwdPacketSize
					flowData.BwdPacketSizeTotal = flowData.BwdPacketSizeTotal + bwdPacketSize

					flowData.FwdPacketSizeMean = common.Mean(flowData.FwdPacketSizeArr)
					flowData.BwdPacketSizeMean = common.Mean(flowData.BwdPacketSizeArr)

					flowData.FwdPacketSizeStd = common.StdDev(flowData.FwdPacketSizeArr)
					flowData.BwdPacketSizeStd = common.StdDev(flowData.BwdPacketSizeArr)

					flowData.FwdPacketSizeMin = fwdPacketSizeMin
					flowData.BwdPacketSizeMin = bwdPacketSizeMin

					flowData.FwdPacketSizeMax = fwdPacketSizeMax
					flowData.BwdPacketSizeMax = bwdPacketSizeMax

					// flowDaTa.packetSizeArr
					flowData.PacketSizeTotal = flowData.FwdPacketSizeTotal + flowData.BwdPacketSizeTotal
					//packetSIzeArr := append(flowData.fwdPacketSizeArr.([]int), flowData.fwdPacketSizeArr.([]int)...)
					packetSizeMin, packetSizeMax := common.MinMax(flowData.PacketSizeArr)
					flowData.PacketSizeMin = packetSizeMin
					flowData.PacketSizeMax = packetSizeMax
					flowData.PacketSizeMean = common.Mean(flowData.PacketSizeArr)
					flowData.PacketSizeStd = common.StdDev(flowData.PacketSizeArr)

					flowData.MinPacketsBool = flowData.FlowLength >= constants.MinPacketsPerFlow
				}

				flowDict[packet5Tuple] = flowData
			}

			_, ifSave := common.IfPresentInSlice(constants.SaveIntervals, numPackets)

			if ifSave {
				saveFlow(flowDict, flowSave)
				fileProcess.FileSave(flowSave, constants.FlowOutputFolder+"/"+fname+"_flow_stats")
			}
		}
		if numPackets == maxNumPackets {
			break
		}
	}
	if numPackets != maxNumPackets {
		logrus.Info("Total number of packets reached: ", numPackets)
	} else {
		logrus.Info("Target number packets reached: ", maxNumPackets)
	}
	saveFlow(flowDict, flowSave)

	fileProcess.FileSave(flowSave, constants.FlowOutputFolder+"/"+fname+"_flow_stats")

	return nil
}

func saveFlow(flowDict map[string]constants.FlowData, flowSave map[string]common.FlowFeatures) {

	// Import model parameters (weight, scaling - mean, standard deviations)
	wt, intercept, meanScale, stdScale := ml.ModelParameters()

	if len(flowDict) > 0 {
		for flow5Tuple, flowData := range flowDict {
			// logrus.Info(flow5Tuple, flowDict[flow5Tuple][constants.MapKeys["flowLength"]], constants.MinPacketsPerFlow, numPackets, " - Flow stats.")

			if (flowData.FlowLength >= constants.MinPacketsPerFlow) && (flowData.FlowDuration >= constants.MinTimeDuration) {
				// Populate flowSave map with flows for which number of packets is beyond a given threshold.
				flow := common.FlowData2FlowFeatures(flowData)
				flowSave[flow5Tuple] = flow

				var features []float64

				// Create feature array for machine learning (ML) analysis.
				features = append(features,
					flow.FlowDuration,
					flow.FlowLength,
					flow.FwdFlowLength,
					flow.BwdFlowLength,
					flow.PacketSizeTotal,
					flow.PacketSizeMean,
					flow.PacketSizeStd,
					flow.PacketSizeMin,
					flow.PacketSizeMax,
					flow.FwdPacketSizeTotal,
					flow.BwdPacketSizeTotal,
					flow.FwdPacketSizeMean,
					flow.BwdPacketSizeMean,
					flow.FwdPacketSizeStd,
					flow.BwdPacketSizeStd,
					flow.FwdPacketSizeMin,
					flow.BwdPacketSizeMin,
					flow.FwdPacketSizeMax,
					flow.BwdPacketSizeMax,
					flow.IATMean,
					flow.IATStd,
					flow.IATMin,
					flow.IATMax,
					flow.FwdIATTotal,
					flow.BwdIATTotal,
					flow.FwdIATMean,
					flow.BwdIATMean,
					flow.FwdIATStd,
					flow.BwdIATStd,
					flow.FwdIATMin,
					flow.BwdIATMin,
					flow.FwdIATMax,
					flow.BwdIATMax,
					flow.FlowLengthPerTime,
					flow.FwdFlowLengthPerTime,
					flow.BwdFlowLengthPerTime,
					flow.PacketSizeTotalPerTime,
					flow.FwdPacketSizeTotalPerTime,
					flow.BwdPacketSizeTotalPerTime)

				if constants.IfFlowStatsVerbose {
					// Scaling of array and ML prediction
					scaledFeature := ml.StdScaler(features, meanScale, stdScale)
					yPred := ml.GetCategory(ml.BinaryClassifier(ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature))))

					logrus.Info(flow5Tuple, ": ", yPred, " ", ml.Sigmoid(ml.NetInput(wt, intercept, scaledFeature)))
					logrus.Info(" ")

					// Print flow statistics.
					for j := 0; j < len(features); j++ {
						logrus.Info(constants.MapLabels[j], ": ", features[j])
					}

					logrus.Info("Flow Length Per Time(ms) : ", float64(flowData.FlowLength)/flow.FlowDuration/float64(time.Millisecond))
					logrus.Info("Forward Flow Length Per Time(ms) : ", float64(flowData.FwdFlowLength)/flow.FlowDuration/float64(time.Millisecond))
					logrus.Info("Backward Flow Length Per Time(ms) : ", float64(flowData.BwdFlowLength)/flow.FlowDuration/float64(time.Millisecond))
					logrus.Info("Packet Size Per Time(ms) : ", float64(flowData.PacketSizeTotal)/flow.FlowDuration/float64(time.Millisecond))
					logrus.Info("Forward Packet Size Per Time(ms) : ", float64(flowData.FwdPacketSizeTotal)/flow.FlowDuration/float64(time.Millisecond))
					logrus.Info("Backward Packet Size Per Time(ms) : ", float64(flowData.BwdPacketSizeTotal)/flow.FlowDuration/float64(time.Millisecond))
					logrus.Info("\n")
				}
			}
		}
	} else {
		logrus.Debug("No entry to save")
	}
}
