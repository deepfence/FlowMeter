package fileProcess

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"

	"github.com/deepfence/FlowMeter/pkg/common"
)

// Save file.
func FileSave(flowSave map[string]common.FlowFeatures, fname string) {
	// logrus.Info(flowSave)

	file, err := os.Create(fname + ".csv")

	CheckErrorFileSave("Cannot create file", err)

	defer file.Close()

	writer := csv.NewWriter(file)

	defer writer.Flush()

	writer.Write([]string{"fiveTuple", "srcIP", "dstIP", "protocol", "srcPort", "dstPort", "flowDuration", "flowLength", "fwdFlowLength", "bwdFlowLength", "packetSizeTotal", "packetSizeMean", "packetSizeStd", "packetSizeMin", "packetSizeMax", "fwdPacketSizeTotal", "bwdPacketSizeTotal", "fwdPacketSizeMean", "bwdPacketSizeMean", "fwdPacketSizeStd", "bwdPacketSizeStd", "fwdPacketSizeMin", "bwdPacketSizeMin", "fwdPacketSizeMax", "bwdPacketSizeMax", "IATMean", "IATStd", "IATMin", "IATMax", "fwdIATTotal", "bwdIATTotal", "fwdIATMean", "bwdIATMean", "fwdIATStd", "bwdIATStd", "fwdIATMin", "bwdIATMin", "fwdIATMax", "bwdIATMax"})

	data := []interface{}{}

	for flow5Tuple, flow := range flowSave {

		flowArr := []interface{}{flow5Tuple, flow.SrcIP, flow.DstIP, flow.Protocol, flow.SrcPort, flow.DstPort, flow.FlowDuration, flow.FlowLength, flow.FwdFlowLength, flow.BwdFlowLength, flow.PacketSizeTotal, flow.PacketSizeMean, flow.PacketSizeStd, flow.PacketSizeMin, flow.PacketSizeMax, flow.FwdPacketSizeTotal, flow.BwdPacketSizeTotal, flow.FwdPacketSizeMean, flow.BwdPacketSizeMean, flow.FwdPacketSizeStd, flow.BwdPacketSizeStd, flow.FwdPacketSizeMin, flow.BwdPacketSizeMin, flow.FwdPacketSizeMax, flow.BwdPacketSizeMax, flow.IATMean, flow.IATStd, flow.IATMin, flow.IATMax, flow.FwdIATTotal, flow.BwdIATTotal, flow.FwdIATMean, flow.BwdIATMean, flow.FwdIATStd, flow.BwdIATStd, flow.FwdIATMin, flow.BwdIATMin, flow.FwdIATMax, flow.BwdIATMax}

		data = append(data, flowArr)
	}

	for _, value := range data {
		modValue := ModifyArrTypeFileSave(value.([]interface{}))

		err := writer.Write(modValue)

		CheckErrorFileSave("Cannot write to file", err)
	}

}

// Type cast arrays for saving of file.
func ModifyArrTypeFileSave(array []interface{}) []string {
	modArray := []string{}

	value := ""

	for i := 0; i < len(array); i++ {
		_, ok := array[i].(string)

		if ok {
			value = array[i].(string)
		} else {
			value = fmt.Sprintf("%f", array[i])
		}

		modArray = append(modArray, value)
	}

	return modArray
}

// Check errors during saving of file.
func CheckErrorFileSave(message string, err error) {
	if err != nil {
		log.Fatal(message, err)
	}
}
