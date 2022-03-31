package fileProcess

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"time"
)

// Save file
func FileSave(flowSave map[string][]interface{}, mapKeys map[string]int, fname string) {
	fmt.Println("Saving4")
	// fmt.Println(flowSave)

	file, err := os.Create(fname + ".csv")

	CheckErrorFileSave("Cannot create file", err)

	defer file.Close()

	writer := csv.NewWriter(file)

	defer writer.Flush()

	writer.Write([]string{"fiveTuple", "srcIP", "dstIP", "protocol", "srcPort", "dstPort", "flowDuration", "flowLength", "fwdFlowLength", "bwdFlowLength", "packetSizeTotal", "packetSizeMean", "packetSizeStd", "packetSizeMin", "packetSizeMax", "fwdPacketSizeTotal", "bwdPacketSizeTotal", "fwdPacketSizeMean", "bwdPacketSizeMean", "fwdPacketSizeStd", "bwdPacketSizeStd", "fwdPacketSizeMin", "bwdPacketSizeMin", "fwdPacketSizeMax", "bwdPacketSizeMax", "IATMean", "IATStd", "IATMin", "IATMax", "fwdIATTotal", "bwdIATTotal", "fwdIATMean", "bwdIATMean", "fwdIATStd", "bwdIATStd", "fwdIATMin", "bwdIATMin", "fwdIATMax", "bwdIATMax"})

	data := []interface{}{}

	for flow5Tuple, values := range flowSave {

		flowArr := []interface{}{flow5Tuple, values[mapKeys["srcIP"]], values[mapKeys["dstIP"]], values[mapKeys["protocol"]], values[mapKeys["srcPort"]], values[mapKeys["dstPort"]], float64(values[mapKeys["flowDuration"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["flowLength"]].(int)), float64(values[mapKeys["fwdFlowLength"]].(int)), float64(values[mapKeys["bwdFlowLength"]].(int)), float64(values[mapKeys["packetSizeTotal"]].(int)), values[mapKeys["packetSizeMean"]].(float64), values[mapKeys["packetSizeStd"]].(float64), float64(values[mapKeys["packetSizeMin"]].(int)), float64(values[mapKeys["packetSizeMax"]].(int)), float64(values[mapKeys["fwdPacketSizeTotal"]].(int)), float64(values[mapKeys["bwdPacketSizeTotal"]].(int)), values[mapKeys["fwdPacketSizeMean"]].(float64), values[mapKeys["bwdPacketSizeMean"]].(float64), values[mapKeys["fwdPacketSizeStd"]].(float64), values[mapKeys["bwdPacketSizeStd"]].(float64), float64(values[mapKeys["fwdPacketSizeMin"]].(int)), float64(values[mapKeys["bwdPacketSizeMin"]].(int)), float64(values[mapKeys["fwdPacketSizeMax"]].(int)), float64(values[mapKeys["bwdPacketSizeMax"]].(int)), float64(values[mapKeys["IATMean"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["IATStd"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["IATMin"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["IATMax"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["fwdIATTotal"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["bwdIATTotal"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["fwdIATMean"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["bwdIATMean"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["fwdIATStd"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["bwdIATStd"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["fwdIATMin"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["bwdIATMin"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["fwdIATMax"]].(time.Duration) / time.Nanosecond), float64(values[mapKeys["bwdIATMax"]].(time.Duration) / time.Nanosecond)}

		data = append(data, flowArr)
	}

	for _, value := range data {
		modValue := ModifyArrTypeFileSave(value.([]interface{}))

		err := writer.Write(modValue)

		CheckErrorFileSave("Cannot write to file", err)
	}

}

// Type cast arrays for saving of file
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

// Check errors during saving of file
func CheckErrorFileSave(message string, err error) {
	if err != nil {
		log.Fatal(message, err)
	}
}
