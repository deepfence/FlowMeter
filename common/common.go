package common

import (
	"math"
	"time"
)

// Min or max (time.Duration datatype.)
func MinMaxTimeDuration(array []time.Duration) (time.Duration, time.Duration) {
	if len(array) == 0 {
		return 0 * time.Microsecond, 0 * time.Microsecond
	} else {
		var max time.Duration = array[0]
		var min time.Duration = array[0]

		for j := 1; j < len(array); j++ {
			value := array[j]
			if max < value {
				max = value
			}
			if min > value {
				min = value
			}
		}
		return min, max
	}
}

// Sum (time.Duration datatype.)
func SumTimeDuration(array []time.Duration) time.Duration {
	var result time.Duration = 0 * time.Microsecond
	for _, v := range array {
		result += v
	}

	return result
}

// Mean (time.Duration datatype.)
func MeanTimeDuration(array []time.Duration) time.Duration {
	sumArr := float64(SumTimeDuration(array)/time.Microsecond) / float64(len(array))

	return time.Duration(sumArr) * time.Microsecond
}

// stdDev (time.Duration datatype.)
func StdDevTimeDuration(array []time.Duration) time.Duration {

	square := float64(0)

	for j := 1; j < len(array); j++ {
		square += float64((array[j]-MeanTimeDuration(array))/time.Microsecond) * float64((array[j]-MeanTimeDuration(array))/time.Microsecond)
	}

	return time.Duration(math.Sqrt(square/float64(len(array)))) * time.Microsecond
}

// Min or max function (int datatype.)
func MinMax(array []int) (int, int) {
	if len(array) == 0 {
		return 0, 0
	} else {
		var max int = array[0]
		var min int = array[0]
		for _, value := range array {
			if max < value {
				max = value
			}
			if min > value {
				min = value
			}
		}
		return min, max
	}
}

// Sum (int datatype.)
func Sum(array []int) int {
	var result int = 0
	for _, v := range array {
		result += v
	}

	return result
}

// Mean (float64 datatype.)
func Mean(array []int) float64 {
	if len(array) == 0 {
		return 0.0
	} else {
		sumArr := float64(Sum(array)) / float64(len(array))

		return float64(sumArr)
	}
}

// stdDev (float64 datatype.)
func StdDev(array []int) float64 {
	if len(array) == 0 {
		return 0.0
	} else {
		square := float64(0)

		for _, v := range array {
			square += (float64(v) - Mean(array)) * (float64(v) - Mean(array))
		}

		return math.Sqrt(square / float64(len(array)))
	}
}

// Takes a slice and looks for an element in it. If found it will
// return it's key, otherwise it will return -1 and a bool of false.
func IfPresentInSlice(slice []int, val int) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}
