package ml

import (
	"bufio"
	"math"
	"os"
	"strconv"

	"github.com/deepfence/FlowMeter/pkg/constants"
	"github.com/sirupsen/logrus"
)

// Get categorical class.
func GetCategory(num int) string {
	if num == 0 {
		return "Benign"
	} else {
		return "Malicious"
	}
}

//Activation function - two class classifier.
func BinaryClassifier(z float64) int {
	if z >= 0.5 {
		return 1
	} else {
		return 0
	}
}

//Sigmoid function.
func Sigmoid(z float64) float64 {
	return 1.0 / (1 + math.Exp(-1*z))
}

//Net input (z.)
func NetInput(w []float64, intercept float64, x []float64) float64 {
	var z float64 = 0

	for i := 0; i < len(x); i++ {
		z += (w[i] * x[i])
	}

	return z + intercept
}

// Standard Scaler.
func StdScaler(x []float64, mu []float64, std []float64) []float64 {
	scaledX := []float64{}

	for i := 0; i < len(x); i++ {
		scaledX = append(scaledX, (x[i]-mu[i])/std[i])
	}

	return scaledX
}

// Offline values of means , standard deviation from standard scaling and weights.
func ModelParameters() ([]float64, float64, []float64, []float64) {
	// Weights from logistic regression
	f, errWt := os.Open(constants.WeightsFile)

	if errWt != nil {
		logrus.Info(errWt)
	}

	defer f.Close()

	scannerWt := bufio.NewScanner(f)
	scannerWt.Split(bufio.ScanWords)

	weights := []float64{}

	for scannerWt.Scan() {
		if s, errWt := strconv.ParseFloat(scannerWt.Text(), 32); errWt == nil {
			weights = append(weights, s)
		}
	}

	// Intercept from logistic regression
	f, errIntercept := os.Open(constants.InterceptFile)

	if errIntercept != nil {
		logrus.Info(errIntercept)
	}

	defer f.Close()

	scannerIntercept := bufio.NewScanner(f)
	scannerIntercept.Split(bufio.ScanWords)

	intercept := []float64{}

	for scannerIntercept.Scan() {
		if s, errIntercept := strconv.ParseFloat(scannerIntercept.Text(), 32); errIntercept == nil {
			intercept = append(intercept, s)
		}
	}

	// Means from standard scaling
	f, errMean := os.Open(constants.MeansFile)

	if errMean != nil {
		logrus.Info(errMean)
	}

	defer f.Close()

	scannerMean := bufio.NewScanner(f)
	scannerMean.Split(bufio.ScanWords)

	meanArrOffline := []float64{}

	for scannerMean.Scan() {
		if s, errMean := strconv.ParseFloat(scannerMean.Text(), 32); errMean == nil {
			meanArrOffline = append(meanArrOffline, s)
		}
	}

	// Standard deviation from standard scaling
	f, errStd := os.Open(constants.StdFile)

	if errStd != nil {
		logrus.Info(errStd)
	}

	defer f.Close()

	scannerStd := bufio.NewScanner(f)
	scannerStd.Split(bufio.ScanWords)

	stdArrOffline := []float64{}

	for scannerStd.Scan() {
		if s, errStd := strconv.ParseFloat(scannerStd.Text(), 32); errStd == nil {
			stdArrOffline = append(stdArrOffline, s)
		}
	}

	return weights, intercept[0], meanArrOffline, stdArrOffline
}
