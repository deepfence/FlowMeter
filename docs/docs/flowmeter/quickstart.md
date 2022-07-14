---
title: Build and Run
---

# Quick Start

## Overview

FlowMeter observes packets, obtains a rich set of features from them, constructs flows and generates output csv files for these flows.

Using these output csv files, an ML model can be trained to classify packets as benign or malicious.

Finallty, weights obtained from the trained ML models can be fed into FlowMeter, which can then be used to classify packets as malicious or benign.


## Build FlowMeter

Build FlowMeter from source using the golang toolchain.

```
git clone https://github.com/deepfence/FlowMeter.git
cd FlowMeter/pkg

# Install libpcap package.
# Ubuntu/Debian:  sudo apt-get install libpcap0.8-dev
# RHEL/Centos:    sudo yum install install libpcap-devel

go build -o flowmeter .
```

## Obtain Sample Training Data

```
# Download pcap files.
mkdir packets

wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/webgoat.pcap -P packets
wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/benign_2017-05-02_kali-normal22.pcap -P packets

# Generate CSVs for flows
./flowmeter -ifLiveCapture=false -fname=webgoat -maxNumPackets=40000000 -ifLocalIPKnown false
./flowmeter -ifLiveCapture=false -fname=benign_2017-05-02_kali-normal22 -maxNumPackets=40000000 -ifLocalIPKnown false
```

## Generate ML parameters and classify packets:

```
cd FlowMeter/assets

python Deepfence_ML_flowmeter.py

cd ../pkg/

./flowmeter -ifLiveCapture=false -fname=webgoat -maxNumPackets=40000000 -ifLocalIPKnown false
./flowmeter -ifLiveCapture=false -fname=benign_2017-05-02_kali-normal22 -maxNumPackets=40000000 -ifLocalIPKnown false
```

## Sample Results

FlowMeter gives a rich set of features about flows from packet data, and classifies packets as benign or malicious.

| ![FlowMeter Results](img/flowmeter-results-anim.gif) |
| :--: |
| *FlowMeter takes packets and returns file with statistics of flows.* |


