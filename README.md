[![GitHub license](https://img.shields.io/github/license/deepfence/FlowMeter)](https://github.com/deepfence/FlowMeter/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/deepfence/FlowMeter)](https://github.com/deepfence/FlowMeter/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/deepfence/FlowMeter)](https://github.com/deepfence/FlowMeter/issues)
[![Slack](https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack)](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ)

# FlowMeter
FlowMeter is an experimental utility built to analyse and classify packets by looking at packet headers. We use FlowMeter internally to quickly analyse and label packets.

## Primary design goals:

Following are the major aims of FlowMeter:

 - **Classify packets and flows as benign or malicious with high true positives (TP) and low false positives (FP)**. 

 - **Use the labeled data to reduce amount of traffic requiring deeper analysis**. 

Additionally, Deepfence FlowMeter also categorizes packets into flows and shows a rich ensemble of flow data and statistics.

| <img width="1559" alt="Flowmeter-flows" src="https://user-images.githubusercontent.com/26308648/165219276-e9c9a99a-1bc1-40c9-bfaa-779b6380ae67.png"> |
|:--:| 
| *FlowMeter takes packets and returns file with statistics of flows.* |


| <img width="1559" alt="Flowmeter-flowsClassification" src="https://user-images.githubusercontent.com/26308648/165219569-42a84939-8c28-4b70-b864-f4980c3ee27d.png">
|:--:|
| *Flowmeter takes packets and returns file with statistics of flows and classifies packets as benign or malicious.*  |


## Datasets:
FlowMeter uses takes packets as input, derives a rich set of features, constructs flows on the basis of these features and uses machine learning to classify the ensuing flows as malicious or benign. 

FlowMeter has provisions to take live packets or analyze offline packets. 

One can download the below-mentioned pcap datasets to replicate the tests shown in this repo. 

 - **Benign:** 
``` 
wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/benign_2017-05-02_kali-normal22.pcap
```

 - **Malicious:**
``` 
wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/webgoat.pcap
```    

Additionally, one can also use sample data from various sources like the datasets mentioned below, or gather packet captures using [PacketStreamer](https://github.com/deepfence/PacketStreamer) or other pcap tools.

 - **Benign:** 
    - [Canadian Institute of Cybersecurity](https://www.unb.ca/cic/datasets/)
    - [Stratosphere Lab](https://www.stratosphereips.org/datasets-overview) 

 - **Malicious:**
    - [Honeypots (T-pot)](https://awesomeopensource.com/project/telekom-security/tpotce)
    - [Various kinds of honeypots + botnets  (Canadian Institute of Cybersecurity)](https://www.unb.ca/cic/datasets/)
    - [Various kinds of honeypots + botnets (Stratosphere Lab)](https://www.stratosphereips.org/datasets-overview) 
    - [OWASP Webgoat](https://owasp.org/www-project-webgoat/)


## Data analysis and choice of features:
FlowMeter obtains the below-mentioned features from packets and constructs flows. Using the said features, FlowMeter can robustly differentiate between malicious and benign flows. 

- **Inter-arrival time**

    - Forward inter-arrival time per microsecond
    - Backward inter-arrival time per microsecond
    - Forward inter-arrival time mean
    - Backward inter-arrival time mean
    - Forward inter-arrival time standard deviation
    - Backward inter-arrival time standard deviation
    - Forward inter-arrival time minimum
    - Backward inter-arrival time minimum
    - Forward inter-arrival time maximum
    - Backward inter-arrival time maximum

- **Packet size**

    - Total (forward + backward) packet size per microsecond
    - Forward packet size per microsecond
    - Backward packet size per microsecond
    - Forward packet size mean
    - Backward packet size mean
    - Forward packet size standard deviation
    - Backward packet size standard deviation
    - Forward packet size minimum
    - Backward packet size minimum
    - Forward packet size maximum
    - Backward packet size maximum

- **Flow length**

    - Total flow length per microsecond
    - Forward flow length per microsecond
    - Backward flow length per microsecond

- **Flow duration**

Following are a few visual examples of how these metrics help us differentiate between benign and malicious traffic.

| <img width="463" alt="fwdPacketSizeMax" src="https://user-images.githubusercontent.com/26308648/165208613-e5116c1e-a991-4d38-b71d-4adbb04a4d23.png"> | 
|:--:| 
| *Profiles of maximum of forward packet sizes shows clear distinction in benign and malicious flow data.* |


| <img width="443" alt="fwdPacketSizeTotal" src="https://user-images.githubusercontent.com/26308648/165208750-e6ec0c4b-dc34-4043-a161-57e53b659822.png"> |
|:--:| 
| *Profiles of maximum of forward flow length shows clear distinction in benign and malicious flow data.* |


| <img width="472" alt="fwdIATMean" src="https://user-images.githubusercontent.com/26308648/165012380-1c61feda-a9e3-4a5f-a6b4-de998882d8b1.png"> |
|:--:| 
| *Profiles of forward inter-arrival time mean shows clear distinction between benign and malicious flow data.* |


| <img width="463" alt="bwdIATMean" src="https://user-images.githubusercontent.com/26308648/165012459-27da8cb9-1564-43ed-9219-edb65dae5162.png"> |
|:--:| 
| *Profiles of backward inter-arrival time mean shows clear distinction between benign and malicious flow data.* |


## Architecture:

FlowMeter observes packets, obtains a rich set of features from them, constructs flows and generates output csv files for these flows.

Using these output csv files, an ML model can be trained to classify packets as benign or malicious.

Weights obtained from the trained ML models can be fed into FlowMeter, which can now be used to classify packets as malicious or benign.


## How to run:
Use the below GitHub link to get FlowMeter.

### Generate csv for flows:

```
git clone https://github.com/deepfence/FlowMeter.git
cd FlowMeter/pkg

# Install libpcap package.
# Ubuntu/Debian:  sudo apt-get install libpcap0.8-dev
# RHEL/Centos:    sudo yum install install libpcap-devel
go build -o flowmeter .

# Download pcap files.
mkdir packets

wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/webgoat.pcap -P packets
wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/benign_2017-05-02_kali-normal22.pcap -P packets

./flowmeter -ifLiveCapture=false -fname=webgoat -maxNumPackets=40000000 -ifLocalIPKnown false
./flowmeter -ifLiveCapture=false -fname=benign_2017-05-02_kali-normal22 -maxNumPackets=40000000 -ifLocalIPKnown false
```

### Generate ML parameters and classify packets:
```
cd FlowMeter/assets

python Deepfence_ML_flowmeter.py

cd ../pkg/

./flowmeter -ifLiveCapture=false -fname=webgoat -maxNumPackets=40000000 -ifLocalIPKnown false
./flowmeter -ifLiveCapture=false -fname=benign_2017-05-02_kali-normal22 -maxNumPackets=40000000 -ifLocalIPKnown false
```

Following is an example output of the code. FlowMeter gives a rich set of features about flows from packet data, and classifies packets as benign or malicious.

![flowmeter](https://user-images.githubusercontent.com/26308648/165217670-fe68e122-efdd-49d8-b491-a60d4a039eab.gif)


## Get in touch

Thank you for using FlowMeter.

* [<img src="https://img.shields.io/badge/slack-@deepfence-brightgreen.svg?logo=slack">](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ) Got a question, need some help?  Find the Deepfence team on Slack
* https://github.com/deepfence/FlowMeter/issues: Got a feature request or found a bug? Raise an issue
* [productsecurity *at* deepfence *dot* io](SECURITY.md): Found a security issue? Share it in confidence
* Find out more at [deepfence.io](https://deepfence.io/)

## Security and Support

For any security-related issues in the FlowMeter project, contact [productsecurity *at* deepfence *dot* io](SECURITY.md).

Please file GitHub issues as needed, and join the Deepfence Community [Slack channel](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ).

## License

The Deepfence FlowMeter project (this repository) is offered under the [Apache2 license](https://www.apache.org/licenses/LICENSE-2.0).

[Contributions](CONTRIBUTING.md) to Deepfence FlowMeter project are similarly accepted under the Apache2 license, as per [GitHub's inbound=outbound policy](https://docs.github.com/en/github/site-policy/github-terms-of-service#6-contributions-under-repository-license).

