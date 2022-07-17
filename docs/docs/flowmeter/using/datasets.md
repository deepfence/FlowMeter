---
title: Datasets
---

# FlowMeter Datasets

FlowMeter uses takes packets as input, derives a rich set of features, constructs flows on the basis of these features and uses machine learning to classify the ensuing flows as malicious or benign. 

FlowMeter can process live packets or can analyze offline packets. 

The tests in the repo used the following sample packet datasets:

### Benign Packets

```bash
wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/benign_2017-05-02_kali-normal22.pcap
```

### Malicious Packets

```bash 
wget https://deepfence-public.s3.amazonaws.com/pcap-datasets/webgoat.pcap
```    

## Other Datasets

Additionally, one can also use sample data from various sources like the datasets mentioned below, or gather packet captures using [PacketStreamer](https://github.com/deepfence/PacketStreamer) or other pcap tools.

 * **Benign:** 
    * [Canadian Institute of Cybersecurity](https://www.unb.ca/cic/datasets/)
    * [Stratosphere Lab](https://www.stratosphereips.org/datasets-overview) 

 * **Malicious:**
    * [Honeypots (T-pot)](https://awesomeopensource.com/project/telekom-security/tpotce)
    * [Various kinds of honeypots + botnets  (Canadian Institute of Cybersecurity)](https://www.unb.ca/cic/datasets/)
    * [Various kinds of honeypots + botnets (Stratosphere Lab)](https://www.stratosphereips.org/datasets-overview) 
    * [OWASP Webgoat](https://owasp.org/www-project-webgoat/)

