# Flowmeter
The essence of Deepfence flowmeter is to use shallow packet inspection and parameters like [network five tuple (source IP, source port, protocol, destination IP, destination port)](https://www.networkworld.com/article/2179975/what-is-a-next-generation-firewall-.html#:~:text=The%20%225%2Dtuple%22%20means,and%20destination%20port%2C%20and%20protocol.&text=For%20example%2C%20to%20allow%20traffic%20to%20a%20Web%20server%20at%201.2.), statistics of packet sizes, flow length, inter-arrival time of packets, flow duration and throughput in conjunction with ML to classify packets.

We use a careful chosen combination of performance metrics to assess the efficacy of the ML model.

Following are the major aims of Deepfence Flowmeter:

 - **Classify incoming packets and flows as benign or malicious with high true positives (TP) and low false positives (FP)**. Here, positives are malicious data, and negatives are benign data.

 - **Use the labeled data to reduce traffic sent to console**. The traffic that is sent to console for deeper analysis is a combination of TP and FP. We would like reduce the data sent to console. In a real world scenario, we expect malicious data to be a very small. We want TP+FP to be a small proportion of total data.

Additionally, Deepfence Flowmeter also categorizes packets into flows and shows a very rich ensemble of flow data and statistics.

# Datasets:
We use a big combination of malicious and benign datasets. In malicious datasets, we use a diverse combination of malicious datasets which include T-Pots, Metasploit, Skipfish, Webgoat, honeypots, botnets and ransomware.

Following are the major sources of our datasets.

 - **Benign:**

    - [Canadian Institute of Cybersecurity](https://www.unb.ca/cic/datasets/)

    - [Stratosphere Lab](https://www.stratosphereips.org/datasets-overview)

    - Apache bench

 - **Malicious:**

    - [Honeypots (T-pot)](https://awesomeopensource.com/project/telekom-security/tpotce)

    - [Various kinds of honeypots + botnets  (Canadian Institute of Cybersecurity)](https://www.unb.ca/cic/datasets/)

    - [Various kinds of honeypots + botnets (Stratosphere Lab)](https://www.stratosphereips.org/datasets-overview)

    - [OWASP Webgoat](https://owasp.org/www-project-webgoat/)

All combined, we have an immense (660+ GB) of packet capture files. These can be found in an iDrive account with the following credentials:


**Username / Email:** siddharthsatpathy.ss@gmail.com
**Password:** Deepfence1#

# Network flow:
A network flow is defined as a collection of packets which share the same [source IP, source port, protocol, destination IP, destination port](https://www.networkworld.com/article/2179975/what-is-a-next-generation-firewall-.html#:~:text=The%20%225%2Dtuple%22%20means,and%20destination%20port%2C%20and%20protocol.&text=For%20example%2C%20to%20allow%20traffic%20to%20a%20Web%20server%20at%201.2). Deepfence flowmeter classifies flows as benign or malicious. At the same time, it is also capable of classifying packets all by itself also.

We assign directionality to the flow of traffic by having a look at source and destination IPs and ports.

At the present time, we require a minimum number of packets to be present in a flow before classify it.

# Data analysis and choice of features:
We carefully analyze above-mentioned data to find important features which can robustly differentiate between malicious and benign flows. From a meticulous and methodical analysis, we decide on the use of the following differentiating features for our ML model.

Following are the metrics that we chose:

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

Following are a few visual examples of the how these metrics help us differentiate between benign and malicious traffic.

| <img width="456" alt="Screen Shot 2021-08-17 at 7 13 56 PM" src="https://user-images.githubusercontent.com/26308648/159632278-db80c802-5415-425d-ac34-f67a14322656.png"> |
|:--:|
| *Profiles of forward inter-arrival time mean shows clear distinction between benign and malicious flow data.* |


| <img width="466" alt="Screen Shot 2021-08-17 at 7 14 28 PM" src="https://user-images.githubusercontent.com/26308648/159633264-66f9fa32-bd54-48dc-ba59-18f752216a73.png"> |
|:--:|
| *Profiles of packet size maximum shows clear distinction between benign and malicious flow data.* |


| <img width="457" alt="Screen Shot 2021-08-17 at 7 14 18 PM" src="https://user-images.githubusercontent.com/26308648/159633460-561129f3-1ac8-49ab-89b4-104790134e06.png"> |
|:--:|
| *Profiles of forward packet size maximum shows clear distinction between benign and malicious flow data.* |


| <img width="448" alt="Screen Shot 2021-08-17 at 7 14 07 PM" src="https://user-images.githubusercontent.com/26308648/159633613-e1d9b7a4-13cd-494f-b565-7c81c27b625d.png"> |
|:--:|
| *Profiles of backward packet size mean shows clear distinction between benign and malicious flow data.* |


# Architecture:
In a real world scenario, one will expect about 0.5 percent of malicious packets in network traffic. As such, we want our ML model to be trained on an inherently imbalanced dataset and make predictions on the same.

We train our ML model on benign data and chosen combinations of malicious data of different types. We will want an actual deployed model to use as less memory and CPU as possible with fast run time and good detection efficacies. Hence, we choose an architecture where, we train our ML model offline using the aforementioned datasets.

Given the fact that we have class imbalance between benign and malicious packets in our model, we expect wanted to choose a ML technique which takes care of class imbalance in datasets in training and prediction. After experimentation with a variety of relevant ML methods, we chose to use [weighted logistic regression](https://towardsdatascience.com/weighted-logistic-regression-for-imbalanced-dataset-9a5cd88e68b) as our ML method of choice. Weighted logistic regression offers huge benefits in efficacy metrics and performance as compared to its peers.

From the [offline ML code](https://github.com/deepfence/deepfence_flowmeter/blob/main/Deepfence_ML_flowmeter.ipynb), we get weights, scaling parameters as a bunch of numbers in text files. We use these numbers and [our own Go based implementation of weighted logistic regression to collect packets](https://github.com/deepfence/deepfence_flowmeter/blob/main/flowmeter.go), coalesce them into flows, build relevant features and derived feature statistics and then classify these as benign or malicious.

# How to run:
One can get Deepfence-flowmeter code from this GitHub link.

```
>> git clone https://github.com/deepfence/deepfence_flowmeter.git
>> cd deepfence_flowmeter
>> go build flowmeter.go
>> ./flowmeter False tpot_143_198_72_237_honeypot_v1 100000 True
```

Following is an example output of the code. In addition to classification of data (benign / malicious), we see rich flow statistics in our data.

| <img width="758" alt="Screen Shot 2021-08-17 at 7 27 06 PM" src="https://user-images.githubusercontent.com/26308648/159634141-3f24394b-fec6-47f1-ac96-8c439f39899e.png"> |
|:--:|
| *Example output of the code.* |




