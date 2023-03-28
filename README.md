[![Documentation](https://img.shields.io/badge/documentation-read-green)](https://docs.deepfence.io/flowmeter)
[![GitHub license](https://img.shields.io/github/license/deepfence/FlowMeter)](https://github.com/deepfence/FlowMeter/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/deepfence/FlowMeter)](https://github.com/deepfence/FlowMeter/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/deepfence/FlowMeter)](https://github.com/deepfence/FlowMeter/issues)
[![Slack](https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack)](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ)

# FlowMeter
FlowMeter is an experimental utility built for analysing and classifing packets by looking at packet headers. 

## Primary design goals:

FlowMeter aims to:

 - **Classify packets and flows as benign or malicious with high true positives (TP) and low false positives (FP)**. 
 - **Use the labeled data to reduce amount of traffic requiring deeper analysis**. 

Additionally, Deepfence FlowMeter also categorizes packets into flows and shows a rich ensemble of flow data and statistics.

| <img width="1559" alt="Flowmeter-flows" src="https://user-images.githubusercontent.com/26308648/165219276-e9c9a99a-1bc1-40c9-bfaa-779b6380ae67.png"> |
|:--:| 
| *FlowMeter takes packets and returns file with statistics of flows.* |

| <img width="1559" alt="Flowmeter-flowsClassification" src="https://user-images.githubusercontent.com/26308648/165219569-42a84939-8c28-4b70-b864-f4980c3ee27d.png">
|:--:|
| *Flowmeter takes packets and returns file with statistics of flows and classifies packets as benign or malicious.*  |

## When to use FLowMeter

Use FlowMeter if you wish to build and operate machine-learning models on network packet data.

## Quick Start

For full instructions, refer to the [FlowMeter Documentation](https://docs.deepfence.io/flowmeter).

![FlowMeter QuickStart](docs/docs/flowmeter/img/flowmeter.svg)

## Who uses FlowMeter?

 * We use FlowMeter internally to quickly analyse and label packets. It forms one part of a project to build a fast pre-filter for packets before we conduct deeper layer-7 analysis in [Deepfence ThreatMapper](https://deepfence.io/threatmapper/).

## Get in touch

Thank you for using FlowMeter.

 * [<img src="https://img.shields.io/badge/documentation-read-green">](https://docs.deepfence.io/flowmeter) Start with the documentation
 * [<img src="https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack">](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ) Got a question, need some help?  Find the Deepfence team on Slack
 * [![GitHub issues](https://img.shields.io/github/issues/deepfence/FlowMeter)](https://github.com/deepfence/FlowMeter/issues) Got a feature request or found a bug? Raise an issue
 * [productsecurity *at* deepfence *dot* io](SECURITY.md): Found a security issue? Share it in confidence
 * Find out more at [deepfence.io](https://deepfence.io/)

## Security and Support

For any security-related issues in the FlowMeter project, contact [productsecurity *at* deepfence *dot* io](SECURITY.md).

Please file GitHub issues as needed, and join the Deepfence Community [Slack channel](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ).

## License

The Deepfence FlowMeter project (this repository) is offered under the [Apache2 license](https://www.apache.org/licenses/LICENSE-2.0).

[Contributions](CONTRIBUTING.md) to Deepfence FlowMeter project are similarly accepted under the Apache2 license, as per [GitHub's inbound=outbound policy](https://docs.github.com/en/github/site-policy/github-terms-of-service#6-contributions-under-repository-license).

