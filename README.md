# Wireshark-PCAP-Threat-Detector ![Status](https://img.shields.io/badge/Status-In_Progress-yellow) ![Version](https://img.shields.io/badge/Version-v0.1_WIP-orange)

# Network Traffic & PCAP Threat Detector

A Python-based network security tool that inspects `.pcap` files (Wireshark packet captures) to detect security threats, unencrypted traffic, and suspicious network anomalies.

## 📌 Features
- **Unencrypted Protocol Detection:** Flags plain-text protocols (HTTP, Telnet, FTP).
- **SYN Flood / Port Scan Detection:** Identifies anomalous connection floods from single source IPs.
- **Automated Summary Reporting:** Generates clean console outputs for security analysis.

## 🛠️ Project Structure
- `pcap_threat_detector.py` - Core packet analysis logic using Scapy.
- `network_utils.py` - Helper functions for protocol mapping and IP validation.
- `test_pcap_analyzer.py` - Unit test suite for verifying detection logic.

## 🚀 How to Run
```bash
pip install scapy
python pcap_threat_detector.py
