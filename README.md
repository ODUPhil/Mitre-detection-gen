# 🛰️ MITREattackDetection
**Network traffic analysis mapped to MITRE ATT&CK**

MITREattackDetection is a Python-based tool that parses PCAP files, extracts key network indicators, and maps them to MITRE ATT&CK techniques.  
It helps analysts quickly identify potential tactics and techniques from captured network data — for threat hunting, incident response, or research.

---

## 🚀 Features
- Parses `.pcap` files using **Scapy**
- Extracts:
  - Source/Destination IPs  
  - Protocols and Ports  
  - Payload text indicators
- Matches extracted features to **MITRE ATT&CK** techniques via MITRE’s open CTI dataset
- Logs per-packet detections:
  - Technique ID and name  
  - Triggering keyword (e.g. `port 53 → DNS C2`)  
  - Timestamps, IPs, ports, payload snippet
- Supports JSONL + human-readable logs
- Port-aware and de-duplicated detection (prevents noise from multiple technique matches)
- Can be converted to a standalone `.exe` using PyInstaller

---

## 🧰 Installation
```bash
git clone https://github.com/ODUPhil/MITREattackDetection.git
cd MITREattackDetection
pip install -r requirements.txt

---

## 🧭 How to Use

This tool analyzes network captures (`.pcap` files) and automatically maps observed behavior to the [MITRE ATT&CK](https://attack.mitre.org) framework.

You can run it directly in Python

---

### 🪄 Step 1 — Run the Script

Run the tool on a `.pcap` file:

```bash
python MITREattackDetection.py sample.pcap 
