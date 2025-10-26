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




---

## 🧠 Lessons Learned

Building **MITREattackDetection** was more than just a coding exercise — it was a hands-on lesson in the complexity of real-world cybersecurity automation.  
Here’s what I learned along the way 👇

---

### 1. Parsing PCAPs isn’t as simple as it looks
- Scapy makes it easy to read packets, but **real PCAPs contain malformed or truncated data** that can break parsing.  
- Large captures can overwhelm memory when using `rdpcap()`.  

**What I learned:** Use `PcapReader()` for large files and handle exceptions gracefully when parsing unusual protocols.

---

### 2. Keyword-based detection creates noise
- My first approach matched *any* extracted keyword (like `"53"` or `"http"`) to MITRE techniques.  
- This caused **massive over-detection** — one packet could trigger 10+ techniques.

**Fix:** Implemented **port-aware mapping and de-duplication**, linking known ports (e.g., 53 → DNS) directly to the right technique.  
**Lesson:** Automated detection must balance **precision vs. recall** — context matters as much as coverage.

---

### 3. Data normalization is essential
- The MITRE ATT&CK dataset contains inconsistent fields, mixed cases, and missing attributes.  
- Early matching attempts failed due to uncleaned strings and extra whitespace.

**Fix:** Added a normalization layer to lowercase and sanitize text before matching.  
**Lesson:** Threat data must be cleaned and structured before it becomes useful.

---

### 4. Local caching improves reliability
- Constantly fetching the MITRE JSON caused slow starts and dependency on internet access.

**Fix:** Cached `enterprise-attack.json` locally and reused it between runs.  
**Lesson:** Always design for **offline operation** in defensive tools.

---

### 5. Building the executable revealed real-world deployment issues
- PyInstaller packaging introduced missing imports and dependency surprises.  
- Antivirus software flagged the unsigned `.exe` as suspicious.  
- Missing Npcap caused “No libpcap provider” warnings on Windows.

**Lesson:** Deploying cybersecurity tools is as challenging as writing them — always test on clean systems, include dependency checks, and consider code-signing.

---

### 6. Context > Automation
- The script successfully identifies potential MITRE techniques, but **not every match is meaningful**.
- Detections lack behavioral context (sequence, timing, or flow correlation).

**Lesson:** Automated tools should **assist analysts, not replace them** — human validation is still key.

---

### 7. Future Improvements
- Add regex and fuzzy matching for payloads instead of simple substrings.  
- Implement scoring or confidence levels for each detection.  
- Use behavioral correlation (multiple packets over time) to reduce false positives.  
- Integrate visual dashboards for interactive analysis.  
- Include unit tests and CI/CD checks for data parsing stability.

---

## ⚠️ Known Issues & Limitations

| Category | Description | Impact |
|-----------|--------------|--------|
| **Over-detection** | Common keywords (e.g., "53", "80", "get") appear in multiple MITRE techniques | Can cause multiple detections for the same event |
| **Static MITRE version** | Uses one snapshot of the ATT&CK database | May miss new or updated techniques until refreshed |
| **Memory usage** | `rdpcap()` loads entire PCAPs into memory | May fail on very large captures |
| **Limited context** | Each packet is analyzed in isolation | No session or multi-packet correlation |
| **No confidence scoring** | All detections have equal weight | Analyst must manually prioritize results |
| **Payload-only text analysis** | Binary or encoded payloads not decoded | Misses some obfuscated activity |
| **Npcap/libpcap dependency** | Missing capture backend causes warnings | PCAP parsing still works, but live capture disabled |
| **Unsigned executable** | PyInstaller `.exe` may trigger antivirus false positives | Requires user trust or signing certificate |

---

### 🔑 Key Takeaway
> **This project taught me that detection engineering is not just about code — it’s about context, data quality, and reliability.**  
> Every false positive or failed parse led to a better understanding of how real-world cybersecurity tools evolve from proof-of-concept to production-ready.

---
