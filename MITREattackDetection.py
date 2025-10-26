"""
MITREattackDetection.py

Purpose:
    - Parse a PCAP file, extract simple network indicators (IPs, ports, protocols,
      short payload snippets), and attempt to map those indicators to MITRE ATT&CK
      Enterprise techniques by keyword matching against the ATT&CK JSON.
    - After matching, scan the PCAP again (optionally in streaming mode) and write
      per-packet detection logs (human-readable and/or JSONL) describing exactly
      which packets caused the detection.

Main features:
    - load_mitre_database(): download or read cached MITRE ATT&CK Enterprise JSON
    - parse_pcap(): extract high-level features (IPs, ports, protocols, payload snippets)
    - match_to_mitre(): simple substring token matching to find relevant techniques
    - find_detections_in_pcap(): locate packets that contain matched keywords and
      produce logs (supports streaming via PcapReader)
    - CLI flags for logging, JSONL output, streaming mode, and limiting packets

Notes and limitations:
    - Matching is substring-based and may produce false positives. For production,
      consider fuzzy matching, weighting, or additional heuristics.
    - Streaming mode uses scapy.PcapReader and processes packets one-by-one (lower memory).
    - Requires scapy and requests to be installed in the Python environment.
"""

from scapy.all import (
    rdpcap,
    PcapReader,
    IP,
    TCP,
    UDP,
    ICMP,
    conf
)
import requests
import json
import re
from collections import Counter
from pathlib import Path
from datetime import datetime
import argparse
import os
from typing import List, Dict, Any, Optional

# Constants
MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
CACHE_FILE = "enterprise-attack.json"
# small curated mapping of well-known ports to the most-likely MITRE technique.
# You can extend this mapping as you like. Keys are strings (port numbers).
# Values are tuples: (preferred_technique_id, preferred_technique_name)
KNOWN_PORTS = {
    "53": ("T1071.004", "Application Layer Protocol: DNS"),         # DNS over UDP/TCP
    "80": ("T1071.001", "Application Layer Protocol: Web Protocols"), # HTTP
    "443": ("T1071.001", "Application Layer Protocol: Web Protocols"),# HTTPS
    "22": ("T1021.002", "Remote Services: SSH"),                    # SSH remote service
    "21": ("T1021.001", "Remote Services: FTP"),                    # FTP remote service
    "25": ("T1048.002", "Exfiltration Over Alternative Protocol: SMTP"), # SMTP-related
    # add more as you see fit
}

# ---------------------------
# MITRE loader & helpers
# ---------------------------
def load_mitre_database(cache_file: str = CACHE_FILE, url: str = MITRE_ENTERPRISE_URL) -> List[Dict[str, Any]]:
    """
    Load MITRE ATT&CK Enterprise JSON.

    - Uses local cache file if present.
    - Otherwise downloads the JSON from the GitHub raw URL and writes to cache_file.

    Returns:
        - List of technique objects where 'type' == 'attack-pattern'.
    """
    if Path(cache_file).exists():
        print(f"[i] Using cached MITRE ATT&CK database: {cache_file}")
        data = json.load(open(cache_file, "r", encoding="utf-8"))
    else:
        print(f"[i] Downloading MITRE ATT&CK database from {url} ...")
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(cache_file, "wb") as f:
            f.write(r.content)
        data = r.json()

    objects = data.get("objects", []) if isinstance(data, dict) else []
    techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"]
    print(f"[+] Loaded {len(techniques)} MITRE techniques")
    return techniques


def normalize(s: Optional[str]) -> str:
    """
    Normalize text for matching: lower-case, collapse whitespace, strip.
    """
    if not s:
        return ""
    return re.sub(r"\s+", " ", s.lower()).strip()


# ---------------------------
# PCAP parsing & feature extraction
# ---------------------------
def parse_pcap(file_path: str, stream: bool = False, max_packets: Optional[int] = None) -> Dict[str, Any]:
    """
    Parse a pcap and extract features used for MITRE matching.

    Args:
        file_path: path to pcap file.
        stream: if True, use PcapReader (streaming) which uses minimal memory.
        max_packets: optionally stop after this many packets (useful for testing).

    Returns:
        features dict with keys: src_ips, dst_ips, tcp_ports, udp_ports, protocols, payload_snippets.
    """
    print(f"[i] Parsing PCAP file: {file_path} (stream={stream})")

    # Choose reader
    if stream:
        reader = PcapReader(file_path)
        packet_iter = iter(reader)
    else:
        packets = rdpcap(file_path)
        packet_iter = iter(packets)

    src_ips, dst_ips = [], []
    tcp_ports, udp_ports = [], []
    protocols = Counter()
    payload_snippets = []

    for idx, packet in enumerate(packet_iter):
        if max_packets is not None and idx >= max_packets:
            break

        if IP in packet:
            try:
                src_ips.append(packet[IP].src)
                dst_ips.append(packet[IP].dst)
            except Exception:
                # If IP fields are malformed skip them
                pass

            # map protocol number to name when possible
            try:
                proto_num = int(packet[IP].proto)
                if proto_num == 6:
                    protocols["TCP"] += 1
                elif proto_num == 17:
                    protocols["UDP"] += 1
                elif proto_num == 1:
                    protocols["ICMP"] += 1
                else:
                    protocols[str(proto_num)] += 1
            except Exception:
                protocols["unknown"] += 1

        # Transport-layer ports (destination ports are taken as observables)
        if TCP in packet:
            try:
                tcp_ports.append(int(packet[TCP].dport))
            except Exception:
                pass
        elif UDP in packet:
            try:
                udp_ports.append(int(packet[UDP].dport))
            except Exception:
                pass

        # Extract printable payload snippets (ASCII-range runs)
        try:
            raw = bytes(packet.payload)
            printable = re.findall(rb"[ -~]{4,}", raw)  # >=4 printable bytes
            for match in printable:
                text = match.decode("utf-8", errors="ignore")
                # Keep shortish snippets to avoid huge blobs
                if 4 <= len(text) <= 300:
                    payload_snippets.append(text.lower())
        except Exception:
            # no payload or un-decodable content
            pass

    # If using PcapReader, close file handle
    if stream:
        try:
            reader.close()
        except Exception:
            pass

    features = {
        "src_ips": sorted(list(set(src_ips))),
        "dst_ips": sorted(list(set(dst_ips))),
        "tcp_ports": sorted(list(set(tcp_ports))),
        "udp_ports": sorted(list(set(udp_ports))),
        "protocols": protocols,
        "payload_snippets": payload_snippets[:200],  # cap stored snippets
    }

    total_packets = "streamed (unknown total)" if stream else idx + 1
    print(f"[+] Parsed {total_packets} packets (collected {len(features['payload_snippets'])} payload snippets)")
    print(f"[+] Found {len(features['src_ips'])} unique src IPs, {len(features['dst_ips'])} dst IPs")
    print(f"[+] Protocols observed: {list(features['protocols'].keys())}")
    return features


# ---------------------------
# MITRE matching
# ---------------------------
def match_to_mitre(features: Dict[str, Any], techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Smarter matching that is aware of keyword types (port/protocol/payload/ip)
    and prefers curated KNOWN_PORTS mappings for well-known ports.

    Returns matches in the same format:
      - technique_name, technique_id, keyword, keyword_type
    """
    print("[i] Mapping extracted indicators to MITRE ATT&CK (port-aware)...")

    # Build searchable blobs for techniques (name + description + data_sources)
    mitre_features = []
    for tech in techniques:
        name = normalize(tech.get("name"))
        description = normalize(tech.get("description"))
        data_sources = normalize(" ".join(tech.get("x_mitre_data_sources", []) or []))
        full_text = f"{name} {description} {data_sources}"
        mitre_features.append({"technique": tech, "name": name, "text": full_text})

    # Build keywords with types
    keywords = set()
    kw_types = {}  # kw -> type: 'port','protocol','payload','ip'
    # protocols
    for proto in features.get("protocols", {}).keys():
        kw = str(proto).lower()
        keywords.add(kw)
        kw_types[kw] = "protocol"
    # ports
    for port in features.get("tcp_ports", []) + features.get("udp_ports", []):
        kw = str(port)
        keywords.add(kw)
        kw_types[kw] = "port"
    # payload tokens
    for snippet in features.get("payload_snippets", []):
        for tok in re.findall(r"[a-zA-Z0-9_\-\.]{2,}", snippet):
            kw = tok.lower()
            keywords.add(kw)
            # payload keywords should take precedence if same token also appears as ip/port/proto
            if kw not in kw_types:
                kw_types[kw] = "payload"
    # ips
    for ip in features.get("src_ips", []) + features.get("dst_ips", []):
        kw = ip
        keywords.add(kw)
        kw_types[kw] = "ip"

    matches = []
    used_techniques = set()  # store (technique_id, technique_name) to prevent duplicate entries

    # First handle known-port direct mappings to avoid broad matches
    for kw in list(keywords):
        ktype = kw_types.get(kw)
        if ktype == "port" and kw in KNOWN_PORTS:
            pref_id, pref_name = KNOWN_PORTS[kw]
            # create match entry directly (don't search entire MITRE text)
            m = {
                "technique_name": pref_name,
                "technique_id": pref_id,
                "keyword": kw,
                "keyword_type": "port"
            }
            key = (m["technique_id"], m["technique_name"])
            if key not in used_techniques:
                matches.append(m)
                used_techniques.add(key)
            # Remove this port from further generic matching to prevent duplicates
            keywords.discard(kw)

    # For remaining keywords, apply type-aware matching rules
    for entry in mitre_features:
        tech = entry["technique"]
        name = entry["name"]
        text = entry["text"]
        ext_refs = tech.get("external_references", []) or []
        ext_id = ""
        if ext_refs and isinstance(ext_refs, list):
            ext_id = ext_refs[0].get("external_id", "") or ""

        for kw in list(keywords):
            if not kw:
                continue
            ktype = kw_types.get(kw, "payload")

            # PORT: less permissive matching for ports not in KNOWN_PORTS:
            # only match if the port appears in the technique *name* (strong signal)
            if ktype == "port":
                if kw in name:
                    m = {
                        "technique_name": tech.get("name"),
                        "technique_id": ext_id,
                        "keyword": kw,
                        "keyword_type": "port"
                    }
                    key = (m["technique_id"], m["technique_name"])
                    if key not in used_techniques:
                        matches.append(m)
                        used_techniques.add(key)
                # do not search description for generic port numbers to avoid noise
                continue

            # PAYLOAD: high-signal — require keyword in full text
            if ktype == "payload":
                if kw in text:
                    m = {
                        "technique_name": tech.get("name"),
                        "technique_id": ext_id,
                        "keyword": kw,
                        "keyword_type": "payload"
                    }
                    key = (m["technique_id"], m["technique_name"])
                    if key not in used_techniques:
                        matches.append(m)
                        used_techniques.add(key)
                continue

            # PROTOCOL or IP: match anywhere in full_text (name+description)
            if ktype in ("protocol", "ip"):
                if kw in text:
                    m = {
                        "technique_name": tech.get("name"),
                        "technique_id": ext_id,
                        "keyword": kw,
                        "keyword_type": ktype
                    }
                    key = (m["technique_id"], m["technique_name"])
                    if key not in used_techniques:
                        matches.append(m)
                        used_techniques.add(key)
                continue

    # Final: short printout and return
    print(f"[+] Found {len(matches)} prioritized MITRE ATT&CK matches (after port-aware filtering)")
    for m in matches[:20]:
        print(f"  - {m.get('technique_id','?')} {m.get('technique_name')} (kw={m.get('keyword')} type={m.get('keyword_type')})")

    return matches

# ---------------------------
# Packet-level detection & logging
# ---------------------------
def find_detections_in_pcap(
    pcap_file: str,
    matches: List[Dict[str, Any]],
    log_path: Optional[str] = None,
    jsonl_path: Optional[str] = None,
    stream: bool = False,
    max_packets: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Scan the PCAP and produce per-packet detections.

    Args:
        pcap_file: path to pcap file.
        matches: list of match dicts (from match_to_mitre) containing at least 'keyword',
                 'technique_name', 'technique_id'.
        log_path: optional path to write human-readable log (text).
        jsonl_path: optional path to write detections as JSONL (one JSON object per line).
        stream: if True use PcapReader for streaming iteration.
        max_packets: optional limit on the number of packets to scan.

    Returns:
        List of detection dicts. Each detection includes:
            packet_index, timestamp_iso, src_ip, dst_ip, src_port, dst_port, protocol,
            payload_snippet, keyword, technique_name, technique_id
    """
    # Build keyword -> list of technique mappings for quick lookup
    kw_map: Dict[str, List[Dict[str, Any]]] = {}
    for m in matches:
        kw = (m.get("keyword") or "").lower()
        if not kw:
            continue
        kw_map.setdefault(kw, []).append({
            "technique_name": m.get("technique_name"),
            "technique_id": m.get("technique_id")
        })

    # Choose the appropriate packet iterator (streaming or full load)
    if stream:
        pkt_iter = PcapReader(pcap_file)
    else:
        pkts = rdpcap(pcap_file)
        pkt_iter = iter(pkts)

    detections: List[Dict[str, Any]] = []

    def _payload_text(pkt) -> str:
        """
        Return a short printable payload snippet (lowercased), or empty string.
        """
        try:
            raw = bytes(pkt.payload)
            parts = re.findall(rb"[ -~]{4,}", raw)  # printable runs
            if parts:
                txt = parts[0].decode("utf-8", errors="ignore")
                return txt.lower()[:400]
        except Exception:
            pass
        return ""

    for idx, pkt in enumerate(pkt_iter):
        if max_packets is not None and idx >= max_packets:
            break

        # timestamp (UTC ISO)
        ts = getattr(pkt, "time", None)
        ts_iso = None
        if ts:
            try:
                ts_iso = datetime.utcfromtimestamp(float(ts)).isoformat() + "Z"
            except Exception:
                ts_iso = None

        # network fields
        src_ip = pkt[IP].src if IP in pkt else ""
        dst_ip = pkt[IP].dst if IP in pkt else ""
        proto = None
        if IP in pkt:
            try:
                pnum = int(pkt[IP].proto)
                proto = "TCP" if pnum == 6 else "UDP" if pnum == 17 else "ICMP" if pnum == 1 else str(pnum)
            except Exception:
                proto = "unknown"

        src_port = None
        dst_port = None
        if TCP in pkt:
            try:
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
            except Exception:
                pass
        elif UDP in pkt:
            try:
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
            except Exception:
                pass

        payload = _payload_text(pkt)

        # Build searchable candidates for keyword matching
        candidates = set()
        if src_ip: candidates.add(src_ip.lower())
        if dst_ip: candidates.add(dst_ip.lower())
        if proto: candidates.add(str(proto).lower())
        if src_port: candidates.add(str(src_port))
        if dst_port: candidates.add(str(dst_port))
        if payload: candidates.add(payload)

        # For each keyword, check if it appears in any candidate
        for kw, techs in kw_map.items():
            matched = False
            for c in candidates:
                if kw in c:
                    matched = True
                    break
            if not matched:
                continue

            # Record detection(s) for all techniques mapped to this keyword
            for t in techs:
                det = {
                    "packet_index": idx,
                    "timestamp_iso": ts_iso,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "payload_snippet": payload,
                    "keyword": kw,
                    "technique_name": t.get("technique_name"),
                    "technique_id": t.get("technique_id"),
                }
                detections.append(det)

    # close reader if streaming
    if stream:
        try:
            pkt_iter.close()
        except Exception:
            pass

    # Write human-readable log if requested
    if log_path:
        try:
            with open(log_path, "w", encoding="utf-8") as outf:
                for d in detections:
                    outf.write(
                        f"[{d['timestamp_iso']}] pkt#{d['packet_index']} "
                        f"{d['src_ip']}:{d.get('src_port','?')} -> {d['dst_ip']}:{d.get('dst_port','?')} "
                        f"proto={d['protocol']} match={d['technique_id']} {d['technique_name']} (kw='{d['keyword']}')\n"
                    )
            print(f"[+] Wrote human-readable log to: {log_path}")
        except Exception as e:
            print(f"[!] Failed to write log file {log_path}: {e}")

    # Write JSONL if requested (one JSON object per line)
    if jsonl_path:
        try:
            with open(jsonl_path, "w", encoding="utf-8") as jout:
                for d in detections:
                    jout.write(json.dumps(d) + "\n")
            print(f"[+] Wrote JSONL detections to: {jsonl_path}")
        except Exception as e:
            print(f"[!] Failed to write jsonl file {jsonl_path}: {e}")

    return detections


# ---------------------------
# CLI & main flow
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK network detection from PCAP")
    parser.add_argument("pcap", help="Path to input pcap file")
    parser.add_argument("--log", help="Human-readable detection log output file (optional)", default=None)
    parser.add_argument("--jsonl", help="JSONL detection output file (optional)", default=None)
    parser.add_argument("--stream", help="Stream pcap instead of loading fully (use PcapReader)", action="store_true")
    parser.add_argument("--max-packets", help="Max packets to process (for testing)", type=int, default=None)
    parser.add_argument("--cache", help="MITRE cache filename", default=CACHE_FILE)
    args = parser.parse_args()

    # Quick environment hint: warn if scapy lacks a pcap provider (user saw this earlier)
    try:
        if not conf.use_pcap:
            print("[!] Warning: Scapy does not have a libpcap/Npcap provider available. Some features (live capture/filters) may not work.")
    except Exception:
        pass

    pcap_file = args.pcap
    if not os.path.exists(pcap_file):
        print(f"[!] PCAP file not found: {pcap_file}")
        return

    # Load MITRE techniques
    techniques = load_mitre_database(cache_file=args.cache)

    # Step 1: extract features from pcap (brief scan)
    features = parse_pcap(pcap_file, stream=args.stream, max_packets=args.max_packets)

    # step 2 match
    matches = match_to_mitre(features, techniques)
    if not matches:
        print("[i] No MITRE matches found from feature scan. Exiting (no packet-level scan performed).")
        return

    # --- De-duplicate matches by keyword to prevent same packet triggering many techniques ---
    deduped_matches = {}
    for m in matches:
        kw = m["keyword"]
        name = (m.get("technique_name") or "").lower()
        if kw not in deduped_matches:
            deduped_matches[kw] = m
        else:
            current = deduped_matches[kw]
            for word in ("dns", "http", "https", "ssh", "ftp", "smtp", "powershell", "c2"):
                if word in name and word not in current.get("technique_name", "").lower():
                    deduped_matches[kw] = m
                    break
    matches = list(deduped_matches.values())
    print(f"[i] De-duplicated to {len(matches)} unique keyword→technique mappings")

    # Step 3: packet-level detection & logging
    detections = find_detections_in_pcap(
        pcap_file,
        matches,

        log_path=args.log,
        jsonl_path=args.jsonl,
        stream=args.stream,
        max_packets=args.max_packets
    )

    # Summary output
    print(f"[+] Total detections recorded: {len(detections)}")
    if detections:
        print("[+] Sample detections (up to 10):")
        for d in detections[:50]:
            print(f"  pkt#{d['packet_index']} {d['src_ip']}->{d['dst_ip']} matched {d['technique_name']} (kw={d['keyword']})")


if __name__ == "__main__":
    main()
