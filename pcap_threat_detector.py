from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
from network_utils import is_unencrypted_port, format_alert

def analyze_pcap(pcap_file):
    print(f"=== ANALYZING PCAP FILE: {pcap_file} ===")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[ERROR] Could not read PCAP file: {e}")
        return

    syn_counter = defaultdict(int)
    detected_threats = 0

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src_ip, dst_ip, dport = pkt[IP].src, pkt[IP].dst, pkt[TCP].dport

            # Check for plaintext protocols
            is_unencrypted, protocol = is_unencrypted_port(dport)
            if is_unencrypted:
                print(format_alert("Unencrypted Traffic", f"{src_ip} -> {dst_ip} via {protocol} (Port {dport})"))
                detected_threats += 1

            # Track SYN flags
            if pkt[TCP].flags == 'S':
                syn_counter[src_ip] += 1

    # Check SYN scan threshold
    for ip, count in syn_counter.items():
        if count > 20:
            print(format_alert("Potential SYN Scan / Flood", f"Source IP: {ip} sent {count} SYN packets"))
            detected_threats += 1

    print(f"\n--- Analysis Complete. Total Security Alerts: {detected_threats} ---")

if __name__ == "__main__":
    print("PCAP Threat Detector initialized. Ready for packet inspection.")
