from scapy.all import sniff, conf
from analysis import analyze_packet, detect_anomalies

packets_data = []

def packet_callback(packet):
    global packets_data
    packet_info = analyze_packet(packet)
    packets_data.append(packet_info)
    anomalies = detect_anomalies(packets_data)
    if not anomalies.empty:
        print("Anomalies detected:")
        print(anomalies)

def capture_packets():
    conf.L3socket = conf.L3socket()
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    capture_packets()
