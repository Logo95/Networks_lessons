import pandas as pd
from scapy.layers.inet import IP

def analyze_packet(packet):
    if IP in packet:
        return {
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'length': len(packet)
        }
    else:
        return {
            'src': None,
            'dst': None,
            'length': len(packet)
        }

def detect_anomalies(packets_data):
    df = pd.DataFrame(packets_data)
    # Пример простого правила выявления аномалий
    anomalies = df[df['length'] > 1000]
    return anomalies
