from scapy.all import sniff, send, IP, UDP, Raw, conf
import threading
import time

def detect_ip_fragmentation(packet):
    if IP in packet:
        ip = packet[IP]
        if ip.flags == 1 or ip.frag > 0:
            print(f"Fragmented packet detected: {ip.summary()}")
            print(f"Details: {packet.show(dump=True)}")

def packet_callback(packet):
    print(f"Packet captured: {packet.summary()}")
    detect_ip_fragmentation(packet)

def start_packet_capture(interface, stop_event):
    print(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda p: stop_event.is_set())

def emulate_ip_fragmentation_attack(target_ip, packet_count=10):
    for i in range(packet_count):
        fragment1 = IP(dst=target_ip, id=42, flags='MF', frag=0)/UDP(dport=12345, sport=54321)/Raw(load="X"*8)
        fragment2 = IP(dst=target_ip, id=42, frag=1)/Raw(load="Y"*8)
        send(fragment1)
        send(fragment2)
        print(f"Sent fragment1: {fragment1.summary()}")
        print(f"Sent fragment2: {fragment2.summary()}")
        print(f"Details fragment1: {fragment1.show(dump=True)}")
        print(f"Details fragment2: {fragment2.show(dump=True)}")
        time.sleep(1)  # Adding a delay to observe the packets properly

def main(interface, target_ip, packet_count):
    stop_event = threading.Event()
    # Start packet capture in a separate thread
    capture_thread = threading.Thread(target=start_packet_capture, args=(interface, stop_event))
    capture_thread.start()

    try:
        # Wait for a moment to ensure capture is running
        time.sleep(5)

        # Start emulation of IP fragmentation attack
        emulate_ip_fragmentation_attack(target_ip, packet_count)

        # Wait for a while to ensure all packets are captured
        time.sleep(10)
    except KeyboardInterrupt:
        print("Stopping packet capture...")
    finally:
        stop_event.set()
        capture_thread.join()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network Anomaly Detection")
    parser.add_argument('--interface', type=str, default="Беспроводная сеть", help="Network interface for packet capture")
    parser.add_argument('--emulate', type=str, help="Target IP for emulating IP fragmentation attack")
    parser.add_argument('--count', type=int, default=10, help="Number of packets to send in emulation")

    args = parser.parse_args()

    if args.emulate:
        main(args.interface, args.emulate, args.count)
    else:
        stop_event = threading.Event()
        try:
            start_packet_capture(args.interface, stop_event)
        except KeyboardInterrupt:
            stop_event.set()
