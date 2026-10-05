from datetime import datetime
import time

from scapy.all import sniff, IP, TCP, UDP, ICMP


def get_protocol(packet):
    """Identify the basic protocol of a packet."""

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(IP):
        return "IP"

    return "Other"


def parse_packet(packet):
    """Extract useful information from a captured packet."""

    try:
        source_ip = None
        destination_ip = None
        source_port = None
        destination_port = None
        tcp_flags = None

        if packet.haslayer(IP):
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        return {
            "timestamp": datetime.now().isoformat(timespec="microseconds"),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": get_protocol(packet),
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_size": len(packet),
            "tcp_flags": tcp_flags
        }

    except Exception as error:
        print(f"Could not process packet: {error}")
        return None


def capture_packets(packet_limit=10):
    """Capture a limited number of packets."""

    print(f"Starting packet capture for {packet_limit} packets...")
    print("Generate some network activity while the capture is running.")

    start_time = time.time()

    captured_packets = sniff(
        count=packet_limit,
        store=True
    )

    end_time = time.time()

    capture_duration = end_time - start_time

    packet_data = []

    for packet in captured_packets:
        parsed_packet = parse_packet(packet)

        if parsed_packet is not None:
            packet_data.append(parsed_packet)

    print(f"Capture duration: {capture_duration:.2f} seconds")

    return packet_data, capture_duration


if __name__ == "__main__":
    packets = capture_packets(10)

    print("\nCaptured Packets:")
    print("-" * 80)

    for packet in packets:
        print(packet)