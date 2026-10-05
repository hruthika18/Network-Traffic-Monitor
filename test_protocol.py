from capture.packet_capture import capture_packets
from analysis.protocol_analysis import identify_protocol, analyze_protocols


print("Capturing 10 packets...")

packets = capture_packets(10)

print("\nIndividual Protocols:")
print("-" * 40)

for packet in packets:
    print(identify_protocol(packet))

print("\nProtocol Statistics:")
print("-" * 40)

statistics = analyze_protocols(packets)

for protocol, values in statistics.items():
    print(
        protocol,
        "->",
        values["packet_count"],
        "packets,",
        values["total_bytes"],
        "bytes"
    )