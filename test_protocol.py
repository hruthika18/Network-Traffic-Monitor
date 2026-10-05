from capture.packet_capture import capture_packets
from analysis.protocol_analysis import identify_protocol, analyze_protocols
from analysis.ip_analysis import analyze_ip_addresses, get_unique_ip_count
from analysis.port_analysis import analyze_ports


print("Capturing 10 packets...")

packets = capture_packets(10)

print("\nIndividual Protocols:")
print("-" * 40)

for packet in packets:
    print(identify_protocol(packet))

print("\nProtocol Statistics:")
print("-" * 40)

protocol_statistics = analyze_protocols(packets)

for protocol, values in protocol_statistics.items():
    print(
        protocol,
        "->",
        values["packet_count"],
        "packets,",
        values["total_bytes"],
        "bytes"
    )

print("\nIP Address Statistics:")
print("-" * 40)

ip_statistics = analyze_ip_addresses(packets)

print("\nSource IPs:")

for ip_address, values in ip_statistics["source_ips"].items():
    print(
        ip_address,
        "->",
        values["packet_count"],
        "packets,",
        values["total_bytes"],
        "bytes,",
        "Type:",
        values["ip_type"]
    )

print("\nDestination IPs:")

for ip_address, values in ip_statistics["destination_ips"].items():
    print(
        ip_address,
        "->",
        values["packet_count"],
        "packets,",
        values["total_bytes"],
        "bytes,",
        "Type:",
        values["ip_type"]
    )

print("\nUnique IP Count:")
print(get_unique_ip_count(packets))

print("\nPort Statistics:")
print("-" * 40)

port_statistics = analyze_ports(packets)

print("\nSource Ports:")

for port, values in port_statistics["source_ports"].items():
    print(
        port,
        "->",
        values["service"],
        ",",
        values["packet_count"],
        "packets,",
        values["total_bytes"],
        "bytes"
    )

print("\nDestination Ports:")

for port, values in port_statistics["destination_ports"].items():
    print(
        port,
        "->",
        values["service"],
        ",",
        values["packet_count"],
        "packets,",
        values["total_bytes"],
        "bytes"
    )