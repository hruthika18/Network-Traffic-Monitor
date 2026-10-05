from capture.packet_capture import capture_packets
from database.db import initialize_database
from database.db import save_packets
from database.db import get_packet_count
from database.db import get_packets
from database.db import save_traffic_summary
from database.db import get_traffic_summary
from analysis.protocol_analysis import analyze_protocols


print("Initializing database...")

initialize_database()

print("Capturing 10 packets...")

packets, capture_duration = capture_packets(10)

print("\nSaving packets to database...")

save_packets(packets)

print("Packets saved successfully.")

print("\nCalculating traffic summary...")

protocol_statistics = analyze_protocols(packets)

save_traffic_summary(protocol_statistics)

print("Traffic summary saved successfully.")

print("\nDatabase Statistics:")
print("-" * 40)

packet_count = get_packet_count()

print("Total stored packets:", packet_count)

print("\nLatest Stored Packets:")
print("-" * 40)

stored_packets = get_packets()

for packet in stored_packets[:10]:
    print(packet)

print("\nStored Traffic Summary:")
print("-" * 40)

traffic_summary = get_traffic_summary()

for summary in traffic_summary[:10]:
    print(summary)