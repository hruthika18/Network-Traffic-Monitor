def calculate_traffic_statistics(packets, monitoring_duration=0):
    """Calculate overall network traffic statistics."""

    if not packets:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "average_packet_size": 0,
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "monitoring_duration": monitoring_duration,
            "unique_source_ips": 0,
            "unique_destination_ips": 0
        }

    total_packets = len(packets)

    total_bytes = sum(
        packet.get("packet_size", 0)
        for packet in packets
    )

    average_packet_size = total_bytes / total_packets

    if monitoring_duration > 0:
        packets_per_second = (
            total_packets / monitoring_duration
        )

        bytes_per_second = (
            total_bytes / monitoring_duration
        )
    else:
        packets_per_second = 0
        bytes_per_second = 0

    source_ips = set()
    destination_ips = set()

    for packet in packets:
        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")

        if source_ip:
            source_ips.add(source_ip)

        if destination_ip:
            destination_ips.add(destination_ip)

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "average_packet_size": average_packet_size,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "monitoring_duration": monitoring_duration,
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips)
    }