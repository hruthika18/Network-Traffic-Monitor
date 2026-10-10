from collections import defaultdict
from datetime import datetime, timedelta

from config import (
    TRAFFIC_THRESHOLD,
    PORT_SCAN_THRESHOLD,
    CONNECTION_THRESHOLD,
    TIME_WINDOW_SECONDS
)


def detect_anomalies(packets):
    """Detect possible suspicious traffic patterns."""

    alerts = []

    if not packets:
        return alerts

    valid_packets = []

    for packet in packets:
        timestamp = packet.get("timestamp")

        if not timestamp:
            continue

        try:
            packet_time = datetime.fromisoformat(timestamp)
        except (ValueError, TypeError):
            continue

        valid_packets.append((packet, packet_time))

    if not valid_packets:
        return alerts

    latest_time = max(item[1] for item in valid_packets)
    window_start = latest_time - timedelta(
        seconds=TIME_WINDOW_SECONDS
    )

    recent_packets = [
        (packet, packet_time)
        for packet, packet_time in valid_packets
        if packet_time >= window_start
    ]

    # Detect excessive traffic from a single source IP.
    source_counts = defaultdict(int)

    for packet, _ in recent_packets:
        source_ip = packet.get("source_ip")

        if source_ip:
            source_counts[source_ip] += 1

    for source_ip, count in source_counts.items():
        if count >= TRAFFIC_THRESHOLD:
            alerts.append({
                "timestamp": latest_time.isoformat(),
                "source_ip": source_ip,
                "alert_type": "Excessive Traffic",
                "severity": "Medium",
                "description": (
                    f"{count} packets from one source within "
                    f"{TIME_WINDOW_SECONDS} seconds."
                )
            })

    # Detect sources contacting many different destination ports.
    source_ports = defaultdict(set)

    for packet, _ in recent_packets:
        source_ip = packet.get("source_ip")
        destination_port = packet.get("destination_port")

        if source_ip and destination_port is not None:
            source_ports[source_ip].add(destination_port)

    for source_ip, ports in source_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "timestamp": latest_time.isoformat(),
                "source_ip": source_ip,
                "alert_type": "Possible Port Scan",
                "severity": "High",
                "description": (
                    f"Contacted {len(ports)} different destination "
                    "ports within the monitoring window."
                )
            })

    # Detect repeated connection attempts using TCP SYN flags.
    connection_attempts = defaultdict(int)

    for packet, _ in recent_packets:
        source_ip = packet.get("source_ip")
        tcp_flags = packet.get("tcp_flags")

        if (
            source_ip
            and tcp_flags is not None
            and "S" in str(tcp_flags)
            and "A" not in str(tcp_flags)
        ):
            connection_attempts[source_ip] += 1

    for source_ip, count in connection_attempts.items():
        if count >= CONNECTION_THRESHOLD:
            alerts.append({
                "timestamp": latest_time.isoformat(),
                "source_ip": source_ip,
                "alert_type": "Repeated Connection Attempts",
                "severity": "Medium",
                "description": (
                    f"{count} possible TCP connection attempts "
                    f"within {TIME_WINDOW_SECONDS} seconds."
                )
            })

    return alerts