COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS"
}


def identify_port(port):
    """Return the common service name for a port."""

    if port is None:
        return "Unknown"

    return COMMON_PORTS.get(port, "Unknown")


def analyze_ports(packets):
    """Analyze source and destination ports."""

    source_ports = {}
    destination_ports = {}

    for packet in packets:
        source_port = packet.get("source_port")
        destination_port = packet.get("destination_port")
        packet_size = packet.get("packet_size", 0)

        if source_port is not None:
            if source_port not in source_ports:
                source_ports[source_port] = {
                    "service": identify_port(source_port),
                    "packet_count": 0,
                    "total_bytes": 0
                }

            source_ports[source_port]["packet_count"] += 1
            source_ports[source_port]["total_bytes"] += packet_size

        if destination_port is not None:
            if destination_port not in destination_ports:
                destination_ports[destination_port] = {
                    "service": identify_port(destination_port),
                    "packet_count": 0,
                    "total_bytes": 0
                }

            destination_ports[destination_port]["packet_count"] += 1
            destination_ports[destination_port]["total_bytes"] += packet_size

    return {
        "source_ports": source_ports,
        "destination_ports": destination_ports
    }