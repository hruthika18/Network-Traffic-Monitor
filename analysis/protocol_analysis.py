def identify_protocol(packet):
    """Identify the protocol using parsed packet information."""

    protocol = packet.get("protocol")
    source_port = packet.get("source_port")
    destination_port = packet.get("destination_port")

    if protocol == "TCP":
        if source_port == 80 or destination_port == 80:
            return "HTTP"

        if source_port == 443 or destination_port == 443:
            return "HTTPS"

        return "TCP"

    if protocol == "UDP":
        if source_port == 53 or destination_port == 53:
            return "DNS"

        if source_port == 443 or destination_port == 443:
            return "HTTPS"

        return "UDP"

    if protocol == "ICMP":
        return "ICMP"

    if protocol == "IP":
        return "IP"

    return "Other"


def analyze_protocols(packets):
    """Count packets and bytes for each protocol."""

    protocol_stats = {}

    for packet in packets:
        protocol = identify_protocol(packet)
        packet_size = packet.get("packet_size", 0)

        if protocol not in protocol_stats:
            protocol_stats[protocol] = {
                "packet_count": 0,
                "total_bytes": 0
            }

        protocol_stats[protocol]["packet_count"] += 1
        protocol_stats[protocol]["total_bytes"] += packet_size

    return protocol_stats