import ipaddress


def get_ip_type(ip_address):
    """Classify an IP address."""

    if not ip_address:
        return "Unknown"

    try:
        address = ipaddress.ip_address(ip_address)

        if address.is_loopback:
            return "Loopback"

        if address.is_multicast:
            return "Multicast"

        if address.is_private:
            return "Private"

        return "Public"

    except ValueError:
        return "Invalid"


def analyze_ip_addresses(packets):
    """Analyze source and destination IP addresses."""

    source_stats = {}
    destination_stats = {}

    for packet in packets:
        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        packet_size = packet.get("packet_size", 0)

        if source_ip:
            if source_ip not in source_stats:
                source_stats[source_ip] = {
                    "packet_count": 0,
                    "total_bytes": 0,
                    "ip_type": get_ip_type(source_ip)
                }

            source_stats[source_ip]["packet_count"] += 1
            source_stats[source_ip]["total_bytes"] += packet_size

        if destination_ip:
            if destination_ip not in destination_stats:
                destination_stats[destination_ip] = {
                    "packet_count": 0,
                    "total_bytes": 0,
                    "ip_type": get_ip_type(destination_ip)
                }

            destination_stats[destination_ip]["packet_count"] += 1
            destination_stats[destination_ip]["total_bytes"] += packet_size

    return {
        "source_ips": source_stats,
        "destination_ips": destination_stats
    }


def get_unique_ip_count(packets):
    """Return the number of unique source and destination IPs."""

    unique_ips = set()

    for packet in packets:
        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")

        if source_ip:
            unique_ips.add(source_ip)

        if destination_ip:
            unique_ips.add(destination_ip)

    return len(unique_ips)