from datetime import datetime, timedelta

from detection.anomaly_detection import detect_anomalies
from database.db import save_alerts, get_alerts


def main():
    now = datetime.now()
    packets = []

    # Test 1: Excessive traffic
    for i in range(500):
        packets.append({
            "timestamp": (
                now + timedelta(milliseconds=i)
            ).isoformat(),
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "protocol": "TCP",
            "source_port": 50000,
            "destination_port": 443,
            "packet_size": 100,
            "tcp_flags": "A"
        })

    # Test 2: Possible port scan
    for port in range(20, 45):
        packets.append({
            "timestamp": (
                now + timedelta(milliseconds=port)
            ).isoformat(),
            "source_ip": "192.0.2.30",
            "destination_ip": "192.0.2.40",
            "protocol": "TCP",
            "source_port": 50001,
            "destination_port": port,
            "packet_size": 60,
            "tcp_flags": "S"
        })

    # Test 3: Repeated TCP connection attempts
    for i in range(50):
        packets.append({
            "timestamp": (
                now + timedelta(milliseconds=i)
            ).isoformat(),
            "source_ip": "192.0.2.50",
            "destination_ip": "192.0.2.60",
            "protocol": "TCP",
            "source_port": 50002,
            "destination_port": 443,
            "packet_size": 60,
            "tcp_flags": "S"
        })

    alerts = detect_anomalies(packets)

    print("Total alerts detected:", len(alerts))
    print()

    for alert in alerts:
        print("Alert Type:", alert["alert_type"])
        print("Source IP:", alert["source_ip"])
        print("Severity:", alert["severity"])
        print("Description:", alert["description"])
        print("-" * 50)

    if alerts:
        save_alerts(alerts)
        print("Alerts saved to the database.")

    print("\nLatest stored alerts:")
    for alert in get_alerts()[:10]:
        print(alert)


if __name__ == "__main__":
    main()