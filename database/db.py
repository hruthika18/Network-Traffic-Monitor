import sqlite3
from pathlib import Path

from config import DATABASE_PATH


def initialize_database():
    """Create the database and required tables."""

    database_folder = Path(DATABASE_PATH).parent
    database_folder.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    schema_path = Path(__file__).parent / "schema.sql"

    with open(schema_path, "r", encoding="utf-8") as file:
        schema = file.read()

    connection.executescript(schema)
    connection.commit()
    connection.close()


def get_connection():
    """Create and return a SQLite database connection."""

    return sqlite3.connect(DATABASE_PATH)


def save_packet(packet):
    """Save one captured packet to the database."""

    connection = get_connection()

    query = """
        INSERT INTO packets (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """

    values = (
        packet.get("timestamp"),
        packet.get("source_ip"),
        packet.get("destination_ip"),
        packet.get("protocol"),
        packet.get("source_port"),
        packet.get("destination_port"),
        packet.get("packet_size"),
        packet.get("tcp_flags")
    )

    connection.execute(query, values)
    connection.commit()
    connection.close()


def save_packets(packets):
    """Save multiple captured packets to the database."""

    connection = get_connection()

    query = """
        INSERT INTO packets (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """

    values = []

    for packet in packets:
        values.append(
            (
                packet.get("timestamp"),
                packet.get("source_ip"),
                packet.get("destination_ip"),
                packet.get("protocol"),
                packet.get("source_port"),
                packet.get("destination_port"),
                packet.get("packet_size"),
                packet.get("tcp_flags")
            )
        )

    connection.executemany(query, values)
    connection.commit()
    connection.close()


def get_packets():
    """Return all stored packets."""

    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT
            id,
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        FROM packets
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    return rows


def get_packet_count():
    """Return the total number of stored packets."""

    connection = get_connection()

    cursor = connection.execute(
        "SELECT COUNT(*) FROM packets"
    )

    count = cursor.fetchone()[0]

    connection.close()

    return count

def save_traffic_summary(protocol_statistics):
    """Save protocol traffic statistics to the database."""

    connection = get_connection()

    query = """
        INSERT INTO traffic_summary (
            timestamp,
            protocol,
            packet_count,
            total_bytes
        )
        VALUES (datetime('now'), ?, ?, ?)
    """

    values = []

    for protocol, statistics in protocol_statistics.items():
        values.append(
            (
                protocol,
                statistics["packet_count"],
                statistics["total_bytes"]
            )
        )

    connection.executemany(query, values)
    connection.commit()
    connection.close()


def get_traffic_summary():
    """Return stored traffic summary records."""

    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT
            id,
            timestamp,
            protocol,
            packet_count,
            total_bytes
        FROM traffic_summary
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    return rows

def save_alerts(alerts):
    """Save detected alerts to SQLite."""

    if not alerts:
        return

    connection = get_connection()

    query = """
        INSERT INTO alerts (
            timestamp,
            source_ip,
            alert_type,
            severity,
            description
        )
        VALUES (?, ?, ?, ?, ?)
    """

    values = [
        (
            alert["timestamp"],
            alert.get("source_ip"),
            alert["alert_type"],
            alert["severity"],
            alert["description"]
        )
        for alert in alerts
    ]

    try:
        connection.executemany(query, values)
        connection.commit()
    finally:
        connection.close()


def get_alerts():
    """Retrieve stored alerts from SQLite."""

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            SELECT
                id,
                timestamp,
                source_ip,
                alert_type,
                severity,
                description
            FROM alerts
            ORDER BY id DESC
            """
        )

        return cursor.fetchall()
    finally:
        connection.close()