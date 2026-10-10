import pandas as pd

from database.db import get_packets


COLUMNS = [
    "id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "tcp_flags"
]


def load_packets_dataframe():
    """Load stored packets into a Pandas DataFrame."""

    packets = get_packets()

    return pd.DataFrame(packets, columns=COLUMNS)