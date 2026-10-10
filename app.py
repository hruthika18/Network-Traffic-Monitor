import pandas as pd
import plotly.express as px
import streamlit as st

from database.db import get_alerts
from database.db import initialize_database
from database.db import save_alerts
from detection.anomaly_detection import detect_anomalies
from utils.data_loader import load_packets_dataframe
from capture.packet_capture import capture_packets
from database.db import save_packets


from pathlib import Path
import streamlit as st


def load_custom_css():
    css_path = Path(__file__).parent / "assets" / "style.css"

    if css_path.exists():
        css = css_path.read_text(encoding="utf-8")
        st.markdown(
            f"<style>{css}</style>",
            unsafe_allow_html=True
        )

st.set_page_config(
    page_title="Network Traffic Monitor",
    page_icon="📡",
    layout="wide"
)
load_custom_css()

initialize_database()

st.sidebar.title("Network Monitor")

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Packet Analysis",
        "Protocol Analysis",
        "IP Analysis",
        "Port Analysis",
        "Alerts"
    ]
)

st.sidebar.caption(
    "Use only on networks you own or are authorized to monitor."
)

st.title("Network Traffic Monitoring System")
st.caption("Network activity overview and traffic analytics")

if st.button("Capture Packets and Detect Anomalies"):
    with st.spinner("Capturing packets and checking for anomalies..."):
        try:
            packets, duration = capture_packets(packet_limit=10)

            if packets:
                save_packets(packets)

                alerts = detect_anomalies(packets)

                if alerts:
                    save_alerts(alerts)
                    st.warning(f"Detected {len(alerts)} alert(s).")
                else:
                    st.success("Capture completed. No anomalies detected.")

                st.write(f"Packets captured: {len(packets)}")
                st.write(f"Capture duration: {duration:.2f} seconds")
            else:
                st.info("No packets were captured.")

        except Exception as error:
            st.error(f"Packet capture failed: {error}")

try:
    packets_df = load_packets_dataframe()

    if packets_df.empty:
        st.info(
            "No packets are stored yet. Run your packet capture "
            "test to collect data."
        )
        st.stop()

    packets_df["timestamp"] = pd.to_datetime(
        packets_df["timestamp"],
        errors="coerce"
    )

    packets_df["packet_size"] = pd.to_numeric(
        packets_df["packet_size"],
        errors="coerce"
    ).fillna(0)

    packets_df["source_port"] = pd.to_numeric(
        packets_df["source_port"],
        errors="coerce"
    )

    packets_df["destination_port"] = pd.to_numeric(
        packets_df["destination_port"],
        errors="coerce"
    )

    if page == "Dashboard":
        total_packets = len(packets_df)
        total_bytes = int(packets_df["packet_size"].sum())
        source_ips = packets_df["source_ip"].nunique()
        destination_ips = packets_df["destination_ip"].nunique()

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Packets", f"{total_packets:,}")
        col2.metric("Total Traffic", f"{total_bytes:,} bytes")
        col3.metric("Source IPs", source_ips)
        col4.metric("Destination IPs", destination_ips)

        st.subheader("Protocol Distribution")

        protocol_counts = (
            packets_df["protocol"]
            .fillna("Unknown")
            .value_counts()
            .rename_axis("Protocol")
            .reset_index(name="Packet Count")
        )

        fig = px.bar(
            protocol_counts,
            x="Protocol",
            y="Packet Count",
            color="Protocol",
            text="Packet Count",
            title="Packets by Protocol"
        )

        fig.update_layout(showlegend=False)

        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Recently Captured Packets")

        st.dataframe(
            packets_df.head(20),
            use_container_width=True,
            hide_index=True
        )

    elif page == "Packet Analysis":
        st.subheader("Packet Analysis")

        protocols = sorted(
            packets_df["protocol"].dropna().unique().tolist()
        )

        selected_protocol = st.selectbox(
            "Filter by protocol",
            ["All"] + protocols
        )

        source_options = sorted(
            packets_df["source_ip"].dropna().unique().tolist()
        )

        selected_source = st.selectbox(
            "Filter by source IP",
            ["All"] + source_options
        )

        destination_options = sorted(
            packets_df["destination_ip"].dropna().unique().tolist()
        )

        selected_destination = st.selectbox(
            "Filter by destination IP",
            ["All"] + destination_options
        )

        filtered_df = packets_df.copy()

        if selected_protocol != "All":
            filtered_df = filtered_df[
                filtered_df["protocol"] == selected_protocol
            ]

        if selected_source != "All":
            filtered_df = filtered_df[
                filtered_df["source_ip"] == selected_source
            ]

        if selected_destination != "All":
            filtered_df = filtered_df[
                filtered_df["destination_ip"] == selected_destination
            ]

        st.metric("Matching Packets", len(filtered_df))

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True
        )

        csv_data = filtered_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Download Filtered Packets CSV",
            data=csv_data,
            file_name="filtered_packets.csv",
            mime="text/csv"
        )

    elif page == "Protocol Analysis":
        st.subheader("Protocol Analysis")

        protocol_stats = (
            packets_df.groupby("protocol", dropna=False)
            .agg(
                packet_count=("id", "count"),
                total_bytes=("packet_size", "sum")
            )
            .reset_index()
        )

        protocol_stats["protocol"] = (
            protocol_stats["protocol"].fillna("Unknown")
        )

        st.dataframe(
            protocol_stats,
            use_container_width=True,
            hide_index=True
        )

        fig = px.pie(
            protocol_stats,
            names="protocol",
            values="packet_count",
            title="Protocol Share"
        )

        st.plotly_chart(fig, use_container_width=True)

    elif page == "IP Analysis":
        st.subheader("IP Address Analysis")

        source_stats = (
            packets_df.dropna(subset=["source_ip"])
            .groupby("source_ip")
            .agg(
                packet_count=("id", "count"),
                total_bytes=("packet_size", "sum")
            )
            .reset_index()
            .sort_values("packet_count", ascending=False)
        )

        destination_stats = (
            packets_df.dropna(subset=["destination_ip"])
            .groupby("destination_ip")
            .agg(
                packet_count=("id", "count"),
                total_bytes=("packet_size", "sum")
            )
            .reset_index()
            .sort_values("packet_count", ascending=False)
        )

        col1, col2 = st.columns(2)

        with col1:
            st.write("Top Source IPs")
            st.dataframe(
                source_stats.head(10),
                use_container_width=True,
                hide_index=True
            )

        with col2:
            st.write("Top Destination IPs")
            st.dataframe(
                destination_stats.head(10),
                use_container_width=True,
                hide_index=True
            )

        if not source_stats.empty:
            fig = px.bar(
                source_stats.head(10),
                x="source_ip",
                y="packet_count",
                title="Top Source IPs by Packet Count"
            )

            st.plotly_chart(fig, use_container_width=True)

    elif page == "Port Analysis":
        st.subheader("Port Analysis")

        port_type = st.radio(
            "Port direction",
            ["Destination Ports", "Source Ports"],
            horizontal=True
        )

        port_column = (
            "destination_port"
            if port_type == "Destination Ports"
            else "source_port"
        )

        port_stats = (
            packets_df.dropna(subset=[port_column])
            .groupby(port_column)
            .agg(
                packet_count=("id", "count"),
                total_bytes=("packet_size", "sum")
            )
            .reset_index()
            .sort_values("packet_count", ascending=False)
        )

        port_stats[port_column] = port_stats[port_column].astype(int)

        st.dataframe(
            port_stats.head(50),
            use_container_width=True,
            hide_index=True
        )

        if not port_stats.empty:
            fig = px.bar(
                port_stats.head(10),
                x=port_column,
                y="packet_count",
                title=f"Top {port_type}"
            )

            st.plotly_chart(fig, use_container_width=True)

    elif page == "Alerts":
        st.subheader("Network Alerts")

        alerts = get_alerts()

        columns = [
            "id",
            "timestamp",
            "source_ip",
            "alert_type",
            "severity",
            "description"
        ]

        alerts_df = pd.DataFrame(
            alerts,
            columns=columns
        )

        if alerts_df.empty:
            st.info("No alerts have been recorded yet.")
            st.write(
                "Alerts will appear here after anomaly detection "
                "runs and saves them to the database."
            )
        else:
            severity_options = ["All"] + sorted(
                alerts_df["severity"].dropna().unique().tolist()
            )

            selected_severity = st.selectbox(
                "Filter by severity",
                severity_options
            )

            if selected_severity != "All":
                alerts_df = alerts_df[
                    alerts_df["severity"] == selected_severity
                ]

            st.metric("Matching Alerts", len(alerts_df))

            st.dataframe(
                alerts_df,
                use_container_width=True,
                hide_index=True
            )

            csv_data = alerts_df.to_csv(index=False).encode("utf-8")

            st.download_button(
                "Download Alerts CSV",
                data=csv_data,
                file_name="network_alerts.csv",
                mime="text/csv"
            )

except Exception as error:
    st.error("Unable to display the selected page.")
    st.caption(f"Error details: {error}")