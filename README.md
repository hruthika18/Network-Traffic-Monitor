
# Network Traffic Monitoring and Analysis System

## Project Overview

The Network Traffic Monitoring and Analysis System is a Python-based application that captures network packets, analyzes traffic information, stores packet records in an SQLite database, and displays network activity through an interactive Streamlit dashboard.

The system provides protocol, IP address, port, and traffic analysis. It also detects selected suspicious traffic patterns and stores alerts for review.

This project is intended for educational use and authorized network monitoring.

## Objectives

- Capture network packets using Scapy.
- Identify protocols and extract packet metadata.
- Analyze source and destination IP addresses.
- Analyze source and destination ports.
- Calculate network traffic statistics.
- Store captured packet information and traffic summaries in SQLite.
- Detect selected suspicious traffic patterns.
- Display network statistics and alerts in a Streamlit dashboard.
- Export packet records and alerts as CSV files.

## Technologies Used

- Python
- Scapy
- Pandas
- SQLite
- Streamlit
- Plotly

## Project Structure

```text
Network-Traffic-Monitor/
├── analysis/
│   ├── protocol_analysis.py
│   ├── ip_analysis.py
│   ├── port_analysis.py
│   └── traffic_analysis.py
├── assets/
│   └── style.css
├── capture/
│   └── packet_capture.py
├── dashboard/
├── database/
│   ├── db.py
│   └── schema.sql
├── detection/
│   └── anomaly_detection.py
├── data/
├── exports/
├── utils/
│   └── data_loader.py
├── app.py
├── config.py
├── requirements.txt
├── test_anomaly_detection.py
├── test_database.py
├── test_protocol.py
├── .gitignore
└── README.md

```

## Features

### 1. Packet Capture

The system uses Scapy to capture network packets and extract metadata, including:

- Timestamp
- Source IP address
- Destination IP address
- Protocol
- Source port
- Destination port
- Packet size
- TCP flags, when available

Packet capture depends on the available network interface and the required operating-system permissions.

### 2. Protocol Analysis

The system classifies captured traffic into protocol categories, including TCP-related HTTP and HTTPS traffic, UDP-related DNS and HTTPS traffic, ICMP, IP, and Other.

The classification uses available packet metadata and configured port mappings; it does not inspect application payloads to verify every protocol.

### 3. IP Address Analysis

The IP analysis module examines available source and destination IP addresses, classifies address types, and calculates packet and byte statistics.

### 4. Port Analysis

The port analysis module examines source and destination ports, identifies configured common ports, and summarizes traffic by port.

### 5. Traffic Statistics

The traffic analysis module calculates:

- Total packets
- Total bytes
- Average packet size
- Packets per second
- Bytes per second
- Unique source IP addresses
- Unique destination IP addresses

### 6. SQLite Database

The database stores packet metadata, traffic summaries, and detected alerts.

The database schema contains three tables:

- `packets`
- `traffic_summary`
- `alerts`

The database file is stored locally under `data/` and is excluded from Git by `.gitignore`.

### 7. Anomaly Detection

The anomaly detection module checks for three configured traffic patterns:

- **Excessive Traffic:** A source generating at least the configured packet threshold within the monitoring window.
- **Possible Port Scan:** A source contacting at least the configured number of distinct destination ports within the monitoring window.
- **Repeated Connection Attempts:** A source generating at least the configured number of TCP SYN connection attempts within the monitoring window.

The current configuration uses a 60-second monitoring window, a threshold of 500 packets for excessive traffic, 20 distinct destination ports for possible port scans, and 50 TCP connection attempts.

These are rule-based indicators, not proof of malicious activity. Results depend on the captured packets and configured thresholds.

### 8. Streamlit Dashboard

The dashboard provides six pages:

- Dashboard
- Packet Analysis
- Protocol Analysis
- IP Analysis
- Port Analysis
- Alerts

The pages display network metrics, charts, packet records, analysis results, and stored alerts. Available filters and CSV downloads help users review the captured information.

### 9. CSV Export

The application provides CSV downloads for supported packet and alert views. Generated CSV files are excluded from Git.

## Installation

### Prerequisites

- Python installed on your system
- Git
- Npcap on Windows when required for Scapy packet capture
- Permission to monitor the selected network interface

### 1. Clone the Repository

```bash
git clone https://github.com/hruthika18/Network-Traffic-Monitor.git
cd Network-Traffic-Monitor
```

### 2. Create a Virtual Environment

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

## Running the Application

Start the Streamlit dashboard from the project root:

```powershell
streamlit run app.py
```

Open the local URL displayed in the terminal.

Use the packet capture control in the application to capture packets and run anomaly detection. The captured packets and any generated alerts are stored in the database.

## Testing

Run the database and packet capture test:

```powershell
python test_database.py
```

Run the packet capture module directly:

```powershell
python capture/packet_capture.py
```

Run the protocol analysis test:

```powershell
python test_protocol.py
```

Run the anomaly detection test:

```powershell
python test_anomaly_detection.py
```

The anomaly detection test creates synthetic packets to check the configured detection rules. These simulated packets do not represent actual malicious network activity.

## Configuration

The `config.py` file contains the database path, export directory, default capture settings, anomaly thresholds, and monitoring window.

Review these settings before using the application in a different environment.

## Limitations

- Results depend on the packets visible to the selected network interface.
- Some packets may not contain source or destination IP addresses or port numbers.
- Protocol labels may be inferred from transport protocols and port numbers.
- Rule-based anomaly detection can produce false positives or miss suspicious activity.
- The project is intended for monitoring and analysis, not as a replacement for a production intrusion detection system.

## Security and Authorized Use

Use this application only on networks and devices that you own or have explicit permission to monitor.

The system is designed to analyze packet metadata and traffic patterns. Do not use it to intercept private communications or monitor networks without authorization.

## Future Improvements

- Add configurable capture duration and interface selection.
- Improve protocol classification and packet parsing.
- Add time-based traffic charts and more detailed reports.
- Improve alert deduplication and alert management.
- Add automated tests for edge cases and malformed packet metadata.

## Author

Developed as an educational computer science project.

## Dashboard UI Design

The application uses a custom-styled Streamlit interface with CSS to improve readability and presentation.

The interface includes:

- A light background with blue accent colors.
- Styled metric cards for displaying network statistics.
- Clearly visible buttons for packet capture and data export.
- Styled tables and chart containers.
- Sidebar navigation for switching between analysis pages.
- Responsive spacing adjustments for smaller screens.

The styling is maintained separately in `assets/style.css`, while the application logic remains in `app.py`.

## Application Workflow

The application follows this workflow:

1. Capture packets from an available network interface.
2. Extract relevant packet metadata.
3. Analyze protocols, IP addresses, ports, and traffic statistics.
4. Store packet records and traffic summaries in the SQLite database.
5. Apply configured rules to identify selected suspicious traffic patterns.
6. Store generated alerts for review.
7. Display analysis results through the Streamlit dashboard.
8. Allow users to filter available records and download supported CSV exports.

## Repository Maintenance

The `.gitignore` file excludes generated files and local environment data, including:

- Virtual environment directories.
- Python cache files.
- The local SQLite database.
- Generated CSV exports.
- Streamlit configuration data.

This keeps the repository focused on source code, configuration, tests, and documentation.

## Conclusion

The Network Traffic Monitoring and Analysis System demonstrates the use of Python, packet capture, data analysis, database storage, rule-based anomaly detection, and interactive visualization in a single application.

The project provides a foundation for understanding network traffic monitoring and basic security analysis. Its modular structure also allows individual components to be tested, maintained, and improved independently.
