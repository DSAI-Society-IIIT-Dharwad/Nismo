# Nismo
🛰️Network Monitor v0.5
A modern, real-time system to analyze, visualize, and secure your home network — built entirely with Python.
Includes an AI-inspired packet sensor, interactive dashboard, and sleek neon UI.

🧠 Overview

This project is a two-part network monitoring suite:
sensor_v0_4.py — The “brain” that captures packets, logs devices, profiles their network behavior, and generates security alerts.
dashboard_v0_5.py — The visual “control center,” built with Plotly Dash + Cytoscape, showing real-time traffic, alerts, and device maps.
style.css — A custom theme file that adds a futuristic cyber look to your dashboard.
Together, they form a self-contained network sentinel — tracking, learning, and visualizing every connection in your home.

🧩 Architecture
            ┌──────────────────────────┐
            │     sensor_v0_4.py       │
            │  • Captures packets      │
            │  • Profiles behavior     │
            │  • Generates alerts      │
            │  • Stores in SQLite      │
            └────────────┬─────────────┘
                         │
                         ▼
             ┌─────────────────────┐
             │     sentinel.db     │
             │  • devices          │
             │  • device_profiles  │
             │  • alerts           │
             └─────────┬───────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │      dashboard_v0_5.py       │
        │  • Live traffic log          │
        │  • Security alert panel      │
        │  • Interactive network map   │
        │  • Device discovery table    │
        └──────────────────────────────┘
                       │
                       ▼
             ┌────────────────────────┐
             │       style.css        │
             │  • Cyberpunk theme     │
             │  • Responsive design   │
             └────────────────────────┘

⚙️ Installation
1. Clone the Repository
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>

2. Install Dependencies
pip install dash pandas scapy mac-vendor-lookup dash-cytoscape

(Optional but recommended: Create a virtual environment before installing.)

🚀 How to Run
Step 1: Start the Network Sensor
sudo python3 sensor_v0_4.py

⚠️ Root/admin privileges are required for scapy to capture packets.

This script will:

Initialize sentinel.db (SQLite)
Log all IP/TCP/UDP traffic to network_traffic.log
Detect new devices and save manufacturer info
Learn connection profiles
Create alerts for insecure or new connections

Step 2: Launch the Dashboard
In a new terminal window:
python3 dashboard_v0_5.py

Then open your browser at:
👉 http://127.0.0.1:8050

You’ll see four main tabs:

Tab	Description
🌐 Network Map	Visualizes live device connections using Dash Cytoscape
🚨 Security Alerts	Shows CRITICAL and Medium alerts with timestamps and details
💻 Discovered Devices	Lists all known devices with manufacturer info
📊 Live Traffic	Displays most recent 50 packets in real time
🛡️ Smart Security Features
Feature	Description
🔍 Device Discovery	Detects all devices on your subnet and identifies manufacturers
⚠️ Insecure Protocol Detection	Flags use of FTP, Telnet, and HTTP as insecure
🧠 Behavioral Profiling	Learns normal device communication patterns
🧩 Anomaly Alerts	Generates alerts for never-before-seen connections
💾 Persistent Logging	Saves all traffic, alerts, and devices to SQLite
🌐 Live Network Map	Real-time visualization of your connections
🎨 Cyber UI	Futuristic neon-blue theme powered by style.css
🧰 Configuration

In sensor_v0_4.py, edit this line to match your network:

YOUR_SUBNET_PREFIX = "192.168.1."

You can also customize which ports are flagged as insecure:

INSECURE_PORTS = {
    21: "FTP (Insecure)",
    23: "Telnet (Insecure)",
    80: "HTTP (Unencrypted)"
}

🎨 Styling (style.css)

The dashboard’s neon theme is defined in style.css.
Key design features:
Dark background with neon cyan and purple highlights
Animated tab transitions
Responsive layout for desktop & mobile
Custom scrollbars and table glow effects
To modify the look, simply tweak the color variables in the :root section.

📂 Project Structure
├── sensor_v0_4.py       # Packet sniffer, behavior profiler, and alert system
├── dashboard_v0_5.py    # Dash dashboard with network map and alert center
├── style.css            # Futuristic cyberpunk theme for dashboard
├── sentinel.db          # SQLite database (auto-generated)
├── network_traffic.log  # Real-time packet log (auto-generated)
└── README.md            # You are here

🧪 Example Output

Sensor Terminal:

🚀 Starting network sensor v0.4... (The Brain)
Monitoring devices on subnet 192.168.1.*
NEW DEVICE: Found new device with MAC 00:1A:2B:3C:4D:5E at 192.168.1.15
ALERT (CRITICAL): Insecure protocol detected: HTTP (Unencrypted) to 142.250.190.78
ALERT (Medium): New connection detected: 192.168.1.15 -> 142.250.190.78:443 (TCP)


Dashboard Tabs:

🌐 Network Map: Interactive graph with internal/external nodes
🚨 Alerts: Color-coded by severity (red = CRITICAL, yellow = Medium)
💻 Devices: Sorted by “Last Seen”
📊 Live Traffic: Real-time packet table (auto-refresh every 5 seconds)

🧠 Tech Stack
Component	Technology
Network Sniffer	Scapy
Web Dashboard	Plotly Dash
Graph Visualization	Dash Cytoscape

Database	SQLite3
Manufacturer Lookup	mac-vendor-lookup

Styling	Custom CSS (neon cyberpunk theme)
⚠️ Disclaimer

This tool is for educational and personal network monitoring only.
Do not use it on networks you do not own or administer.
Unauthorized packet capture may be illegal in your jurisdiction.
Team Nismo
