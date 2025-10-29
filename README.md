#Team Nismo
Network Monitor v0.7
A real-time network monitoring system that captures, analyzes, and visualizes local network activity — all in a lightweight, Python-based interface.
This version introduces anti-spam alert cooldowns (sensor v0.6) and a modern Dash dashboard with live data visualization (dashboard v0.7).

🧠 Overview
The system consists of two main components:
sensor_v0_6.py — A packet sniffer and behavioral analyzer using Scapy.
Captures IP/TCP/UDP traffic
Detects insecure or suspicious connections
Generates alerts with cooldown logic
Logs traffic and device activity to SQLite
dashboard_v0_7.py — An interactive web dashboard built with Plotly Dash and Cytoscape.
Displays live network traffic
Shows real-time alerts
Maps device communication visually
Lists discovered devices with manufacturers

⚙️ Installation
1. Clone the Repository
git clone https://github.com/DSAI-Society-IIIT-Dharwad/Nismo.git
cd Nismo

2. Install Dependencies
pip install dash pandas scapy mac-vendor-lookup dash-cytoscape

🚀 Usage
Step 1 — Start the Network Sensor
Run with administrator/root privileges:
sudo python3 sensor_v0_6.py

This script will:
Initialize or update sentinel.db
Begin capturing all IP/TCP/UDP packets
Detect devices by MAC address and manufacturer
Generate alerts for:
Insecure protocols (FTP, Telnet, MQTT, etc.)
Suspicious ports (RDP, SSH, SMB, ADB, etc.)
New/unseen device connections
Save live packet logs to network_traffic.log
You’ll see output similar to:

🚀 Starting network sensor v0.6... (Anti-Spam Brain)
Monitoring devices on subnet 10.0.3.*
Alert cooldown set to 10 minutes.
NEW DEVICE: Found new device with MAC 84:C2:E4:12:34:56 at 10.0.3.42
ALERT (CRITICAL): Insecure protocol detected: Telnet (Insecure Remote Login) to 34.120.19.5
ALERT (Info): New connection detected: 10.0.3.42 -> 8.8.8.8:443 (TCP)

Step 2 — Launch the Dashboard
Open a new terminal and run:
python3 dashboard_v0_7.py

Then open your browser and go to:
👉 http://127.0.0.1:8050

🌐 Dashboard Overview
Tab	Description
🗺️ Network Map	Visual representation of recent device connections (30 latest)
🚨 Security Alerts	Displays real-time alerts sorted by severity
💻 Discovered Devices	Lists known devices with MAC address, manufacturer, and timestamps
📊 Live Traffic	Shows the latest 50 packets captured in real time
Map Visualization

Internal nodes = Local devices (your network)
External nodes = Remote IPs (connections)
Edges = Communication between internal and external nodes

🛡️ Smart Features
Feature	Description
🔍 Device Discovery	Automatically identifies new devices by MAC vendor
⚠️ Port Intelligence	Flags insecure and suspicious network ports
🧠 Behavior Profiling	Learns normal communication patterns for each device
🔕 Alert Cooldowns	Prevents spammy alerts by enforcing per-event cooldowns
📡 Real-time Updates	Dashboard auto-refreshes every 5 seconds
🌐 Interactive Network Map	See device relationships with Dash Cytoscape
💾 Persistent Storage	SQLite + CSV for full network history
🧰 Configuration

Edit these variables in sensor_v0_6.py to match your network setup:

YOUR_SUBNET_PREFIX = "192.168.1."
ALERT_COOLDOWN_MINUTES = 10

The subnet prefix ensures alerts and discovery only apply to your own devices.
The cooldown (in minutes) controls how often the same alert can repeat.

📂 Project Structure
├── sensor_v0_6.py         # Network sniffer and analyzer
├── dashboard_v0_7.py      # Dash-based visualization dashboard
├── assets/
│   └── style.css          # Neon UI theme (optional custom styles)
├── sentinel.db            # Auto-generated SQLite database
├── network_traffic.log    # Auto-generated packet log
└── README.md              # You are here

🧪 Example Outputs
Sensor Console
🚀 Starting network sensor v0.6... (Anti-Spam Brain)
Monitoring devices on subnet 10.0.3.*
Alert cooldown set to 10 minutes.
NEW DEVICE: Found new device with MAC 44:1A:2B:3C:4D:5E at 10.0.3.22
ALERT (HIGH): Suspicious outbound port: RDP (Attempted Remote Desktop) to 54.71.82.113
ALERT (Info): New connection detected: 10.0.3.22 -> 142.250.190.78:443 (TCP)

Dashboard Interface
Security Alerts: CRITICAL (red), HIGH (orange), Info (blue)
Network Map: Displays connections visually
Live Traffic: Scrollable table of recent packets
Devices: Lists all devices by MAC and manufacturer

🎨 Dashboard Styling
The dashboard uses a neon cyber theme (defined in /assets/style.css):
Dark background with cyan and teal accents
Glowing headers and section highlights
Smooth tab transitions
Responsive for both desktop and laptop displays

🧠 Tech Stack
Component	Technology
Packet Capture	Scapy
Dashboard	Plotly Dash
Graph Visualization	Dash Cytoscape
Database	SQLite3
Manufacturer Lookup	mac-vendor-lookup

Styling	Custom CSS in /assets/style.css
⚠️ Disclaimer

This tool is for educational and personal network monitoring only.
Do not use it to inspect or capture traffic on networks you don’t own or administer.
Unauthorized monitoring may be illegal in your jurisdiction.
#Team Nismo
