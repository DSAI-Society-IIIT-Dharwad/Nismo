# Nismo
🛰️ Home Network Analyzer

A lightweight, two-part system to monitor network traffic and discover devices on your local network in real time.
Built for hackathons — combining a Python packet sniffer and a Dash web dashboard for visualization.

🚀 Overview

This project consists of two main components:
sensor_v0_3.py — A network sensor using scapy to capture packets, log network traffic, and detect connected devices (with manufacturer lookup via MAC address).
dashboard_v0_2.py — A Dash-based web interface that visualizes live traffic and device information from the logs and database created by the sensor.
Together, these scripts allow you to:
Capture live IP/TCP/UDP traffic.
Identify and track devices on your network.
View real-time data through a browser dashboard.

🧠 Architecture
[ Sensor (sensor_v0_3.py) ]
   ├─ Captures packets via Scapy
   ├─ Logs traffic to CSV file (network_traffic.log)
   ├─ Stores devices in SQLite (sentinel.db)
   └─ Looks up vendor names via MAC address

          ↓

[ Dashboard (dashboard_v0_2.py) ]
   ├─ Reads traffic from network_traffic.log
   ├─ Reads device data from sentinel.db
   ├─ Displays via Dash web UI
   └─ Auto-refreshes every 5 seconds

⚙️ Setup & Installation
1. Clone the Repository
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>

2. Install Dependencies
You’ll need Python 3.8+ and the following packages:
pip install dash pandas scapy mac-vendor-lookup
(You may also need sqlite3, which is included by default with most Python installations.)

🧩 Usage
Step 1: Run the Sensor
Start capturing live network traffic.
sudo python3 sensor_v0_3.py

⚠️ Root privileges required for packet sniffing.
This will:
Create (or update) network_traffic.log
Create a SQLite database sentinel.db
Continuously log new packets and devices

Step 2: Launch the Dashboard
In a new terminal window:
python3 dashboard_v0_2.py
Then open your browser and go to:
👉 http://127.0.0.1:8050 (similar link)

🧠 Features
Feature	Description
🌐 Live Traffic Monitor	Real-time table of captured IP/TCP/UDP packets
💻 Device Discovery	Lists all devices seen on your subnet with manufacturer info
🗃️ SQLite Storage	Devices persist between runs
🧩 Vendor Lookup	Identifies hardware manufacturers using MAC addresses
⚡ Auto-Refreshing Dashboard	Updates every 5 seconds
🛠️ Configuration

Edit the following in sensor_v0_3.py to match your network:
YOUR_SUBNET_PREFIX = "10.0.3." (ur ipv4 prefix)

Example:
If your IP is 192.168.1.42, set:
YOUR_SUBNET_PREFIX = "192.168.1."

📂 Files
File	Purpose
sensor_v0_3.py	Network packet sniffer and device logger
dashboard_v0_2.py	Dash dashboard for visualization
network_traffic.log	Generated traffic log (CSV)
sentinel.db	SQLite database storing device info
🧪 Example Output

Terminal (sensor):
🚀 Starting network sensor v0.3... (logging to network_traffic.log, DB at sentinel.db)
Monitoring devices on subnet 10.0.3.*
NEW DEVICE: Found new device with MAC 00:1A:2B:3C:4D:5E at 10.0.3.25


Dashboard:

Tab 1: Live Traffic (timestamps, protocol, source/destination)
Tab 2: Discovered Devices (MAC, manufacturer, first seen, last seen)
🧰 Tech Stack
Python 3
Dash — Interactive dashboard UI
Scapy — Network packet sniffing
SQLite3 — Lightweight local database
Mac Vendor Lookup — Hardware manufacturer identification

⚠️ Disclaimer
This tool is intended only for monitoring your own network.
Do not use it on networks you don’t own or administer — packet capture without consent may violate local laws.
Team Nismo
