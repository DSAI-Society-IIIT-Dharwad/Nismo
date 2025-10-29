# **Network Traffic Analyzer for Home Security**

## **Overview**

This project is a home network security monitoring system designed to detect suspicious activities in real-time. It analyzes network traffic, identifies connected devices, flags potential vulnerabilities or compromises, and visualizes communication patterns on an interactive web dashboard. The goal is to provide homeowners with insights into their network's behavior and alert them to potential threats.

## **Core Features**

This system integrates several layers of analysis to provide comprehensive monitoring:

1. **Real-time Packet Capture:**  
   * **Explanation:** Uses the scapy library to capture network packets directly from specified network interfaces (e.g., main Wi-Fi, hotspot).  
   * **Need:** This is the fundamental data source. Without capturing packets, no analysis is possible.
2. **Device Fingerprinting (MAC/OUI & DHCP):**  
   * **Explanation:** Identifies devices on the network by their unique MAC address. It looks up the manufacturer using the OUI (first half of the MAC) and captures the device's self-assigned hostname (e.g., "Sams-iPhone", "LivingRoom-TV") from DHCP requests.  
   * **Need:** Knowing *what* devices are on the network provides crucial context for alerts. A suspicious connection from a known computer is different from the same connection coming from a smart plug.  
3. **Insecure Protocol Detection (CRITICAL Alerts):**  
   * **Explanation:** Actively monitors for traffic using inherently insecure protocols like Telnet, FTP, rlogin, rsh, and unencrypted MQTT.  z
   * **Need:** Usage of these protocols, especially by IoT devices, indicates a significant vulnerability that could be easily exploited. This directly addresses the "flag insecure IoT devices" objective.  
4. **Suspicious Port Detection (HIGH Alerts):**  
   * **Explanation:** Flags outbound connections to ports commonly associated with malicious activity or services that shouldn't typically originate from a home device (e.g., SSH, RDP, IRC, common malware backdoor ports).  
   * **Need:** This helps detect potentially compromised devices that might be trying to connect to botnet command-and-control servers, attempting to spread laterally, or being remotely accessed.  
5. **Connection Baselining (NORMAL Alerts):**  
   * **Explanation:** Creates a profile for each known device, recording every unique connection (Destination IP \+ Port \+ Protocol) it makes. The *first* time a new, previously unseen connection is detected, a "NORMAL" alert is generated.  
   * **Need:** While not inherently malicious, tracking new connections provides visibility into device behavior changes. It helps establish what's "normal" for each device over time.  
6. **DNS Monitoring & Threat Intelligence (CRITICAL Alerts):**  
   * **Explanation:** Captures DNS queries (UDP Port 53\) to see which domain names devices are trying to resolve. It checks these domains against a configurable blocklist of known malicious sites.  
   * **Need:** Malware often uses domain names, not fixed IPs. Detecting attempts to contact known malicious domains is a highly effective way to catch compromised devices early, often before they establish a harmful connection.  
7. **Interactive Dashboard (Plotly Dash):**  
   * **Explanation:** A web-based user interface providing multiple views of the network data:  
     * **Network Map:** Visualizes devices (using icons/hostnames) and their connections (color-coded by alert severity).  
     * **Security Alerts:** Lists all generated alerts (CRITICAL, HIGH, NORMAL), color-coded and filterable by severity, with pop-up notifications for new high-priority alerts.  
     * **Discovered Devices:** Shows all identified devices with their MAC, Hostname, Manufacturer, and activity timestamps.  
     * **DNS Logs:** A live feed of all observed DNS queries.  
     * **Live Traffic:** A raw log of captured network packets.  
   * **Need:** Makes the complex network data accessible and understandable, allowing users to quickly assess the network's status and investigate alerts.

## **How it Works (Architecture)**

1. **Sensors (sensor\_\*.py):** Two Python scripts run using scapy to capture packets on different network interfaces (e.g., main Wi-Fi and a hotspot). They perform initial packet dissection (DHCP, DNS, TCP/UDP).  
2. **Analysis & Database (sqlite3):** The sensors analyze packet details, compare against known patterns (ports, DNS blocklist, scan behavior), update device profiles, and log alerts and DNS queries into a central sentinel.db SQLite database.  
3. **Dashboard (dashboard\_\*.py):** A Plotly Dash web application runs independently. It periodically queries the sentinel.db database and updates the tables and network map displayed in the user's web browser.

## **Setup & Running**

1. **Prerequisites:** Python 3, pip.
2. **Clone the Repository:**
   git clone \<https://github.com/DSAI-Society-IIIT-Dharwad/Nismo.git)\>  
   cd Nismo
3. **Install Dependencies:**  
   pip install scapy mac-vendor-lookup dash pandas dash-cytoscape  
   \# On Windows, install Npcap (with WinPcap compatibility)  
   \# On Linux/macOS, ensure libpcap-dev (or equivalent) is installed

4. **Configure Sensors:** Edit both sensor\_main\_wifi.py and sensor\_hotspot.py:  
   * Set YOUR\_SUBNET\_PREFIX correctly for each network they monitor.  
   * Set the correct iface name in the sniff() command at the bottom of each file.  
5. **Run:**  
   * Open **Terminal 1 (Admin):** python sensor\_main\_wifi.py  
   * Open **Terminal 2 (Admin):** python sensor\_hotspot.py  
   * Open **Terminal 3 (Normal):** python dashboard.py (use your latest dashboard file)  
6. **Access Dashboard:** Open http://127.0.0.1:8050 in your web browser.

## **Future Improvements**

* **HTTP User-Agent Fingerprinting:** Extract User-Agent strings from HTTP traffic to identify specific applications or device models.  
* **Traffic Volume Baselining:** Monitor the *amount* of data transferred per connection to detect anomalies like data exfiltration or DDoS participation.  
* **Encrypted Traffic Analysis (Advanced):** Analyze patterns in encrypted traffic (TLS handshake details, connection timing) for potential threats (requires more advanced techniques).  
* **Configuration File:** Move settings like subnet, cooldowns, and blocklists into a separate config file instead of hardcoding.
