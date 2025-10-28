import sys
import os
import sqlite3
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Ether
from mac_vendor_lookup import MacLookup

# --- CONFIGURATION ---
LOG_FILE = "network_traffic.log"
DB_FILE = "sentinel.db"
# !!! Make sure this is still correct for your network !!!
YOUR_SUBNET_PREFIX = "10.0.3." # Example: "192.168.1."
# ---

# --- Insecure Port Definitions ---
INSECURE_PORTS = {
    21: "FTP (Insecure)",
    23: "Telnet (Insecure)",
    80: "HTTP (Unencrypted)", # We'll just flag this for now
}
# ---

LOG_HEADER = "timestamp,protocol,src_ip,dst_ip,dst_port\n"

# --- Database Setup ---
def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    print(f"Initializing database at {DB_FILE}...")
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    
    # 'devices' table (unchanged)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        manufacturer TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    ''')
    
    # --- NEW: 'device_profiles' table ---
    # Stores known-good connections for each device
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS device_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        protocol TEXT,
        first_seen TEXT,
        FOREIGN KEY (mac) REFERENCES devices (mac)
    )
    ''')
    
    # --- NEW: 'alerts' table ---
    # Stores all generated security alerts
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        mac TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        protocol TEXT,
        severity TEXT,
        description TEXT,
        FOREIGN KEY (mac) REFERENCES devices (mac)
    )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized.")

# --- Initialize MacLookup (unchanged) ---
try:
    mac_lookup = MacLookup()
    print("MacLookup initialized.")
except Exception as e:
    print(f"[!] Could not initialize MacLookup. Error: {e}")
    mac_lookup = None

# We need a persistent connection for this more complex sensor
DB_CONN = sqlite3.connect(DB_FILE, check_same_thread=False)

def handle_device(mac, ip):
    """ (Unchanged) Manages the device list. """
    cursor = DB_CONN.cursor()
    now = datetime.now().isoformat()
    
    cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
    if cursor.fetchone():
        cursor.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (now, mac))
    else:
        print(f"NEW DEVICE: Found new device with MAC {mac} at {ip}")
        manufacturer = "Unknown"
        if mac_lookup:
            try: manufacturer = mac_lookup.lookup(mac)
            except: manufacturer = "Unknown (Lookup Failed)"
        
        cursor.execute("INSERT INTO devices VALUES (?, ?, ?, ?)", (mac, manufacturer, now, now))
    DB_CONN.commit()

# --- NEW: Alert Generation Function ---
def create_alert(mac, src_ip, dst_ip, dst_port, protocol, severity, description):
    """Inserts a new alert into the database."""
    print(f"ALERT ({severity}): {description}")
    cursor = DB_CONN.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO alerts (timestamp, mac, src_ip, dst_ip, dst_port, protocol, severity, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, mac, src_ip, dst_ip, dst_port, protocol, severity, description)
    )
    DB_CONN.commit()

# --- NEW: Behavioral Analysis Function ---
def analyze_packet_behavior(mac, src_ip, dst_ip, dst_port, protocol):
    """
    Analyzes a packet for insecure protocols and connection anomalies.
    """
    cursor = DB_CONN.cursor()
    now = datetime.now().isoformat()
    
    # 1. Insecure Protocol Check
    if dst_port in INSECURE_PORTS:
        desc = f"Insecure protocol detected: {INSECURE_PORTS[dst_port]} to {dst_ip}"
        # To avoid spam, let's check if we already flagged this exact alert today
        cursor.execute(
            "SELECT * FROM alerts WHERE mac = ? AND dst_port = ? AND description = ? AND date(timestamp) = date('now')",
            (mac, dst_port, desc)
        )
        if not cursor.fetchone():
            create_alert(mac, src_ip, dst_ip, dst_port, protocol, "CRITICAL", desc)

    # 2. Connection Baselining
    # Check if this exact connection is already in our profile
    cursor.execute(
        "SELECT * FROM device_profiles WHERE mac = ? AND dst_ip = ? AND dst_port = ? AND protocol = ?",
        (mac, dst_ip, dst_port, protocol)
    )
    profile = cursor.fetchone()
    
    if not profile:
        # This is a new, unseen connection!
        # Add it to the profile
        cursor.execute(
            "INSERT INTO device_profiles (mac, dst_ip, dst_port, protocol, first_seen) VALUES (?, ?, ?, ?, ?)",
            (mac, dst_ip, dst_port, protocol, now)
        )
        DB_CONN.commit()
        
        # Create an alert
        desc = f"New connection detected: {src_ip} -> {dst_ip}:{dst_port} ({protocol})"
        create_alert(mac, src_ip, dst_ip, dst_port, protocol, "Medium", desc)

# --- Packet Processing (Updated) ---
def process_packet(packet):
    """
    Main packet processing function.
    """
    if IP in packet and Ether in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet[Ether].src
        
        proto = ""
        dst_port = None
        
        if TCP in packet:
            proto = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            dst_port = packet[UDP].dport
        
        if proto:
            # --- Device Fingerprinting (only for our subnet) ---
            if src_ip.startswith(YOUR_SUBNET_PREFIX):
                handle_device(src_mac, src_ip)
                
                # --- Behavioral Analysis (only for our devices) ---
                analyze_packet_behavior(src_mac, src_ip, dst_ip, dst_port, proto)
            
            # --- Traffic Logging (same as before) ---
            log_line = f"{datetime.now().isoformat()},{proto},{src_ip},{dst_ip},{dst_port}\n"
            try:
                with open(LOG_FILE, "a") as f:
                    f.write(log_line)
            except Exception as e:
                print(f"[!] Error writing to log: {e}")

# --- Main part of the script ---
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write(LOG_HEADER)

init_db()
print(f"🚀 Starting network sensor v0.4... (The Brain)")
print(f"Monitoring devices on subnet {YOUR_SUBNET_PREFIX}*")
print("Press Ctrl+C to stop.")

try:
    sniff(filter="ip and (tcp or udp)", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\n[!] Sensor stopped. Closing DB connection.")
    DB_CONN.close()
    sys.exit(0)
except Exception as e:
    print(f"\n[!] An error occurred: {e}")
    DB_CONN.close()