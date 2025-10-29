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
YOUR_SUBNET_PREFIX = "10.0.3." # I've updated this based on your screenshot
ALERT_COOLDOWN_MINUTES = 10 # Don't re-log the same alert for this many minutes
# ---

# --- Port Definitions (Unchanged) ---
INSECURE_PORTS = {
    21: "FTP (Insecure File Transfer)", 23: "Telnet (Insecure Remote Login)",
    513: "rlogin (Insecure Remote Login)", 514: "rsh (Insecure Remote Shell)",
    1883: "MQTT (Unencrypted IoT Protocol)",
}
SUSPICIOUS_PORTS = {
    22: "SSH (Attempted Server Access)", 3389: "RDP (Attempted Remote Desktop)",
    445: "SMB (Attempted File Share Access)", 4444: "Metasploit (Common Reverse Shell)",
    5555: "Android Debug Bridge (Common Malware Port)", 6667: "IRC (Common Botnet C&C Channel)",
    1337: "leet (Common Malware/Backdoor Port)",
}
# ---

LOG_HEADER = "timestamp,protocol,src_ip,dst_ip,dst_port\n"

def init_db():
    # (This function is unchanged)
    print(f"Initializing database at {DB_FILE}...")
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY, manufacturer TEXT, first_seen TEXT, last_seen TEXT
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS device_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, dst_ip TEXT, dst_port INTEGER,
        protocol TEXT, first_seen TEXT, FOREIGN KEY (mac) REFERENCES devices (mac)
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, mac TEXT, src_ip TEXT,
        dst_ip TEXT, dst_port INTEGER, protocol TEXT, severity TEXT, description TEXT,
        FOREIGN KEY (mac) REFERENCES devices (mac)
    )''')
    conn.commit()
    conn.close()
    print("Database initialized.")

try:
    mac_lookup = MacLookup()
    print("MacLookup initialized.")
except Exception as e:
    print(f"[!] Could not initialize MacLookup. Error: {e}")
    mac_lookup = None

DB_CONN = sqlite3.connect(DB_FILE, check_same_thread=False)

def handle_device(mac, ip):
    # (This function is unchanged)
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

def create_alert(mac, src_ip, dst_ip, dst_port, protocol, severity, description):
    # (This function is unchanged)
    print(f"ALERT ({severity}): {description}")
    cursor = DB_CONN.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO alerts (timestamp, mac, src_ip, dst_ip, dst_port, protocol, severity, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, mac, src_ip, dst_ip, dst_port, protocol, severity, description)
    )
    DB_CONN.commit()

# --- *** UPDATED BEHAVIOR ANALYSIS *** ---
def check_alert_cooldown(cursor, mac, dst_port, description):
    """
    Checks if this exact alert has already been logged within the cooldown period.
    Returns True if on cooldown (should NOT alert), False otherwise (OK to alert).
    """
    cooldown_check = f"datetime('now', '-{ALERT_COOLDOWN_MINUTES} minutes')"
    
    query = f"""
        SELECT * FROM alerts 
        WHERE mac = ? 
        AND dst_port = ? 
        AND description = ?
        AND timestamp > {cooldown_check}
    """
    cursor.execute(query, (mac, dst_port, description))
    return cursor.fetchone() is not None # True if an alert was found

def analyze_packet_behavior(mac, src_ip, dst_ip, dst_port, protocol):
    """
    Analyzes a packet for insecure protocols and connection anomalies.
    """
    cursor = DB_CONN.cursor()
    now = datetime.now().isoformat()
    
    # 1. Insecure Protocol Check (CRITICAL)
    if dst_port in INSECURE_PORTS:
        desc = f"Insecure protocol detected: {INSECURE_PORTS[dst_port]} to {dst_ip}"
        # --- UPDATED COOLDOWN LOGIC ---
        if not check_alert_cooldown(cursor, mac, dst_port, desc):
            create_alert(mac, src_ip, dst_ip, dst_port, protocol, "CRITICAL", desc)

    # 2. Suspicious Port Check (HIGH)
    elif dst_port in SUSPICIOUS_PORTS:
        desc = f"Suspicious outbound port: {SUSPICIOUS_PORTS[dst_port]} to {dst_ip}"
        # --- UPDATED COOLDOWN LOGIC ---
        if not check_alert_cooldown(cursor, mac, dst_port, desc):
            create_alert(mac, src_ip, dst_ip, dst_port, protocol, "HIGH", desc)

    # 3. Connection Baselining (INFO)
    cursor.execute(
        "SELECT * FROM device_profiles WHERE mac = ? AND dst_ip = ? AND dst_port = ? AND protocol = ?",
        (mac, dst_ip, dst_port, protocol)
    )
    profile = cursor.fetchone()
    
    if not profile:
        cursor.execute(
            "INSERT INTO device_profiles (mac, dst_ip, dst_port, protocol, first_seen) VALUES (?, ?, ?, ?, ?)",
            (mac, dst_ip, dst_port, protocol, now)
        )
        DB_CONN.commit()
        
        desc = f"New connection detected: {src_ip} -> {dst_ip}:{dst_port} ({protocol})"
        # Cooldown also applies to "Info" alerts to reduce noise
        # --- UPDATED COOLDOWN LOGIC ---
        if not check_alert_cooldown(cursor, mac, dst_port, desc):
            create_alert(mac, src_ip, dst_ip, dst_port, protocol, "Info", desc)
# ---

# --- Packet Processing (unchanged) ---
def process_packet(packet):
    if IP in packet and Ether in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet[Ether].src
        proto = ""
        dst_port = None
        if TCP in packet:
            proto = "TCP"; dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"; dst_port = packet[UDP].dport
        if proto:
            if src_ip.startswith(YOUR_SUBNET_PREFIX):
                handle_device(src_mac, src_ip)
                analyze_packet_behavior(src_mac, src_ip, dst_ip, dst_port, proto)
            log_line = f"{datetime.now().isoformat()},{proto},{src_ip},{dst_ip},{dst_port}\n"
            try:
                with open(LOG_FILE, "a") as f:
                    f.write(log_line)
            except Exception as e:
                print(f"[!] Error writing to log: {e}")

# --- Main part (unchanged) ---
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write(LOG_HEADER)

init_db()
print(f"🚀 Starting network sensor v0.6... (Anti-Spam Brain)")
print(f"Monitoring devices on subnet {YOUR_SUBNET_PREFIX}*")
print(f"Alert cooldown set to {ALERT_COOLDOWN_MINUTES} minutes.")
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