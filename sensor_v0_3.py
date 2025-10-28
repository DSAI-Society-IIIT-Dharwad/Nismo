import sys
import os
import sqlite3
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Ether
from mac_vendor_lookup import MacLookup # <-- THIS LINE HAS CHANGED

# --- CONFIGURATION ---
LOG_FILE = "network_traffic.log"
DB_FILE = "sentinel.db"
# !!! IMPORTANT: Change this to match your home network's subnet.
YOUR_SUBNET_PREFIX = "10.0.3." 
# ---

LOG_HEADER = "timestamp,protocol,src_ip,dst_ip,dst_port\n"

# --- Database Setup ---
def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    print(f"Initializing database at {DB_FILE}...")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        manufacturer TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized.")

# --- THIS BLOCK HAS CHANGED ---
# Initialize the MacLookup table
try:
    mac_lookup = MacLookup()
    # Note: This library might need its vendor list updated.
    # If lookups fail, we may need to add: mac_lookup.update_vendors()
    # But let's try without it first as it requires an internet call.
    print("MacLookup initialized.")
except Exception as e:
    print(f"[!] Could not initialize MacLookup. Error: {e}")
    mac_lookup = None
# --- END OF CHANGED BLOCK ---

def handle_device(mac, ip):
    """
    Checks if a device is in the database. If not, adds it.
    If it is, updates its 'last_seen' timestamp.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
    device = cursor.fetchone()
    
    if device:
        # Device exists, update last_seen
        cursor.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (now, mac))
    else:
        # New device, get manufacturer and insert
        print(f"NEW DEVICE: Found new device with MAC {mac} at {ip}")
        manufacturer = "Unknown"
        if mac_lookup:
            try:
                # This lookup method is the same
                manufacturer = mac_lookup.lookup(mac)
            except Exception as e:
                manufacturer = "Unknown (Lookup Failed)"
                print(f"Could not look up MAC {mac}: {e}")
        
        cursor.execute("INSERT INTO devices VALUES (?, ?, ?, ?)", (mac, manufacturer, now, now))
    
    conn.commit()
    conn.close()

# --- Packet Processing (No Changes Below) ---
def process_packet(packet):
    """
    Main packet processing function.
    Logs traffic and calls handle_device for device fingerprinting.
    """
    if IP in packet and Ether in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet[Ether].src
        
        if src_ip.startswith(YOUR_SUBNET_PREFIX):
            handle_device(src_mac, src_ip)
        
        timestamp = datetime.now().isoformat()
        proto = ""
        dst_port = ""

        if TCP in packet:
            proto = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            dst_port = packet[UDP].dport
        
        if proto:
            log_line = f"{timestamp},{proto},{src_ip},{dst_ip},{dst_port}\n"
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
print(f"🚀 Starting network sensor v0.3... (logging to {LOG_FILE}, DB at {DB_FILE})")
print(f"Monitoring devices on subnet {YOUR_SUBNET_PREFIX}*")
print("Press Ctrl+C to stop.")

try:
    sniff(filter="ip", prn=process_packet, store=0) 
except KeyboardInterrupt:
    print("\n[!] Sensor stopped by user.")
    sys.exit(0)
except Exception as e:
    print(f"\n[!] An error occurred: {e}")