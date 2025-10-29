import sys
import os
import sqlite3
from datetime import datetime
# --- UPDATED 1: Imports ---
from scapy.all import sniff, IP, TCP, UDP, Ether, BOOTP, DHCP, DNS, DNSQR
from mac_vendor_lookup import MacLookup

# --- CONFIGURATION (from your file) ---
LOG_FILE = "network_traffic.log"
DB_FILE = "sentinel.db"
YOUR_SUBNET_PREFIX = "10.0.3."
CRITICAL_COOLDOWN_MINUTES = 0
HIGH_COOLDOWN_MINUTES = 0
NORMAL_COOLDOWN_MINUTES = 3
# ---

# --- UPDATED 2: Malicious Domain Blocklist ---
MALICIOUS_DOMAINS = {
    "malware-test-domain.com",  # Safe for testing
    "botnet-c2-server.ru",
    "phishing-site-example.net",
}
# ---

# --- Port Definitions ---
INSECURE_PORTS = {21: "FTP", 23: "Telnet", 513: "rlogin", 514: "rsh", 1883: "MQTT"}
SUSPICIOUS_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 4444: "Metasploit", 5555: "Android Debug", 6667: "IRC", 1337: "leet"}

LOG_HEADER = "timestamp,protocol,src_ip,dst_ip,dst_port\n"

# --- UPDATED 3: init_db() ---
def init_db():
    print(f"Initializing database at {DB_FILE}...")
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY, hostname TEXT, manufacturer TEXT, 
        first_seen TEXT, last_seen TEXT
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS device_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, dst_ip TEXT, 
        dst_port INTEGER, protocol TEXT, first_seen TEXT, 
        FOREIGN KEY (mac) REFERENCES devices (mac)
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, mac TEXT, 
        src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT, 
        severity TEXT, description TEXT,
        FOREIGN KEY (mac) REFERENCES devices (mac)
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS dns_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        mac TEXT,
        src_ip TEXT,
        queried_domain TEXT,
        FOREIGN KEY (mac) REFERENCES devices (mac)
    )
    ''')
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


def handle_device(mac, ip, hostname=None):
    cursor = DB_CONN.cursor()
    now = datetime.now().isoformat()
    cursor.execute("SELECT hostname FROM devices WHERE mac = ?", (mac,))
    device = cursor.fetchone()
    if device:
        current_hostname = device[0]
        if hostname and not current_hostname:
            print(f"✅ DEVICE UPDATE: MAC {mac} is Hostname: {hostname}")
            cursor.execute("UPDATE devices SET last_seen = ?, hostname = ? WHERE mac = ?", (now, hostname, mac))
        else:
            cursor.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (now, mac))
    else:
        print(f"NEW DEVICE: Found new device with MAC {mac} at {ip}")
        manufacturer = "Unknown"
        if mac_lookup:
            try:
                manufacturer = mac_lookup.lookup(mac)
            except:
                manufacturer = "Unknown (Lookup Failed)"
        cursor.execute(
            "INSERT INTO devices (mac, hostname, manufacturer, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (mac, hostname, manufacturer, now, now)
        )
        if hostname:
            print(f"✅ DEVICE UPDATE: MAC {mac} is Hostname: {hostname}")
    DB_CONN.commit()


def create_alert(mac, src_ip, dst_ip, dst_port, protocol, severity, description):
    print(f"🚨 ALERT ({severity}): {description}")
    cursor = DB_CONN.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO alerts (timestamp, mac, src_ip, dst_ip, dst_port, protocol, severity, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, mac, src_ip, dst_ip, dst_port, protocol, severity, description)
    )
    DB_CONN.commit()


def check_alert_cooldown(mac, dst_port, description, severity):
    if severity == "CRITICAL":
        cooldown_minutes = CRITICAL_COOLDOWN_MINUTES
    elif severity == "HIGH":
        cooldown_minutes = HIGH_COOLDOWN_MINUTES
    else:
        cooldown_minutes = NORMAL_COOLDOWN_MINUTES

    if cooldown_minutes == 0:
        return False
    cursor = DB_CONN.cursor()
    cooldown_check = f"datetime('now', '-{cooldown_minutes} minutes')"
    query = f"""
        SELECT * FROM alerts 
        WHERE mac = ? AND dst_port = ? AND description = ? AND timestamp > {cooldown_check}
    """
    cursor.execute(query, (mac, dst_port, description))
    return cursor.fetchone() is not None


def analyze_packet_behavior(mac, src_ip, dst_ip, dst_port, protocol):
    now = datetime.now().isoformat()
    was_flagged = False
    if dst_port in INSECURE_PORTS:
        desc = f"Insecure protocol detected: {INSECURE_PORTS[dst_port]} to {dst_ip}"
        if not check_alert_cooldown(mac, dst_port, desc, "CRITICAL"):
            create_alert(mac, src_ip, dst_ip, dst_port, protocol, "CRITICAL", desc)
        was_flagged = True
    elif dst_port in SUSPICIOUS_PORTS:
        desc = f"Suspicious outbound port: {SUSPICIOUS_PORTS[dst_port]} to {dst_ip}"
        if not check_alert_cooldown(mac, dst_port, desc, "HIGH"):
            create_alert(mac, src_ip, dst_ip, dst_port, protocol, "HIGH", desc)
        was_flagged = True
    cursor = DB_CONN.cursor()
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
        if not was_flagged:
            desc = f"New connection detected: {src_ip} -> {dst_ip}:{dst_port} ({protocol})"
            if not check_alert_cooldown(mac, dst_port, desc, "NORMAL"):
                create_alert(mac, src_ip, dst_ip, dst_port, protocol, "NORMAL", desc)


def handle_dns_packet(packet, mac, src_ip):
    if DNSQR in packet and packet[DNSQR].qtype == 1:  # 'A' Record query
        queried_domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        print(f"DNS Query: {src_ip} ({mac}) -> {queried_domain}")
        cursor = DB_CONN.cursor()
        timestamp = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO dns_logs (timestamp, mac, src_ip, queried_domain) VALUES (?, ?, ?, ?)",
            (timestamp, mac, src_ip, queried_domain)
        )
        DB_CONN.commit()
        if queried_domain in MALICIOUS_DOMAINS:
            desc = f"Malicious DNS query detected for: {queried_domain}"
            if not check_alert_cooldown(mac, 53, desc, "CRITICAL"):
                create_alert(mac, src_ip, packet[IP].dst, 53, "DNS", "CRITICAL", desc)


def process_packet(packet):
    try:
        if not (IP in packet and Ether in packet):
            return
        src_mac = packet[Ether].src
        src_ip = packet[IP].src
        if packet.haslayer(DHCP):
            if packet[DHCP].options[0][1] == 3:
                hostname = "Unknown"
                for opt in packet[DHCP].options:
                    if opt[0] == 'hostname':
                        hostname = opt[1].decode('utf-8')
                        break
                handle_device(src_mac, src_ip, hostname=hostname)
                return
        if packet.haslayer(DNS) and packet[UDP].dport == 53 and packet[DNS].qr == 0:
            if src_ip.startswith(YOUR_SUBNET_PREFIX):
                handle_dns_packet(packet, src_mac, src_ip)
            return
        dst_ip = packet[IP].dst
        proto = ""
        dst_port = None
        if TCP in packet:
            proto = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            dst_port = packet[UDP].dport
        if proto and dst_port is not None:
            if src_ip.startswith(YOUR_SUBNET_PREFIX):
                handle_device(src_mac, src_ip)
                analyze_packet_behavior(src_mac, src_ip, dst_ip, dst_port, proto)
            log_line = f"{datetime.now().isoformat()},{proto},{src_ip},{dst_ip},{dst_port}\n"
            try:
                with open(LOG_FILE, "a") as f:
                    f.write(log_line)
            except Exception as e:
                print(f"[!] Error writing to log file: {e}")
    except Exception as e:
        print(f"[!] Error processing packet: {e} -- Packet: {packet.summary()}")


if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write(LOG_HEADER)

    init_db()

    print("=" * 60)
    print("🚀 Network Security Sensor v1.1 - DNS Monitoring Enabled")
    print("=" * 60)
    print(f"📊 Monitoring subnet: {YOUR_SUBNET_PREFIX}*")
    print(f"⏱️  Alert Cooldowns:")
    print(f"   - CRITICAL: {CRITICAL_COOLDOWN_MINUTES} minutes")
    print(f"   - HIGH: {HIGH_COOLDOWN_MINUTES} minutes")
    print(f"   - NORMAL: {NORMAL_COOLDOWN_MINUTES} minutes")
    print(f"💾 Database: {DB_FILE}")
    print(f"📝 Log File: {LOG_FILE}")
    print("=" * 60)
    print("🎯 Monitoring for insecure protocols (Telnet, FTP, etc.)")
    print("📡 Monitoring for DHCP hostnames...")
    print("📖 Monitoring for DNS queries and threats...")
    print("🔍 Press Ctrl+C to stop")
    print("=" * 60)

    try:
        sniff(iface="MediaTek Wi-Fi 6 MT7921 Wireless LAN Card", filter="ip", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n\n[!] Sensor stopped by user. Closing database connection...")
        DB_CONN.close()
        print("✅ Shutdown complete.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] A fatal error occurred: {e}")
        DB_CONN.close()
        sys.exit(1)
