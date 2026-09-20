from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import datetime


def init_db(db_path="traffic.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        protocol TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dst_ip TEXT,
        dst_port INTEGER)
        """)
    conn.commit()
    return conn


print("Enter protocol to sniff (TCP/UDP or ALL): ")
protocol = input().strip().upper()


def extract_packet_info(packet):
    if IP not in packet:
        return None

    src = packet[IP].src
    dst = packet[IP].dst

    if TCP in packet:
        return {
            "protocol": "TCP",
            "src": src,
            "src_port": packet[TCP].sport,
            "dst": dst,
            "dst_port": packet[TCP].dport,
        }
    elif UDP in packet:
        return {
            "protocol": "UDP",
            "src": src,
            "src_port": packet[UDP].sport,
            "dst": dst,
            "dst_port": packet[UDP].dport,
        }
    return None


def display_packet(info):
    print(
        f"{info['protocol']} | {info['src']}:{info['src_port']} -> {info['dst']}:{info['dst_port']}"
    )


def save_packet(info, conn):
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO packets (timestamp, protocol, src_ip, src_port, dst_ip, dst_port) VALUES (?, ?, ?, ?, ?, ?)",
        (
            datetime.datetime.now(),
            info["protocol"],
            info["src"],
            info["src_port"],
            info["dst"],
            info["dst_port"],
        ),
    )
    conn.commit()


def view_packets(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM packets")
    rows = cursor.fetchall()
    for row in rows:
        print(row)


def frequent_packets(conn):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT src_ip, COUNT(*) FROM packets GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5
    """)
    rows = cursor.fetchall()
    for row in rows:
        print(row)


def filter_by_ip(conn, ip):
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM packets WHERE src_ip = ? OR dst_ip = ?""", (ip, ip))
    rows = cursor.fetchall()
    for row in rows:
        print(row)


def packet_callback(packet):
    info = extract_packet_info(packet)
    if info is not None:
        save_packet(info, conn)

        if info["protocol"] == "TCP":
            if protocol == "TCP" or protocol == "ALL":
                display_packet(info)

        if info["protocol"] == "UDP":
            if protocol == "UDP" or protocol == "ALL":
                display_packet(info)


conn = init_db()


try:
    sniff(prn=packet_callback, store=False, timeout=30)
except KeyboardInterrupt:
    pass

print("\nStopped Capturing.")

view_packets(conn)
frequent_packets(conn)
target_ip = input("Enter IP to filter: ").strip()
filter_by_ip(conn, target_ip)
