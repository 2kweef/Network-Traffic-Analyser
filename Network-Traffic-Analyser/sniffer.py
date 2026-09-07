from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import datetime

def init_db(db_path = "traffic.db"):
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


def packet_callback(packet):

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        if protocol == "ALL":
            if TCP in packet:
                print(f"TCP |  {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}")
            elif UDP in packet:
                print(f"UDP |  {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}")

        elif protocol == "TCP" and TCP in packet:
            print(f"TCP |  {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}")

        elif protocol == "UDP" and UDP in packet:
            print(f"UDP |  {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}")

try:
    sniff(prn=packet_callback, store=False, timeout=30)
    conn = init_db()
except KeyboardInterrupt:
    pass
    print("\nStopped Capturing.")
