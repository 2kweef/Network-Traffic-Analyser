from scapy.all import sniff, IP, TCP, UDP

print("Enter protocol to sniff (TCP/UDP or ALL): ")
protocol = input().strip().upper

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto    
    
    if TCP in packet:
        print(f"TCP |  {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}")
    elif UDP in packet:
        print(f"UDP |  {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}")

sniff(count=20, prn=packet_callback)