from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    print("\n" + "=" * 70)
    print(f"Packet Number : {packet_count}")
    print(f"Time          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if packet.haslayer(IP):
        ip = packet[IP]

        print(f"Source IP     : {ip.src}")
        print(f"Destination IP: {ip.dst}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol      : TCP")
            print(f"Source Port   : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol      : UDP")
            print(f"Source Port   : {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        elif packet.haslayer(ICMP):
            print("Protocol      : ICMP")

        else:
            print(f"Protocol      : {ip.proto}")

        try:
            payload = bytes(packet.payload)
            if payload:
                print(f"Payload Preview: {payload[:100]}")
        except:
            pass

print("Network Sniffer Started...")
print("Press CTRL + C to Stop")

sniff(prn=packet_callback, store=False)
