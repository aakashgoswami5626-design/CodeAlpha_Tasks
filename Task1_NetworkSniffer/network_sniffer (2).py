from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, ARP
import datetime


def process_packet(packet):
    print("=" * 80)

    # Ethernet Layer
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        print(f"-> Ethernet: {eth_layer.src} -> {eth_layer.dst} | "
              f"Type: {hex(eth_layer.type)}")

    # IPv4 Layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IPv4: {ip_layer.src} -> {ip_layer.dst} | "
              f"Protocol: {ip_layer.proto} | TTL: {ip_layer.ttl}")

    # IPv6 Layer
    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        print(f"IPv6: {ipv6_layer.src} -> {ipv6_layer.dst} | "
              f"Next Header: {ipv6_layer.nh}")

    # TCP Layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"TCP: {tcp_layer.sport} -> {tcp_layer.dport} | "
              f"Flags: {tcp_layer.flags}")

    # UDP Layer
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"UDP: {udp_layer.sport} -> {udp_layer.dport} | "
              f"Length: {udp_layer.len}")

    # ICMP Layer
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print(f"ICMP: Type-{icmp_layer.type} | Code-{icmp_layer.code}")

    # ARP Layer
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        print(f"ARP: {arp_layer.psrc} -> {arp_layer.pdst} | "
              f"Opcode: {arp_layer.op}")

    # Raw Data
    if packet.haslayer("Raw"):
        raw_data = packet["Raw"].load
        print(f"Raw Data: {raw_data}")

    print("=" * 80)


# Start packet capturing
print("Network Sniffer Running........ Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)











