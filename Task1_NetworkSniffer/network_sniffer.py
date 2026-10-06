import argparse
import sys
import time
from datetime import datetime

from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP, sniff
from scapy.arch import get_if_addr, get_if_list
from scapy.packet import NoPayload


def get_capture_interface():
    for interface in get_if_list():
        if "Loopback" in interface:
            continue
        try:
            address = get_if_addr(interface)
            if address and address != "0.0.0.0":
                return interface
        except Exception:
            pass
    return None


def list_interfaces():
    for interface in get_if_list():
        try:
            address = get_if_addr(interface)
        except Exception:
            address = "unknown"
        print(f"{interface}  IPv4={address}")


def format_payload(packet, max_bytes):
    if packet.haslayer(TCP):
        payload = packet[TCP].payload
    elif packet.haslayer(UDP):
        payload = packet[UDP].payload
    elif packet.haslayer(ICMP):
        payload = packet[ICMP].payload
    elif packet.haslayer(IP):
        payload = packet[IP].payload
    elif packet.haslayer(IPv6):
        payload = packet[IPv6].payload
    else:
        return "<empty>"

    if isinstance(payload, NoPayload):
        return "<empty>"

    data = bytes(payload)
    if not data:
        return "<empty>"
    if max_bytes == 0:
        return f"<{len(data)} bytes hidden>"

    preview = data[:max_bytes]
    printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in preview)
    suffix = "..." if len(data) > max_bytes else ""
    return f"{len(data)} bytes; hex={preview.hex(' ')}; ascii={printable!r}{suffix}"


def get_payload_bytes(packet):
    if packet.haslayer(TCP):
        payload = packet[TCP].payload
    elif packet.haslayer(UDP):
        payload = packet[UDP].payload
    elif packet.haslayer(ICMP):
        payload = packet[ICMP].payload
    elif packet.haslayer(IP):
        payload = packet[IP].payload
    elif packet.haslayer(IPv6):
        payload = packet[IPv6].payload
    else:
        return b""

    if isinstance(payload, NoPayload):
        return b""
    return bytes(payload)


def get_application_protocol(packet, payload):
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(UDP) and {packet[UDP].sport, packet[UDP].dport} & {546, 547}:
        return "DHCPv6"
    if packet.haslayer(TCP) and len(payload) >= 5 and payload[1] == 3:
        if payload[0] in {20, 21, 22, 23}:
            return "TLS"
    if packet.haslayer(IP) and packet[IP].proto == 2:
        return "IGMP"
    return None


def get_protocol_stack(packet, application_protocol):
    layers = []
    if packet.haslayer(Ether):
        layers.append("Ethernet")

    if packet.haslayer(ARP):
        layers.append("ARP")
    elif packet.haslayer(IP):
        layers.append("IPv4")
    elif packet.haslayer(IPv6):
        layers.append("IPv6")

    if packet.haslayer(TCP):
        layers.append("TCP")
    elif packet.haslayer(UDP):
        layers.append("UDP")
    elif packet.haslayer(ICMP):
        layers.append("ICMP")
    elif packet.haslayer(IPv6) and packet[IPv6].nh == 58:
        layers.append("ICMPv6")
    elif packet.haslayer(IP) and packet[IP].proto == 2:
        layers.append("IGMP")

    if application_protocol and application_protocol not in layers:
        layers.append(application_protocol)
    return " > ".join(layers) or packet.lastlayer().name


def get_endpoints(packet):
    source = "unknown"
    destination = "unknown"
    source_port = None
    destination_port = None

    if packet.haslayer(ARP):
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
    elif packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst
    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    if source_port is not None:
        source = f"[{source}]:{source_port}" if ":" in source else f"{source}:{source_port}"
        destination = (
            f"[{destination}]:{destination_port}"
            if ":" in destination
            else f"{destination}:{destination_port}"
        )

    return source, destination


def describe_packet(packet, payload):
    details = []

    if packet.haslayer(IP):
        ip_packet = packet[IP]
        details.append(f"IPv4 TTL={ip_packet.ttl}, packet ID={ip_packet.id}")
    elif packet.haslayer(IPv6):
        details.append(f"IPv6 hop limit={packet[IPv6].hlim}")

    if packet.haslayer(Ether):
        details.append(f"Ethernet {packet[Ether].src} -> {packet[Ether].dst}")

    if packet.haslayer(TCP):
        tcp_packet = packet[TCP]
        flags = str(tcp_packet.flags)
        flag_meanings = {
            "S": "starts a connection",
            "A": "acknowledges received data",
            "P": "carries pushed application data",
            "F": "closes a connection",
            "R": "resets a connection",
        }
        meanings = [meaning for flag, meaning in flag_meanings.items() if flag in flags]
        meaning_text = ", ".join(meanings) if meanings else "no common control flags"
        details.append(
            f"TCP flags={flags} ({meaning_text}); sequence={tcp_packet.seq}, "
            f"ack={tcp_packet.ack}, window={tcp_packet.window}"
        )
    elif packet.haslayer(UDP):
        details.append(f"UDP datagram length={packet[UDP].len or 'unknown'} bytes")
    elif packet.haslayer(ICMP):
        icmp_packet = packet[ICMP]
        icmp_meanings = {0: "echo reply", 3: "destination unreachable", 8: "echo request", 11: "time exceeded"}
        meaning = icmp_meanings.get(icmp_packet.type, "ICMP message")
        details.append(f"ICMP {meaning}; type={icmp_packet.type}, code={icmp_packet.code}")

    if packet.haslayer(ARP):
        arp_packet = packet[ARP]
        operation = {1: "who-has request", 2: "address reply"}.get(arp_packet.op, "message")
        details.append(f"ARP {operation}; hardware address={arp_packet.hwsrc}")

    if packet.haslayer(DNS):
        dns_packet = packet[DNS]
        question = dns_packet.qd
        if question:
            name = question.qname.decode("utf-8", errors="replace").rstrip(".")
            query_types = {1: "A (IPv4)", 28: "AAAA (IPv6)", 5: "CNAME", 12: "PTR", 16: "TXT"}
            query_type = query_types.get(question.qtype, f"type {question.qtype}")
            direction = "response" if dns_packet.qr else "query"
            details.append(f"DNS {direction}: {name} ({query_type})")

        answer_count = int(dns_packet.ancount or 0)
        if dns_packet.qr:
            details.append(f"DNS result code={dns_packet.rcode}; answers={answer_count}")
            answer_record = dns_packet.an
            for _ in range(min(answer_count, 8)):
                if isinstance(answer_record, NoPayload):
                    break
                record_name = getattr(answer_record, "rrname", b"?")
                if isinstance(record_name, bytes):
                    record_name = record_name.decode("utf-8", errors="replace").rstrip(".")
                record_type = getattr(answer_record, "type", None)
                record_data = getattr(answer_record, "rdata", None)
                details.append(f"DNS answer: {record_name} -> {record_data} (type {record_type})")
                answer_record = answer_record.payload

    application_protocol = get_application_protocol(packet, payload)
    if application_protocol == "DHCPv6" and payload:
        message_types = {1: "Solicit", 2: "Advertise", 3: "Request", 7: "Reply", 11: "Information-request"}
        message_type = message_types.get(payload[0], f"message type {payload[0]}")
        details.append(f"DHCPv6 {message_type}")
    elif application_protocol == "TLS" and len(payload) >= 5:
        record_types = {20: "change cipher spec", 21: "alert", 22: "handshake", 23: "encrypted application data"}
        record_type = record_types.get(payload[0], "TLS record")
        record_length = int.from_bytes(payload[3:5], "big")
        details.append(f"TLS {record_type}; record version=0x{payload[1:3].hex()}, record length={record_length} bytes")
        if payload[0] == 23:
            details.append("TLS application contents are encrypted and cannot be read here")
    elif application_protocol == "IGMP":
        igmp_type = payload[0] if payload else None
        meaning = "membership report" if igmp_type == 0x22 else "multicast control message"
        details.append(f"IGMP {meaning}; message type=0x{igmp_type:02x}" if igmp_type is not None else "IGMP message")

    if packet.haslayer(TCP) and not payload:
        details.append("No TCP application payload; this is typically a control or acknowledgement packet")

    return details, application_protocol


def format_packet(packet, index, payload_bytes):
    payload = get_payload_bytes(packet)
    source, destination = get_endpoints(packet)
    details, application_protocol = describe_packet(packet, payload)
    protocol_stack = get_protocol_stack(packet, application_protocol)
    timestamp = datetime.fromtimestamp(float(getattr(packet, "time", time.time()))).strftime("%H:%M:%S.%f")[:-3]

    lines = [
        f"[{index:05d}] {timestamp}  {source} -> {destination}",
        f"  Protocol: {protocol_stack} | frame size: {len(packet)} bytes",
    ]
    lines.extend(f"  {detail}" for detail in details)
    lines.append(f"  Payload preview: {format_payload(packet, payload_bytes)}")
    return "\n".join(lines)


packet_count = 0


def show_packet(packet, payload_bytes=48):
    global packet_count
    packet_count += 1
    print(format_packet(packet, packet_count, payload_bytes), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Capture and inspect network packets.")
    parser.add_argument("-i", "--interface", help="interface to capture on")
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="packets to capture; use 0 to scan continuously until interrupted (default)",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=48,
        help="maximum payload bytes shown per packet (default: 48)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="list available interfaces and exit",
    )
    args = parser.parse_args(argv)

    if args.list_interfaces:
        list_interfaces()
        return 0

    if args.count < 0 or args.payload_bytes < 0:
        parser.error("--count and --payload-bytes must be zero or greater")

    interface = args.interface or get_capture_interface()
    if interface is None:
        print("No usable network interface found. Try --list-interfaces.", file=sys.stderr)
        return 1

    global packet_count
    packet_count = 0
    capture_limit = "continuously" if args.count == 0 else f"up to {args.count} packets"
    print(f"Live capture on {interface} ({capture_limit}); press Ctrl+C to stop.", flush=True)
    try:
        sniff(
            iface=interface,
            prn=lambda packet: show_packet(packet, args.payload_bytes),
            store=False,
            count=args.count,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except (OSError, PermissionError) as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 1

    print(f"Captured {packet_count} packets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

