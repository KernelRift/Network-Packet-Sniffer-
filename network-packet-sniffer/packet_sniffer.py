#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from collections import Counter
import csv
import argparse
from datetime import datetime


protocol_counter = Counter()
captured_packets = []


def get_protocol(packet):
    """Identify the main protocol carried by the packet."""

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(TCP):
        if packet.haslayer(DNS):
            return "DNS/TCP"
        return "TCP"

    if packet.haslayer(UDP):
        if packet.haslayer(DNS):
            return "DNS/UDP"
        return "UDP"

    return "Other"


def get_payload_preview(packet):
    """Return a safe, readable preview of packet payload."""

    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)

        preview = raw_data[:40]

        return preview.hex(" ")

    return "-"


def analyze_packet(packet):
    """Extract useful information from a captured packet."""

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = get_protocol(packet)

    src_port = "-"
    dst_port = "-"

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    packet_size = len(packet)

    payload = get_payload_preview(packet)

    dns_query = "-"

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            dns_query = packet[DNSQR].qname.decode(errors="replace")
        except Exception:
            dns_query = "-"

    packet_info = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": src_ip,
        "destination": dst_ip,
        "protocol": protocol,
        "source_port": src_port,
        "destination_port": dst_port,
        "size": packet_size,
        "dns_query": dns_query,
        "payload": payload
    }

    captured_packets.append(packet_info)
    protocol_counter[protocol] += 1

    number = len(captured_packets)

    print(
        f"{number:<5}"
        f"{src_ip:<18}"
        f"{dst_ip:<18}"
        f"{protocol:<12}"
        f"{str(src_port):<8}"
        f"{str(dst_port):<8}"
        f"{packet_size:<8}"
    )


def save_to_csv(filename):
    """Save captured packet information to CSV."""

    if not captured_packets:
        return

    fieldnames = captured_packets[0].keys()

    with open(filename, "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(captured_packets)

    print(f"\n[+] Packet data saved to: {filename}")


def show_summary():
    """Display packet capture statistics."""

    print("\n" + "=" * 75)
    print("PACKET CAPTURE SUMMARY")
    print("=" * 75)

    print(f"Total packets captured: {len(captured_packets)}")

    print("\nProtocol statistics:")

    for protocol, count in protocol_counter.most_common():
        print(f"  {protocol:<15} {count}")

    print("=" * 75)


def main():
    parser = argparse.ArgumentParser(
        description="Python Network Packet Sniffer using Scapy"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to sniff on"
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=20,
        help="Number of packets to capture (default: 20)"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="captured_packets.csv",
        help="CSV output filename"
    )

    args = parser.parse_args()

    print("=" * 75)
    print("              PYTHON NETWORK PACKET SNIFFER")
    print("=" * 75)

    print(f"Packets to capture : {args.count}")
    print(f"Output file        : {args.output}")

    if args.interface:
        print(f"Interface          : {args.interface}")
    else:
        print("Interface          : Default")

    print("=" * 75)

    print(
        f"{'No.':<5}"
        f"{'Source IP':<18}"
        f"{'Destination IP':<18}"
        f"{'Protocol':<12}"
        f"{'Src':<8}"
        f"{'Dst':<8}"
        f"{'Size':<8}"
    )

    print("-" * 75)

    try:
        sniff(
            iface=args.interface,
            prn=analyze_packet,
            count=args.count,
            store=False
        )

    except PermissionError:
        print("\n[!] Permission denied.")
        print("[!] Run the program with appropriate packet-capture privileges.")

        return

    except Exception as error:
        print(f"\n[!] Error: {error}")
        return

    save_to_csv(args.output)
    show_summary()


if __name__ == "__main__":
    main()
