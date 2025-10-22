"""Simple network sniffer using scapy.

This script listens for IP packets on a given network interface and prints
basic information (source, destination and protocol) for each captured packet.
"""

from __future__ import annotations

import argparse
import signal
from contextlib import contextmanager
from typing import Iterator, Optional

from scapy.all import IP, sniff  # type: ignore[attr-defined]


PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def resolve_protocol(proto_number: int) -> str:
    """Return the human readable name for a protocol number."""
    return PROTOCOL_NAMES.get(proto_number, str(proto_number))


def format_packet(packet: IP) -> str:
    """Format an IP packet for display."""
    proto_name = resolve_protocol(packet.proto)
    return f"{packet.src:>15} -> {packet.dst:<15} {proto_name}"


def packet_handler(packet) -> None:
    """Print information about an IP packet."""
    if IP not in packet:
        return

    ip_packet: IP = packet[IP]
    print(format_packet(ip_packet))


@contextmanager
def handle_keyboard_interrupt() -> Iterator[None]:
    """Allow the program to exit cleanly on Ctrl+C."""

    def signal_handler(signum: int, frame) -> None:  # type: ignore[override]
        raise KeyboardInterrupt

    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, original_handler)


def sniff_packets(interface: Optional[str], packet_count: Optional[int]) -> None:
    """Start sniffing packets on the given interface."""
    sniff_args = {
        "filter": "ip",
        "prn": packet_handler,
        "store": False,
    }

    if interface:
        sniff_args["iface"] = interface

    if packet_count:
        sniff_args["count"] = packet_count

    sniff(**sniff_args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple IP packet sniffer")
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to listen on (default: scapy chooses automatically)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        help="Number of packets to capture before exiting (default: infinite)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        with handle_keyboard_interrupt():
            sniff_packets(args.interface, args.count)
    except PermissionError:
        print("Permission denied: try running the script with elevated privileges.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
