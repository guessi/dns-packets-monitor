#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import platform
import signal

from src.socket_handler import SocketHandler
from src.ip_parser import parse_ip_packet
from src.dns_parser import parse_dns_packet
from src.stats import Statistics
from src.formatter import format_packet
from src.display import Display

os.environ["PYTHONIOENCODING"] = "utf-8"

running = True
stats = Statistics()
socket_handler = SocketHandler()
display = Display()


def stop_monitoring(signum, frame):
    global running
    running = False


def process_packet(data):
    parsed = parse_ip_packet(data)
    if not parsed:
        return

    protocol = parsed.get("protocol", "UDP")
    stats.add_packet(protocol)

    packet_info = parse_dns_packet(
        parsed["dns_data"],
        parsed["src_ip"],
        parsed["dst_ip"],
        parsed["src_port"],
        parsed["dst_port"],
    )

    if not packet_info:
        return

    # Add protocol info to packet_info for formatting
    packet_info["protocol"] = protocol

    header = packet_info["header"]
    if header["qr"] == 0:  # Query
        stats.add_query()
        for question in packet_info["questions"]:
            stats.add_domain(question["domain"])
    else:  # Response
        stats.add_response()

    # Format packet and add to display
    lines = format_packet(packet_info)
    for line in lines:
        display.add_packet_line(line)

    # Update display
    display.update(stats)


def monitor_dns():
    print("Creating raw socket (requires admin privileges)...")

    sock = socket_handler.create()
    if not sock:
        print(f"\n❌ Failed: {socket_handler.error}")
        print("💡 Make sure you're running as administrator.")
        input("Press Enter to exit...")
        return False

    # Clear screen and show initial display
    display.clear_screen()
    display.update(stats)

    try:
        while running:
            result = socket_handler.receive(timeout=0.1)
            if result:
                data, _ = result
                process_packet(data)

    except KeyboardInterrupt:
        pass
    finally:
        socket_handler.close()

    return True


def main():
    print("=" * 80)
    print("🔍 Windows DNS Raw Socket Monitor")
    print("=" * 80)
    print("Windows 10+ | Administrator privileges required\n")

    signal.signal(signal.SIGINT, stop_monitoring)

    if platform.system() != "Windows":
        print("❌ This tool requires Windows 10 or newer")
        input("Press Enter to exit...")
        return

    try:
        if monitor_dns():
            # Show final stats
            print("\n")
            stats.print()
        else:
            print("\n⚠️  Raw socket monitoring failed")
    except Exception as e:
        print(f"\n⚠️  Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
