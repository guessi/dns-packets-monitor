#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import time
from collections import deque


class Display:
    def __init__(self):
        self.packet_lines = deque(maxlen=200)
        self.last_update = 0
        self.update_interval = 0.1

        # Enable VT100 mode on Windows 10+
        if sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass

    def get_terminal_size(self):
        """Get current terminal width and height"""
        try:
            size = shutil.get_terminal_size()
            return size.columns, size.lines
        except Exception:
            return 120, 30

    def add_packet_line(self, line):
        """Add a packet line to the display buffer"""
        self.packet_lines.append(line)

    def clear_screen(self):
        """Clear the screen"""
        if sys.platform == "win32":
            os.system('cls')
        else:
            os.system('clear')

    def update(self, stats, force=False):
        """Update the entire display"""
        current_time = time.time()
        if not force and (current_time - self.last_update) < self.update_interval:
            return

        self.last_update = current_time

        width, height = self.get_terminal_size()

        # Calculate dynamic layout
        fixed_lines = 18
        packet_display_lines = max(5, height - fixed_lines)

        # Move cursor to home position
        sys.stdout.write("\033[H")

        # Build the entire screen content
        lines = []

        # Header
        lines.append("=" * width)
        lines.append("🔍 DNS Traffic Monitor - Press Ctrl+C to stop")

        # Live statistics
        stats_line = (
            f"📊 Packets: {stats.packet_count}  |  "
            f"Queries: {stats.query_count}  |  "
            f"Responses: {stats.response_count}  |  "
            f"UDP: {stats.udp_count}  |  TCP: {stats.tcp_count}"
        )
        lines.append(stats_line[:width] if len(stats_line) > width else stats_line)
        lines.append("=" * width)

        # Top domains panel
        lines.append("🔝 Top 10 Domains")
        lines.append("-" * width)

        # Top 10 domains
        sorted_domains = sorted(
            stats.domain_stats.items(), key=lambda x: x[1], reverse=True
        )

        for i in range(10):
            if i < len(sorted_domains):
                domain, count = sorted_domains[i]
                if domain not in ["parse_error", "unknown"]:
                    domain_width = width - 10
                    domain_display = (
                        domain[:domain_width]
                        if len(domain) > domain_width
                        else domain
                    )
                    line = (
                        f" {domain_display.ljust(domain_width)} "
                        f"{str(count).rjust(5)}"
                    )
                    lines.append(line[:width] if len(line) > width else line)
                else:
                    lines.append("")
            else:
                lines.append("")

        lines.append("=" * width)

        # Packet area
        packet_list = list(self.packet_lines)
        start_idx = max(0, len(packet_list) - packet_display_lines)
        displayed_packets = packet_list[start_idx:]

        for line in displayed_packets:
            lines.append(line[:width] if len(line) > width else line)

        # Fill remaining packet lines with empty lines
        for _ in range(packet_display_lines - len(displayed_packets)):
            lines.append("")

        # Clear screen from cursor and print all lines
        sys.stdout.write("\033[J")
        for line in lines:
            sys.stdout.write(line + "\033[K\n")
        sys.stdout.flush()
