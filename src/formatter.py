#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from src.dns_parser import query_type_name, rcode_name


def format_packet(packet_info):
    header = packet_info["header"]
    timestamp = packet_info["timestamp"]
    protocol = packet_info.get("protocol", "UDP")
    src = f"{packet_info['src_ip']}:{packet_info['src_port']}"
    dst = f"{packet_info['dst_ip']}:{packet_info['dst_port']}"
    direction = "→" if header["qr"] == 0 else "←"

    lines = []
    for question in packet_info["questions"]:
        domain = question["domain"]
        qtype = query_type_name(question["type"])

        if header["qr"] == 0:  # DNS Query
            line = (
                f"{timestamp} {src} {direction} {dst} "
                f"DNS/{protocol} Query {domain} {qtype}"
            )
        else:  # DNS Response
            rcode = rcode_name(header["rcode"])
            answer_count = header["answers"]
            line = (
                f"{timestamp} {src} {direction} {dst} "
                f"DNS/{protocol} Response {domain} {qtype} "
                f"{rcode} ({answer_count} answers)"
            )

        lines.append(line)

    return lines
