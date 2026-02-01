#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from datetime import datetime, timezone

QUERY_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}

RESPONSE_CODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DNS_HEADER_SIZE = 12
MAX_DOMAIN_JUMPS = 5
COMPRESSION_MASK = 0xC0
POINTER_MASK = 0x3FFF


def parse_domain_name(data, offset):
    try:
        domain_parts = []
        original_offset = offset
        jumped = False
        jumps = 0

        while offset < len(data) and jumps < MAX_DOMAIN_JUMPS:
            length = data[offset]

            if length == 0:  # End of domain name
                offset += 1
                break
            elif length & COMPRESSION_MASK:  # Compressed pointer
                if not jumped:
                    original_offset = offset + 2
                pointer = (
                    struct.unpack("!H", data[offset:offset + 2])[0] & POINTER_MASK
                )
                offset = pointer
                jumped = True
                jumps += 1
            else:  # Regular label
                if offset + length + 1 > len(data):
                    break
                try:
                    label = data[offset + 1:offset + 1 + length].decode(
                        "ascii", errors="ignore"
                    )
                    domain_parts.append(label)
                except Exception:
                    domain_parts.append(f"<binary-{length}>")
                offset += length + 1

        domain = ".".join(domain_parts) if domain_parts else "unknown"
        final_offset = original_offset if jumped else offset
        return domain, final_offset
    except Exception:
        return "parse_error", offset + 1


def parse_dns_header(data):
    if len(data) < DNS_HEADER_SIZE:
        return None

    try:
        # DNS Header format (12 bytes)
        # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        #                                     1  1  1  1  1  1
        #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #     |                      ID                       |
        #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #     |                    QDCOUNT                    |
        #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #     |                    ANCOUNT                    |
        #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #     |                    NSCOUNT                    |
        #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #     |                    ARCOUNT                    |
        #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        dns_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", data[:DNS_HEADER_SIZE]
        )

        # Extract bit fields from flags (16 bits)
        qr = (flags >> 15) & 0x1  # bit 15: Query (0) or Response (1)
        opcode = (flags >> 11) & 0xF  # bits 11-14: Operation code
        rcode = flags & 0xF  # bits 0-3: Response code

        return {
            "id": dns_id,
            "qr": qr,
            "opcode": opcode,
            "rcode": rcode,
            "questions": qdcount,
            "answers": ancount,
            "authority": nscount,
            "additional": arcount,
        }
    except Exception:
        return None


def parse_dns_question(data, offset):
    try:
        domain, new_offset = parse_domain_name(data, offset)

        if new_offset + 4 <= len(data):
            # DNS Question section (after domain name):
            # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
            # +----------------+----------------+
            # |     QTYPE      |     QCLASS     |
            # |   (2 bytes)    |   (2 bytes)    |
            # +----------------+----------------+
            qtype, qclass = struct.unpack("!HH", data[new_offset:new_offset + 4])
            new_offset += 4
        else:
            qtype, qclass = 0, 0

        return domain, qtype, qclass, new_offset
    except Exception:
        return "parse_error", 0, 0, offset + 1


def query_type_name(qtype):
    return QUERY_TYPES.get(qtype, f"TYPE{qtype}")


def rcode_name(rcode):
    return RESPONSE_CODES.get(rcode, f"RCODE{rcode}")


def parse_dns_packet(data, src_ip, dst_ip, src_port, dst_port):
    header = parse_dns_header(data)
    if not header:
        return None

    packet_info = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "header": header,
        "questions": [],
    }

    offset = DNS_HEADER_SIZE
    for i in range(header["questions"]):
        if offset >= len(data):
            break

        domain, qtype, qclass, offset = parse_dns_question(data, offset)
        packet_info["questions"].append(
            {"domain": domain, "type": qtype, "class": qclass}
        )

    return packet_info
