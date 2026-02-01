#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct

UDP_PROTOCOL = 17
TCP_PROTOCOL = 6
DNS_PORT = 53
MIN_IP_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8
TCP_HEADER_SIZE = 20
MIN_DNS_SIZE = 12


def parse_ip_packet(data):
    # Raw socket packet structure (received from network):
    # +----------------+------------------+------------------+
    # |   IP Header    | Transport Header | Application Data |
    # |  (20+ bytes)   | (UDP=8, TCP=20+) |  (DNS payload)   |
    # +----------------+------------------+------------------+
    # ^                  ^                  ^
    # offset=0           offset=IP_len      offset=IP_len+Transport_len
    #
    # Parsing requires calculating offsets to locate each layer:
    # 1. IP header starts at byte 0
    # 2. Transport header starts at byte (IP header length)
    # 3. DNS data starts at byte (IP header length + Transport header length)

    if len(data) < MIN_IP_HEADER_SIZE:
        return None

    try:
        # IP Header (20 bytes minimum)
        # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |Version|  IHL  |Type of Service|          Total Length         |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |         Identification        |Flags|      Fragment Offset    |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  Time to Live |    Protocol   |         Header Checksum       |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                       Source Address                          |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                    Destination Address                        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        (
            version_ihl,
            tos,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            src_addr,
            dst_addr,
        ) = struct.unpack("!BBHHHBBH4s4s", data[:20])
        header_length = (version_ihl & 0xF) * 4
        src_ip = socket.inet_ntoa(src_addr)
        dst_ip = socket.inet_ntoa(dst_addr)
    except Exception:
        return None

    # Process both UDP and TCP packets
    if protocol == UDP_PROTOCOL:
        return parse_udp_dns(data, header_length, src_ip, dst_ip)
    elif protocol == TCP_PROTOCOL:
        return parse_tcp_dns(data, header_length, src_ip, dst_ip)
    else:
        return None


def parse_udp_dns(data, ip_header_length, src_ip, dst_ip):
    # UDP packet layout in raw socket data:
    # +----------------+----------------+----------------+
    # |   IP Header    |   UDP Header   |    DNS Data    |
    # |   (20 bytes)   |   (8 bytes)    |   (variable)   |
    # +----------------+----------------+----------------+
    # data[0:20]         data[20:28]        data[28:]
    #                    ^                  ^
    #                    udp_start          dns_start
    #
    # udp_start = ip_header_length (usually 20, but can be larger with IP options)
    # dns_start = ip_header_length + UDP_HEADER_SIZE (8 bytes)

    if len(data) < ip_header_length + UDP_HEADER_SIZE:
        return None

    try:
        udp_start = ip_header_length
        # UDP Header (8 bytes)
        # https://datatracker.ietf.org/doc/html/rfc768
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |          Source Port          |       Destination Port        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |            Length             |           Checksum            |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        src_port, dst_port, length, checksum = struct.unpack(
            "!HHHH", data[udp_start:udp_start + UDP_HEADER_SIZE]
        )
    except Exception:
        return None

    # Only process DNS traffic (port 53)
    if src_port != DNS_PORT and dst_port != DNS_PORT:
        return None

    dns_data = data[ip_header_length + UDP_HEADER_SIZE:]
    if len(dns_data) < MIN_DNS_SIZE:
        return None

    return {
        "protocol": "UDP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "dns_data": dns_data,
    }


def parse_tcp_dns(data, ip_header_length, src_ip, dst_ip):
    # TCP packet layout in raw socket data:
    # +----------------+----------------+----------+----------------+
    # |   IP Header    |   TCP Header   |  Length  |    DNS Data    |
    # |   (20 bytes)   |  (20+ bytes)   | (2 bytes)|   (variable)   |
    # +----------------+----------------+----------+----------------+
    # data[0:20]         data[20:40+]       data[X:X+2] data[X+2:]
    #                    ^                  ^
    #                    tcp_start          dns_length_start
    #
    # tcp_start = ip_header_length
    # TCP header length is variable (20-60 bytes) due to options
    # data_offset field (byte 12) tells us actual TCP header length
    # DNS over TCP prepends 2-byte length field before DNS message

    if len(data) < ip_header_length + TCP_HEADER_SIZE:
        return None

    try:
        tcp_start = ip_header_length
        # TCP Header (20 bytes minimum)
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.1
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |          Source Port          |       Destination Port        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                        Sequence Number                        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                    Acknowledgment Number                      |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  Data |           |U|A|P|R|S|F|                               |
        # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        # |       |           |G|K|H|T|N|N|                               |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |           Checksum            |         Urgent Pointer        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        (
            src_port,
            dst_port,
            seq_num,
            ack_num,
            offset_flags,
            flags,
            window,
            checksum,
            urgent,
        ) = struct.unpack("!HHLLBBHHH", data[tcp_start:tcp_start + TCP_HEADER_SIZE])
        data_offset = (offset_flags >> 4) * 4  # TCP header length
    except Exception:
        return None

    # Only process DNS traffic (port 53)
    if src_port != DNS_PORT and dst_port != DNS_PORT:
        return None

    # TCP DNS messages are prefixed with a 2-byte length field
    tcp_data_start = ip_header_length + data_offset
    if len(data) < tcp_data_start + 2:
        return None

    try:
        # Read the length prefix
        dns_length = struct.unpack("!H", data[tcp_data_start:tcp_data_start + 2])[0]
        dns_data = data[tcp_data_start + 2:tcp_data_start + 2 + dns_length]

        if len(dns_data) < MIN_DNS_SIZE:
            return None
    except Exception:
        return None

    return {
        "protocol": "TCP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "dns_data": dns_data,
    }
