#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import select


class SocketHandler:

    def __init__(self):
        self.sock = None
        self.error = None

    def create(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            local_ip = socket.gethostbyname(socket.gethostname())
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self.sock = sock
            return sock
        except Exception as e:
            self.error = str(e)
            return None

    def receive(self, timeout=2.0):
        if not self.sock:
            return None

        try:
            ready = select.select([self.sock], [], [], timeout)
            if ready[0]:
                return self.sock.recvfrom(65535)
        except Exception:
            pass

        return None

    def close(self):
        if not self.sock:
            return

        try:
            if hasattr(self.sock, "ioctl"):
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass

        try:
            self.sock.close()
        except Exception:
            pass

        self.sock = None
