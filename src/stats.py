#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class Statistics:

    def __init__(self):
        self.packet_count = 0
        self.query_count = 0
        self.response_count = 0
        self.udp_count = 0
        self.tcp_count = 0
        self.domain_stats = {}

    def add_packet(self, protocol="UDP"):
        self.packet_count += 1
        if protocol == "UDP":
            self.udp_count += 1
        elif protocol == "TCP":
            self.tcp_count += 1

    def add_query(self):
        self.query_count += 1

    def add_response(self):
        self.response_count += 1

    def add_domain(self, domain):
        if self._is_valid_domain(domain):
            self.domain_stats[domain] = self.domain_stats.get(domain, 0) + 1

    def _is_valid_domain(self, domain):
        return domain not in ["parse_error", "unknown"]

    def print(self):
        """Print final statistics summary"""
        print("\n📊 DNS Traffic Statistics:")
        print(f"   Total packets captured: {self.packet_count}")
        print(f"   DNS queries: {self.query_count}")
        print(f"   DNS responses: {self.response_count}")
        print(f"   UDP packets: {self.udp_count}")
        print(f"   TCP packets: {self.tcp_count}")

        if self.domain_stats:
            self._print_top_domains()

    def _print_top_domains(self):
        print("\n🔝 Most queried domains:")
        sorted_domains = sorted(
            self.domain_stats.items(), key=lambda x: x[1], reverse=True
        )

        for domain, count in sorted_domains[:10]:
            if self._is_valid_domain(domain):
                print(f"   {domain:<40} - {count} times")
