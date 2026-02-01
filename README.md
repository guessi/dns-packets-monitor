# 🔍 DNS Monitor

Real-time DNS traffic monitoring for Windows 10+ with live statistics dashboard.

![Windows 10+](https://img.shields.io/badge/Windows-10%2B-blue) ![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-green)

## ✨ Features

- 📊 Live statistics with auto-updating counters
- 🔝 Top 10 most queried domains
- 🌐 UDP & TCP DNS traffic capture
- 📱 Responsive full-width terminal display
- ⚡ Flicker-free updates (100ms throttling)
- 🕐 UTC timestamps (ISO 8601)

## 🚀 Quick Start

```cmd
# Run as administrator
python main.py
```

## 📸 Sample Output

```
================================================================================
🔍 DNS Traffic Monitor - Press Ctrl+C to stop
📊 Packets: 156  |  Queries: 78  |  Responses: 78  |  UDP: 154  |  TCP: 2
================================================================================
🔝 Top 10 Domains
--------------------------------------------------------------------------------
 github.com                                                                  24
 api.github.com                                                              18
 www.google.com                                                              12
 fonts.googleapis.com                                                         8
 cdn.jsdelivr.net                                                             6
================================================================================
2026-02-23T01:25:54Z 192.168.1.100:54321 → 8.8.8.8:53 DNS/UDP Query github.com A
2026-02-23T01:25:54Z 8.8.8.8:53 ← 192.168.1.100:54321 DNS/UDP Response github.com A NOERROR (1 answers)
...
```

## 📋 Requirements

- Windows 10 or newer
- Python 3.11+
- Administrator privileges

## 🛠️ How It Works

Uses raw sockets to capture DNS traffic on port 53, parses IP/UDP/TCP/DNS headers, and displays real-time statistics with domain tracking.
