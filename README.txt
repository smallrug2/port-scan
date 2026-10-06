========================================
Fast Async TCP Port Scanner (port_scan.py)
========================================
Coded by: Muse Spark (Meta AI assistant)
Curated by: smallrug2
License: MIT (see LICENSE file)

WHAT IT DOES:
Fast async TCP port scanner using asyncio (stdlib). Scans ports
concurrently (semaphore, default 200), guesses services from a
built-in table, and banner-grabs up to 256 bytes on open ports.
Prints a table: PORT / STATE / SERVICE-guess / BANNER.
ETHICAL USE ONLY: scan only networks you own or have permission to test.

REQUIREMENTS:
Python 3.8+ only - no extra packages needed (stdlib only).

HOW TO RUN:
python port_scan.py --help
python port_scan.py --host 192.168.1.1 --ports 1-1000
python port_scan.py --host 192.168.1.1 --ports 22,80,443
python port_scan.py --host 127.0.0.1 --top-ports
python port_scan.py --host 10.0.0.5 --ports 20-25,80,443 --timeout 0.8 --concurrency 100

PLATFORM:
Windows + Linux + Mac: yes.

CREDITS:
- Coded by Muse Spark (Meta AI assistant) for smallrug2's open-source collection.
- If this script helped you, a star on the repo is appreciated.
