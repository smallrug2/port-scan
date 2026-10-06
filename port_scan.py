"""Fast async TCP port scanner (asyncio, stdlib only).

Scans TCP ports on a host concurrently, guesses services from a
built-in table, and banner-grabs up to 256 bytes on open ports.

ETHICAL USE ONLY: scan only hosts/networks you own or have explicit
written permission to test. Unauthorized scanning may be illegal or
violate provider terms. The author assumes no liability for misuse.

Usage examples:
    python port_scan.py --host 192.168.1.1 --ports 1-1000
    python port_scan.py --host example.com --ports 22,80,443
    python port_scan.py --host 127.0.0.1 --top-ports
    python port_scan.py --host 10.0.0.5 --ports 20-25,80,443 --timeout 0.8 --concurrency 100

Platform notes:
    Windows + Linux + macOS. Pure asyncio (stdlib); no raw sockets so
    no admin/root needed. On Windows the default ProactorEventLoop
    supports asyncio.open_connection; on Linux/macOS the SelectorEventLoop
    is used. Ctrl+C aborts cleanly on all three.

Dependencies:
    Standard library only (argparse, asyncio, socket, sys).
"""

import argparse
import asyncio
import socket
import sys

# Small built-in guess table for common TCP ports.
SERVICE_GUESS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-sub",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "OracleDB",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "Postgres",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}

# Default preset scanned with --top-ports (25 common ports).
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 587, 993, 995, 1433, 1723, 3306, 3389,
    5432, 5900, 6379, 8080, 8443,
]

BANNER_BYTES = 256
BANNER_TIMEOUT = 1.0  # short extra wait for banner after connect


def parse_ports(spec):
    """Parse '22,80,443' / '1-1000' / '20-25,80' into a sorted port list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
            except ValueError:
                raise ValueError("bad range %r (use LO-HI, e.g. 1-1000)" % part)
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError("ports must be 1-65535 (got %r)" % part)
            if lo > hi:
                raise ValueError("range start > end in %r" % part)
            if hi - lo > 65535:
                raise ValueError("range too large: %r" % part)
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError("bad port %r (must be 1-65535)" % part)
            if not 1 <= p <= 65535:
                raise ValueError("port out of range 1-65535: %d" % p)
            ports.add(p)
    if not ports:
        raise ValueError("no ports parsed from %r" % spec)
    if len(ports) > 65535:
        raise ValueError("too many ports requested")
    return sorted(ports)


def clean_banner(raw):
    """Decode bytes to printable-safe short string for table display."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return ""
    # Keep printable chars; fold the rest to '.' so table stays readable.
    out = "".join(c if (c.isprintable() or c in (" ", "\t")) else "." for c in text)
    out = " ".join(out.split())  # collapse whitespace/newlines
    return out[:80]


async def scan_one(host, port, timeout, sem):
    """Try TCP connect; on success grab banner. Returns (port, open, banner)."""
    async with sem:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (port, False, "")  # closed/filtered/unreachable
        except Exception:
            return (port, False, "")
        try:
            try:
                data = await asyncio.wait_for(
                    reader.read(BANNER_BYTES), timeout=min(timeout, BANNER_TIMEOUT)
                )
                banner = clean_banner(data) if data else ""
            except (asyncio.TimeoutError, OSError):
                banner = ""
            return (port, True, banner)
        finally:
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass


async def run_scan(host, ports, timeout, concurrency):
    """Scan all ports with bounded concurrency; returns list of results."""
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_one(host, p, timeout, sem) for p in ports]
    return list(await asyncio.gather(*tasks))


def build_parser():
    p = argparse.ArgumentParser(
        description="Fast async TCP port scanner. ETHICAL USE ONLY: scan only "
                    "networks you own or have permission to test."
    )
    p.add_argument("--host", required=True, help="Target hostname or IP address.")
    p.add_argument("--ports", default=None,
                   help="Ports to scan: '1-1000' and/or comma list '22,80,443' "
                        "(e.g. '20-25,80,443'). Required unless --top-ports.")
    p.add_argument("--top-ports", action="store_true",
                   help="Scan a preset of ~25 common ports instead of --ports.")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Per-port connect timeout in seconds (default: %(default)s).")
    p.add_argument("--concurrency", type=int, default=200,
                   help="Max parallel connections (default: %(default)s).")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.timeout <= 0:
        print("error: --timeout must be > 0", file=sys.stderr)
        return 2
    if not 1 <= args.concurrency <= 2000:
        print("error: --concurrency must be 1-2000", file=sys.stderr)
        return 2

    if args.top_ports:
        ports = list(TOP_PORTS)
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
    else:
        print("error: give --ports (e.g. 1-1000 or 22,80,443) or --top-ports",
              file=sys.stderr)
        return 2

    host = args.host.strip()
    if not host:
        print("error: --host must not be empty", file=sys.stderr)
        return 2

    # Resolve early for a clean DNS error (no traceback).
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        print("error: cannot resolve host %r (check name/IP/DNS)" % host,
              file=sys.stderr)
        return 1
    except OSError as e:
        print("error: DNS lookup failed for %r: %s" % (host, e), file=sys.stderr)
        return 1

    # Platform note: default event loop works on all three OSes for TCP
    # connect; no special policy needed on Python 3.8+. Windows uses
    # ProactorEventLoop, Linux/macOS use SelectorEventLoop.
    if sys.platform == "win32":
        pass  # explicit: no loop tweak needed for open_connection
    elif sys.platform.startswith("linux"):
        pass  # explicit: default selector loop is fine
    elif sys.platform == "darwin":
        pass  # explicit: default selector loop is fine

    try:
        results = asyncio.run(run_scan(host, ports, args.timeout, args.concurrency))
    except KeyboardInterrupt:
        print("\naborted by user.", file=sys.stderr)
        return 130
    except OSError as e:
        print("error: network unreachable scanning %r: %s" % (host, e),
              file=sys.stderr)
        return 1

    results.sort()
    open_count = sum(1 for _, is_open, _ in results if is_open)

    # Print table: PORT / STATE / SERVICE-guess / BANNER.
    print("%-6s %-8s %-12s %s" % ("PORT", "STATE", "SERVICE", "BANNER"))
    print("-" * 60)
    for port, is_open, banner in results:
        state = "open" if is_open else "closed"
        svc = SERVICE_GUESS.get(port, "?")
        print("%-6d %-8s %-12s %s" % (port, state, svc, banner if is_open else ""))

    print("-" * 60)
    if open_count:
        print("%d open / %d scanned on %s." % (open_count, len(results), host))
    else:
        print("no open ports found (%d scanned on %s). Host may be down or filtered."
              % (len(results), host))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
