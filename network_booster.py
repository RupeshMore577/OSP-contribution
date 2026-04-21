#!/usr/bin/env python3
"""Network Booster Advisor: diagnose connectivity and suggest practical improvements."""

from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import socket
import struct
import time
from dataclasses import asdict, dataclass
from typing import Iterable, cast

DEFAULT_DNS_SERVERS = [
    "1.1.1.1",  # Cloudflare
    "8.8.8.8",  # Google
    "9.9.9.9",  # Quad9
    "208.67.222.222",  # OpenDNS
]

FALLBACK_DNS = DEFAULT_DNS_SERVERS[0]

DEFAULT_TCP_TARGETS = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 53),
    ("example.com", 443),
]


@dataclass
class DnsProbeResult:
    server: str
    average_ms: float | None
    success_rate: float


@dataclass
class TcpProbeResult:
    target: str
    average_ms: float | None
    success_rate: float


@dataclass
class NetworkReport:
    domain: str
    dns_results: list[DnsProbeResult]
    tcp_results: list[TcpProbeResult]
    recommendations: list[str]
    fastest_dns: str | None


def build_dns_query(domain: str) -> tuple[int, bytes]:
    transaction_id = secrets.randbelow(65536)
    flags = 0x0100  # standard recursive query
    qdcount = 1
    header = struct.pack("!HHHHHH", transaction_id, flags, qdcount, 0, 0, 0)

    labels = domain.rstrip(".").split(".")
    question = b"".join(struct.pack("B", len(label)) + label.encode("idna") for label in labels)
    question += b"\x00"  # end of QNAME
    question += struct.pack("!HH", 1, 1)  # QTYPE A, QCLASS IN

    return transaction_id, header + question


def probe_dns_server(server: str, domain: str, attempts: int, timeout: float) -> DnsProbeResult:
    latencies: list[float] = []
    successes = 0

    for _ in range(attempts):
        transaction_id, query = build_dns_query(domain)
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (server, 53))
                data, _ = sock.recvfrom(512)
            elapsed_ms = (time.perf_counter() - start) * 1000
            if len(data) >= 12:
                response_id, flags, _, _, _, _ = struct.unpack("!HHHHHH", data[:12])
                rcode = flags & 0x000F
                if response_id == transaction_id and rcode == 0:
                    latencies.append(elapsed_ms)
                    successes += 1
        except (TimeoutError, OSError):
            continue

    average = sum(latencies) / len(latencies) if latencies else None
    return DnsProbeResult(
        server=server,
        average_ms=average,
        success_rate=round(successes / attempts, 2) if attempts else 0.0,
    )


def probe_tcp_target(host: str, port: int, attempts: int, timeout: float) -> TcpProbeResult:
    latencies: list[float] = []
    successes = 0

    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)
            successes += 1
        except OSError:
            continue

    average = sum(latencies) / len(latencies) if latencies else None
    return TcpProbeResult(
        target=f"{host}:{port}",
        average_ms=average,
        success_rate=round(successes / attempts, 2) if attempts else 0.0,
    )


def best_dns(results: Iterable[DnsProbeResult]) -> str | None:
    valid = [r for r in results if r.average_ms is not None and r.success_rate >= 0.5]
    if not valid:
        return None
    return min(valid, key=lambda r: cast(float, r.average_ms)).server


def generate_recommendations(
    dns_results: list[DnsProbeResult],
    tcp_results: list[TcpProbeResult],
    fastest_dns: str | None,
) -> list[str]:
    recs: list[str] = []

    dns_failures = [r for r in dns_results if r.success_rate < 0.5]
    if dns_failures:
        recs.append("DNS responses are unstable. Restart your router and avoid overloaded ISP DNS.")

    if fastest_dns:
        recs.append(f"Set primary DNS to {fastest_dns} for faster name resolution.")
    else:
        recs.append("Could not find a reliable public DNS from current network path. Check firewall/VPN settings.")

    weak_tcp = [r for r in tcp_results if r.success_rate < 0.7]
    high_latency = [r for r in tcp_results if r.average_ms is not None and r.average_ms > 150]

    if weak_tcp:
        recs.append("Packet drops detected. Move closer to Wi-Fi router or use Ethernet for stability.")
    if high_latency:
        recs.append("High latency detected. Pause background downloads and disable unnecessary VPN hops.")

    if weak_tcp or high_latency or dns_failures:
        recs.append("Use 5 GHz Wi-Fi for speed, 2.4 GHz only when you need longer range.")
    return recs


def os_dns_hints(selected_dns: str | None) -> list[str]:
    if not selected_dns:
        return []

    system = platform.system().lower()
    hints = []

    if "linux" in system:
        hints.extend(
            [
                "Linux (NetworkManager):",
                "  Find connection name: nmcli con show",
                f"  nmcli con mod <connection-name> ipv4.dns '{selected_dns} {FALLBACK_DNS}'",
                "  nmcli con up <connection-name>",
            ]
        )
    elif "darwin" in system:
        hints.extend(
            [
                "macOS:",
                f"  sudo networksetup -setdnsservers Wi-Fi {selected_dns} {FALLBACK_DNS}",
            ]
        )
    elif "windows" in system:
        hints.extend(
            [
                "Windows (PowerShell as Admin):",
                f"  Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses ('{selected_dns}','{FALLBACK_DNS}')",
            ]
        )

    return hints


def create_report(domain: str, attempts: int, timeout: float) -> NetworkReport:
    dns_results = [probe_dns_server(server, domain, attempts, timeout) for server in DEFAULT_DNS_SERVERS]
    tcp_results = [probe_tcp_target(host, port, attempts, timeout) for host, port in DEFAULT_TCP_TARGETS]
    fastest = best_dns(dns_results)
    recommendations = generate_recommendations(dns_results, tcp_results, fastest)

    return NetworkReport(
        domain=domain,
        dns_results=dns_results,
        tcp_results=tcp_results,
        recommendations=recommendations,
        fastest_dns=fastest,
    )


def print_human_report(report: NetworkReport) -> None:
    print("\n=== Network Booster Advisor Report ===")
    print(f"Domain tested for DNS: {report.domain}")

    print("\nDNS benchmark:")
    for item in report.dns_results:
        avg = f"{item.average_ms:.1f} ms" if item.average_ms is not None else "N/A"
        print(f"- {item.server:15} avg={avg:>8} success={item.success_rate * 100:>5.0f}%")

    print("\nInternet path probe (TCP handshake):")
    for item in report.tcp_results:
        avg = f"{item.average_ms:.1f} ms" if item.average_ms is not None else "N/A"
        print(f"- {item.target:18} avg={avg:>8} success={item.success_rate * 100:>5.0f}%")

    if report.fastest_dns:
        print(f"\nSuggested primary DNS: {report.fastest_dns}")

    print("\nAction plan:")
    for rec in report.recommendations:
        print(f"- {rec}")

    for line in os_dns_hints(report.fastest_dns):
        print(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diagnose network quality and suggest practical booster actions.",
    )
    parser.add_argument("--domain", default="example.com", help="Domain used for DNS timing checks only; TCP checks use fixed default targets.")
    parser.add_argument("--attempts", type=int, default=3, help="Probe attempts per target.")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds for each probe.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.attempts <= 0:
        raise SystemExit("--attempts must be a positive integer")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be a positive number")

    report = create_report(args.domain, args.attempts, args.timeout)

    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print_human_report(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
