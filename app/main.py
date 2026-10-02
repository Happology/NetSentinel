"""Command-line entry point for NetSentinel."""

import argparse

from app.scanner.port_scanner import DEFAULT_PORTS, scan_ports


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check selected TCP ports on a host you own or are authorized to test."
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_PORTS,
        help=f"TCP ports to check (default: {', '.join(map(str, DEFAULT_PORTS))})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Seconds to wait for each connection attempt (default: 1.0)",
    )
    args = parser.parse_args()

    invalid_ports = [port for port in args.ports if not 1 <= port <= 65535]
    if invalid_ports:
        parser.error(f"ports must be between 1 and 65535: {invalid_ports}")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    print("NetSentinel v0.1")
    print(f"Target: {args.target}")
    print("Scanning...\n")
    print("PORT\tSTATUS")
    for port, is_open in scan_ports(args.target, args.ports, args.timeout):
        print(f"{port}\t{'OPEN' if is_open else 'CLOSED'}")
    print("\nScan complete.")


if __name__ == "__main__":
    main()
