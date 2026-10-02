"""Basic TCP connect scanner for authorized, limited port checks."""

import socket
from collections.abc import Iterable

DEFAULT_PORTS = (22, 80, 443, 8080)


def is_port_open(target: str, port: int, timeout: float = 1.0) -> bool:
    """Return whether a TCP connection to target:port succeeds."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        return connection.connect_ex((target, port)) == 0


def scan_ports(
    target: str, ports: Iterable[int] = DEFAULT_PORTS, timeout: float = 1.0
) -> list[tuple[int, bool]]:
    """Check each requested port and return (port, is_open) pairs."""
    return [(port, is_port_open(target, port, timeout)) for port in ports]
