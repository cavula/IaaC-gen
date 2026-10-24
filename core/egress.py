"""Egress allowlist (threat T6).

Two layers stop data going anywhere except approved hosts:

1. The LLM gateway checks the endpoint host before every call.
2. A process wide guard, installed when the app starts, refuses DNS lookups
   for hosts that are not on the list and refuses connections to addresses
   that did not come from an approved lookup. It uses Python audit hooks
   (PEP 578), so it also covers network calls made inside third party
   libraries, such as a library fetching data at import time.

Loopback (127.0.0.1, ::1, localhost) is always allowed, for the local web app
and for local models through Ollama.

Limit: if the machine routes traffic through a proxy, the guard sees only the
proxy, so the proxy host must be added and the proxy becomes responsible for
filtering. This is recorded in the threat model.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
import threading
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

# Public Terraform Registry, used from Slice 2 through the Terraform MCP server.
TERRAFORM_REGISTRY = "registry.terraform.io"
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})


class EgressDenied(PermissionError):
    pass


def host_of(url: str) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise ValueError("URL has no host")
    return host.lower()


def is_loopback(host: str) -> bool:
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class EgressPolicy:
    def __init__(self, hosts: Iterable[str]) -> None:
        self.hosts = frozenset(h.lower().rstrip(".") for h in hosts)

    def allows(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return is_loopback(host) or host in self.hosts


_install_lock = threading.Lock()
_installed: EgressPolicy | None = None


def install_guard(policy: EgressPolicy) -> None:
    """Install the process wide guard. It cannot be removed once installed."""
    global _installed
    with _install_lock:
        if _installed is not None:
            raise RuntimeError("egress guard is already installed")
        _installed = policy

    approved_ips: set[str] = set()
    original: Callable[..., Any] = socket.getaddrinfo

    def recording_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        results = original(host, *args, **kwargs)
        name = host.decode() if isinstance(host, bytes) else host
        if isinstance(name, str) and policy.allows(name):
            for *_, sockaddr in results:
                approved_ips.add(str(sockaddr[0]))
        return results

    socket.getaddrinfo = recording_getaddrinfo

    def hook(event: str, args: tuple[Any, ...]) -> None:
        if event == "socket.getaddrinfo":
            host = args[0]
            if isinstance(host, bytes):
                host = host.decode(errors="replace")
            if host is None or not isinstance(host, str):
                return
            if not policy.allows(host) and not _is_approved_ip(host, approved_ips):
                raise EgressDenied(f"network lookup for '{host}' is not on the allowlist")
        elif event == "socket.gethostbyname":
            host = str(args[0])
            if not policy.allows(host):
                raise EgressDenied(f"network lookup for '{host}' is not on the allowlist")
        elif event == "socket.connect":
            address = args[1]
            if isinstance(address, tuple) and address:
                ip = str(address[0])
                if not is_loopback(ip) and ip not in approved_ips:
                    raise EgressDenied(f"connection to {ip} is not on the allowlist")

    sys.addaudithook(hook)


def _is_approved_ip(host: str, approved: set[str]) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return host in approved
