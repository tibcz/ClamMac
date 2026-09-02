"""Asking macOS what its network configuration is, and reading the answers.

Every command run from here is a read-only query against the local machine.
Nothing in this module changes a setting, sends a packet to another host, or
looks anything up on the internet: the audit describes the Mac it is running
on and stops there. That constraint is deliberate -- a tool that probed the
network around it would be a scanner, which is a different thing with
different rules about where you are allowed to point it.

The parsers are separated from the commands so the whole rule set can be
exercised against recorded output, on any platform, without a Mac.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from ..log import get_logger
from .model import (
    DnsConfig,
    FirewallState,
    Interface,
    Listener,
    Neighbour,
    PeerConnection,
    ProxyConfig,
    RouteInfo,
    WirelessInfo,
)

log = get_logger(__name__)

__all__ = [
    "CommandResult",
    "collect_dns",
    "collect_firewall",
    "collect_hosts_overrides",
    "collect_interfaces",
    "collect_neighbours",
    "collect_processes",
    "collect_proxy",
    "collect_route",
    "collect_sockets",
    "collect_wireless",
    "parse_arp",
    "parse_hosts",
    "parse_ifconfig",
    "parse_lsof",
    "parse_netstat",
    "parse_proxy",
    "parse_routes",
    "parse_scutil_dns",
    "parse_wireless",
    "run",
]

DEFAULT_TIMEOUT = 8.0


@dataclass(frozen=True)
class CommandResult:
    """What happened when a probe ran. Never raises; always answerable."""

    argv: tuple[str, ...]
    code: int = 0
    stdout: str = ""
    stderr: str = ""
    missing: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return not self.missing and not self.timed_out and self.code == 0

    @property
    def usable(self) -> bool:
        """Some tools print useful output and still exit non-zero."""
        return not self.missing and not self.timed_out and bool(self.stdout.strip())

    @property
    def denied(self) -> bool:
        text = (self.stderr + self.stdout).lower()
        return "permission denied" in text or "operation not permitted" in text


def run(argv: list[str], *, timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
    """Run one read-only probe. Failure of any kind is data, not an exception."""
    executable = argv[0]
    if not Path(executable).is_absolute() and shutil.which(executable) is None:
        return CommandResult(tuple(argv), missing=True)
    if Path(executable).is_absolute() and not Path(executable).exists():
        return CommandResult(tuple(argv), missing=True)

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        log.debug("network probe timed out: %s", " ".join(argv))
        return CommandResult(tuple(argv), timed_out=True)
    except (OSError, ValueError) as exc:
        log.debug("network probe failed: %s (%s)", " ".join(argv), exc)
        return CommandResult(tuple(argv), missing=True, stderr=str(exc))

    return CommandResult(
        tuple(argv), code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr
    )


# --------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------


def _split_endpoint(text: str, separator: str = ":") -> tuple[str, str]:
    """Split ``address:port`` where the address may itself contain colons."""
    value = (text or "").strip()
    if value.startswith("["):
        host, _, rest = value.partition("]")
        return host[1:], rest.lstrip(separator)
    host, found, port = value.rpartition(separator)
    if not found:
        return value, ""
    return host, port


def _port(text: str) -> int:
    value = (text or "").strip()
    return int(value) if value.isdigit() else 0


# --------------------------------------------------------------------------
# lsof
# --------------------------------------------------------------------------


def parse_lsof(text: str) -> tuple[list[Listener], list[PeerConnection]]:
    """Read ``lsof -nP -i -F pcLtPnT`` output.

    Field output rather than the table, because the table truncates process
    names and lets them contain spaces, and both of those quietly corrupt a
    naive split.
    """
    listeners: list[Listener] = []
    connections: list[PeerConnection] = []

    pid = 0
    command = ""
    user = ""
    current: dict[str, str] | None = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        entry, current = current, None

        protocol = entry.get("protocol", "").lower()
        name = entry.get("name", "")
        state = entry.get("state", "")
        family = "ipv6" if entry.get("family", "").upper() == "IPV6" else "ipv4"
        if not protocol or not name:
            return

        if "->" in name:
            local, _, remote = name.partition("->")
            local_host, local_port = _split_endpoint(local)
            remote_host, remote_port = _split_endpoint(remote)
            if state in ("", "LISTEN", "CLOSED"):
                return
            connections.append(
                PeerConnection(
                    protocol=protocol,
                    local_address=local_host,
                    local_port=_port(local_port),
                    remote_address=remote_host,
                    remote_port=_port(remote_port),
                    state=state,
                    process=command,
                    pid=pid,
                )
            )
            return

        # No peer: a listening socket, or a bound but idle UDP socket.
        if protocol == "tcp" and state != "LISTEN":
            return
        host, port_text = _split_endpoint(name)
        port = _port(port_text)
        if not port:
            return
        listeners.append(
            Listener(
                protocol=protocol,
                address=host,
                port=port,
                process=command,
                pid=pid,
                user=user,
                family=family,
            )
        )

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            flush()
            pid = int(value) if value.isdigit() else 0
            command = ""
            user = ""
        elif tag == "c":
            command = value
        elif tag == "L":
            user = value
        elif tag == "f":
            flush()
            current = {}
        elif current is not None:
            if tag == "t":
                current["family"] = value
            elif tag == "P":
                current["protocol"] = value
            elif tag == "n":
                current["name"] = value
            elif tag == "T" and value.startswith("ST="):
                current["state"] = value[3:]
    flush()

    return listeners, connections


# --------------------------------------------------------------------------
# netstat
# --------------------------------------------------------------------------

_NETSTAT_ROW = re.compile(r"^(tcp|udp)(\d*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*(\S*)")


def parse_netstat(text: str) -> tuple[list[Listener], list[PeerConnection]]:
    """Read ``netstat -an`` output, for when lsof is unavailable.

    Loses the process name -- netstat needs privileges to report it -- but
    still gives a complete picture of what is bound and what is connected.
    """
    listeners: list[Listener] = []
    connections: list[PeerConnection] = []

    for raw in text.splitlines():
        line = raw.strip()
        if line.lower().startswith("active local"):
            break  # unix domain sockets follow; they are not network exposure
        match = _NETSTAT_ROW.match(line)
        if match is None:
            continue

        protocol, suffix, local, remote, state = match.groups()
        family = {"4": "ipv4", "6": "ipv6", "46": "dual"}.get(suffix, "ipv4")
        local_host, local_port = _split_endpoint(local, ".")
        port = _port(local_port)
        if not port:
            continue

        if state == "LISTEN" or (protocol == "udp" and remote in ("*.*", "*")):
            listeners.append(
                Listener(
                    protocol=protocol,
                    address="*" if local_host in ("*", "") else local_host,
                    port=port,
                    family=family,
                )
            )
        elif state and state != "CLOSED" and remote not in ("*.*", "*"):
            remote_host, remote_port = _split_endpoint(remote, ".")
            connections.append(
                PeerConnection(
                    protocol=protocol,
                    local_address=local_host,
                    local_port=port,
                    remote_address=remote_host,
                    remote_port=_port(remote_port),
                    state=state,
                )
            )

    return listeners, connections


def collect_sockets(*, timeout: float = DEFAULT_TIMEOUT) -> tuple[
    list[Listener], list[PeerConnection], list[str]
]:
    """Everything bound or connected, with lsof preferred and netstat as backup."""
    notes: list[str] = []

    result = run(
        ["/usr/sbin/lsof", "-nP", "-i", "-F", "pcLtPnT"], timeout=timeout
    )
    if not result.usable:
        result = run(["lsof", "-nP", "-i", "-F", "pcLtPnT"], timeout=timeout)

    if result.usable:
        listeners, connections = parse_lsof(result.stdout)
        if listeners or connections:
            if not result.ok:
                notes.append(
                    "Some sockets belong to other users and were not listed; run ClamMac "
                    "with administrator rights for the complete picture."
                )
            return _dedupe(listeners), connections, notes

    fallback = run(["netstat", "-an"], timeout=timeout)
    if not fallback.usable:
        fallback = run(["/usr/sbin/netstat", "-an"], timeout=timeout)
    if fallback.usable:
        listeners, connections = parse_netstat(fallback.stdout)
        notes.append(
            "lsof was unavailable, so listening sockets could not be matched to the "
            "applications that opened them."
        )
        return _dedupe(listeners), connections, notes

    notes.append("Neither lsof nor netstat could be run, so open ports are unknown.")
    return [], [], notes


def _dedupe(listeners: list[Listener]) -> list[Listener]:
    """One row per socket. IPv4 and IPv6 bindings of one service collapse."""
    seen: dict[tuple[str, str, int, int], Listener] = {}
    for listener in listeners:
        seen.setdefault(listener.key, listener)
    return sorted(seen.values(), key=lambda listener: (listener.port, listener.protocol))


# --------------------------------------------------------------------------
# firewall
# --------------------------------------------------------------------------

_OFF = re.compile(r"\b(disabled|is off|turned off|not enabled)\b", re.IGNORECASE)
_ON = re.compile(r"\b(enabled|is on|turned on)\b", re.IGNORECASE)


def _flag(text: str) -> bool | None:
    """Read one socketfilterfw answer, whose wording varies by macOS version."""
    value = (text or "").strip()
    if not value:
        return None
    lowered = value.lower()
    if "state = 1" in lowered:
        return True
    if "state = 0" in lowered:
        return False
    if _OFF.search(lowered):
        return False
    if _ON.search(lowered):
        return True
    return None


_FIREWALL_TOOL = (
    "/usr/libexec/ApplicationFirewall/socketfilterfw"
)


def collect_firewall(*, timeout: float = DEFAULT_TIMEOUT) -> tuple[FirewallState, list[str]]:
    """The application firewall's settings, plus whether pf is running."""
    notes: list[str] = []
    if not paths.is_macos():
        return FirewallState(available=False, detail="Not running on macOS."), notes

    if not Path(_FIREWALL_TOOL).exists():
        return (
            FirewallState(available=False, detail="socketfilterfw is not present."),
            ["The macOS firewall tool was not found, so firewall settings are unknown."],
        )

    def ask(flag: str) -> str:
        return run([_FIREWALL_TOOL, flag], timeout=timeout).stdout

    global_state = ask("--getglobalstate")
    signed = ask("--getallowsigned")
    signed_lines = [line for line in signed.splitlines() if line.strip()]
    built_in = _flag(signed_lines[0]) if signed_lines else None
    downloaded = _flag(signed_lines[1]) if len(signed_lines) > 1 else None

    packet_filter: bool | None = None
    pf = run(["/sbin/pfctl", "-s", "info"], timeout=timeout)
    if pf.usable:
        packet_filter = "status: enabled" in pf.stdout.lower()
    elif pf.denied:
        notes.append(
            "The packet filter's state needs administrator rights to read, so it was "
            "not checked."
        )

    state = FirewallState(
        available=True,
        enabled=_flag(global_state),
        stealth=_flag(ask("--getstealthmode")),
        block_all=_flag(ask("--getblockall")),
        logging=_flag(ask("--getloggingmode")),
        allow_signed=built_in,
        allow_downloaded_signed=downloaded,
        packet_filter=packet_filter,
        detail=global_state.strip(),
    )
    return state, notes


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

_NAMESERVER = re.compile(r"nameserver\[\d+\]\s*:\s*(\S+)")
_SEARCH = re.compile(r"search domain\[\d+\]\s*:\s*(\S+)")


def parse_scutil_dns(text: str) -> DnsConfig:
    """Read ``scutil --dns``, keeping the order resolvers are consulted in."""
    resolvers: list[str] = []
    domains: list[str] = []
    for match in _NAMESERVER.finditer(text):
        value = match.group(1)
        if value not in resolvers:
            resolvers.append(value)
    for match in _SEARCH.finditer(text):
        value = match.group(1)
        if value not in domains:
            domains.append(value)

    lowered = text.lower()
    encrypted = "https://" in lowered or "dns over" in lowered or "tls_name" in lowered
    detail = ""
    if encrypted:
        found = re.search(r"(https://\S+)", text)
        detail = found.group(1) if found else "Encrypted DNS is configured."

    return DnsConfig(
        resolvers=tuple(resolvers),
        search_domains=tuple(domains),
        encrypted=encrypted,
        encrypted_detail=detail,
    )


def collect_dns(*, timeout: float = DEFAULT_TIMEOUT) -> DnsConfig:
    result = run(["scutil", "--dns"], timeout=timeout)
    if not result.usable:
        result = run(["/usr/sbin/scutil", "--dns"], timeout=timeout)
    return parse_scutil_dns(result.stdout) if result.usable else DnsConfig()


# --------------------------------------------------------------------------
# interfaces and routing
# --------------------------------------------------------------------------

_IFACE_HEADER = re.compile(r"^([a-zA-Z0-9_.\-]+):\s+flags=(\d+)<([^>]*)>")


def parse_ifconfig(text: str) -> list[Interface]:
    """Read ``ifconfig -a`` into one record per interface."""
    interfaces: list[Interface] = []
    name = ""
    flags = ""
    mac = ""
    ipv4: list[str] = []
    ipv6: list[str] = []
    status = ""

    def flush() -> None:
        if not name:
            return
        running = "RUNNING" in flags and "UP" in flags
        active = running and (bool(ipv4) or bool(ipv6)) and status != "inactive"
        interfaces.append(
            Interface(
                name=name,
                active=active,
                mac=mac,
                ipv4=tuple(ipv4),
                ipv6=tuple(ipv6),
                kind="loopback" if "LOOPBACK" in flags else "",
            )
        )

    for raw in text.splitlines():
        header = _IFACE_HEADER.match(raw)
        if header is not None:
            flush()
            name, _, flags = header.group(1), header.group(2), header.group(3)
            mac, status = "", ""
            ipv4, ipv6 = [], []
            continue
        line = raw.strip()
        if line.startswith("ether "):
            mac = line.split()[1]
        elif line.startswith("inet6 "):
            ipv6.append(line.split()[1])
        elif line.startswith("inet "):
            ipv4.append(line.split()[1])
        elif line.startswith("status:"):
            status = line.split(":", 1)[1].strip()

    flush()
    return interfaces


def collect_interfaces(*, timeout: float = DEFAULT_TIMEOUT) -> list[Interface]:
    result = run(["ifconfig", "-a"], timeout=timeout)
    if not result.usable:
        result = run(["/sbin/ifconfig", "-a"], timeout=timeout)
    return parse_ifconfig(result.stdout) if result.usable else []


def parse_routes(text: str) -> RouteInfo:
    """Pull the default gateways out of ``netstat -rn``."""
    gateway = ""
    interface = ""
    gateway_v6 = ""
    family = "inet"

    for raw in text.splitlines():
        line = raw.strip()
        if line.lower().startswith("internet6"):
            family = "inet6"
            continue
        if line.lower().startswith("internet:"):
            family = "inet"
            continue
        if not line.startswith("default"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if family == "inet" and not gateway:
            gateway = parts[1]
            interface = parts[-1] if len(parts) > 3 else ""
        elif family == "inet6" and not gateway_v6:
            gateway_v6 = parts[1]

    return RouteInfo(gateway=gateway, interface=interface, gateway_v6=gateway_v6)


def collect_route(*, timeout: float = DEFAULT_TIMEOUT) -> RouteInfo:
    result = run(["netstat", "-rn"], timeout=timeout)
    if not result.usable:
        result = run(["/usr/sbin/netstat", "-rn"], timeout=timeout)
    return parse_routes(result.stdout) if result.usable else RouteInfo()


# --------------------------------------------------------------------------
# neighbours
# --------------------------------------------------------------------------

_ARP_ROW = re.compile(
    r"\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+|\(incomplete\))"
    r"(?:\s+on\s+(?P<iface>\S+))?(?P<rest>.*)$"
)


def parse_arp(text: str) -> list[Neighbour]:
    """Read ``arp -an``: the other devices this Mac has spoken to."""
    neighbours: list[Neighbour] = []
    for raw in text.splitlines():
        match = _ARP_ROW.search(raw)
        if match is None:
            continue
        mac = match.group("mac")
        if mac.startswith("("):
            continue
        neighbours.append(
            Neighbour(
                address=match.group("ip"),
                mac=_normalise_mac(mac),
                interface=match.group("iface") or "",
                permanent="permanent" in (match.group("rest") or ""),
            )
        )
    return neighbours


def _normalise_mac(mac: str) -> str:
    """macOS prints ``0:11:22`` where everything else prints ``00:11:22``."""
    parts = mac.split(":")
    if len(parts) != 6:
        return mac.lower()
    return ":".join(part.rjust(2, "0").lower() for part in parts)


def collect_neighbours(*, timeout: float = DEFAULT_TIMEOUT) -> list[Neighbour]:
    result = run(["arp", "-an"], timeout=timeout)
    if not result.usable:
        result = run(["/usr/sbin/arp", "-an"], timeout=timeout)
    return parse_arp(result.stdout) if result.usable else []


# --------------------------------------------------------------------------
# wireless
# --------------------------------------------------------------------------


def parse_wireless(text: str) -> WirelessInfo:
    """Read the Wi-Fi section of ``system_profiler SPAirPortDataType``."""
    lines = text.splitlines()
    for index, raw in enumerate(lines):
        if "current network information" not in raw.lower():
            continue
        ssid = ""
        security = ""
        channel = ""
        indent = len(raw) - len(raw.lstrip())
        for follow in lines[index + 1 :]:
            if not follow.strip():
                continue
            depth = len(follow) - len(follow.lstrip())
            if depth <= indent:
                break
            stripped = follow.strip()
            if not ssid and stripped.endswith(":") and ":" not in stripped[:-1]:
                ssid = stripped[:-1]
                continue
            key, _, value = stripped.partition(":")
            key = key.strip().lower()
            if key == "security":
                security = value.strip()
            elif key == "channel":
                channel = value.strip()
        if ssid or security:
            return WirelessInfo(present=True, ssid=ssid, security=security, channel=channel)

    if "wi-fi" in text.lower() or "airport" in text.lower():
        return WirelessInfo(present=True, detail="Wi-Fi is present but not connected.")
    return WirelessInfo()


def collect_wireless(*, timeout: float = DEFAULT_TIMEOUT) -> WirelessInfo:
    if not paths.is_macos():
        return WirelessInfo()
    # system_profiler is slow; it is worth its own, longer budget.
    # A .app launched from the Finder gets a minimal PATH, so every tool that
    # lives outside /usr/bin is tried by absolute path as well.
    argv = ["-detailLevel", "basic", "SPAirPortDataType"]
    result = run(["system_profiler", *argv], timeout=max(timeout, 20.0))
    if not result.usable:
        result = run(["/usr/sbin/system_profiler", *argv], timeout=max(timeout, 20.0))
    return parse_wireless(result.stdout) if result.usable else WirelessInfo()


# --------------------------------------------------------------------------
# proxies
# --------------------------------------------------------------------------


def parse_proxy(text: str) -> ProxyConfig:
    """Read ``scutil --proxy``'s dictionary dump."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        key, sep, value = raw.partition(":")
        if not sep:
            continue
        values[key.strip()] = value.strip()

    def enabled(prefix: str) -> str:
        if values.get(f"{prefix}Enable") != "1":
            return ""
        host = values.get(f"{prefix}Proxy", "")
        port = values.get(f"{prefix}Port", "")
        return f"{host}:{port}" if host and port else host

    return ProxyConfig(
        http=enabled("HTTP"),
        https=enabled("HTTPS"),
        socks=enabled("SOCKS"),
        pac_url=values.get("ProxyAutoConfigURLString", "")
        if values.get("ProxyAutoConfigEnable") == "1"
        else "",
        auto_discovery=values.get("ProxyAutoDiscoveryEnable") == "1",
    )


def collect_proxy(*, timeout: float = DEFAULT_TIMEOUT) -> ProxyConfig:
    result = run(["scutil", "--proxy"], timeout=timeout)
    if not result.usable:
        result = run(["/usr/sbin/scutil", "--proxy"], timeout=timeout)
    return parse_proxy(result.stdout) if result.usable else ProxyConfig()


# --------------------------------------------------------------------------
# hosts file
# --------------------------------------------------------------------------

_DEFAULT_HOSTS = {
    "localhost",
    "broadcasthost",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
}


def parse_hosts(text: str) -> list[str]:
    """Every non-default entry in ``/etc/hosts``, as ``address name`` strings.

    A redirected hostname is one of the oldest tricks there is: point an
    antivirus vendor's update server at 127.0.0.1 and the machine quietly
    stops being protected while every screen still says it is.
    """
    entries: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        address, names = parts[0], parts[1:]
        for name in names:
            if name.lower().rstrip(".") in _DEFAULT_HOSTS:
                continue
            entries.append(f"{address} {name}")
    return entries


def collect_hosts_overrides() -> list[str]:
    try:
        return parse_hosts(Path("/etc/hosts").read_text("utf-8", errors="replace"))
    except OSError:
        return []


# --------------------------------------------------------------------------
# processes
# --------------------------------------------------------------------------


def collect_processes(*, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Executable paths of everything running, for the agent checks."""
    result = run(["ps", "-axo", "comm="], timeout=timeout)
    if not result.usable:
        result = run(["/bin/ps", "-axo", "comm="], timeout=timeout)
    if not result.usable:
        return []
    names = []
    for raw in result.stdout.splitlines():
        name = raw.strip()
        if name:
            names.append(name)
    return names


# --------------------------------------------------------------------------
# host identity
# --------------------------------------------------------------------------


def host_description() -> tuple[str, str]:
    """The machine's name and OS version, for the report header."""
    name = platform.node() or "this Mac"
    if paths.is_macos():
        release = platform.mac_ver()[0] or platform.release()
        return name, f"macOS {release}"
    return name, f"{platform.system()} {platform.release()}"
