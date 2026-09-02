"""The vocabulary of a network audit: what was observed, and what it means.

Two halves. The *snapshot* is a plain description of how this Mac is attached
to the network right now -- which sockets are listening, what is connected,
what the firewall is set to, which resolver answers DNS. It contains no
judgements. The *findings* are the judgements, produced from a snapshot by
``checks``, and every one of them carries the evidence it was drawn from.

Keeping the two apart is what makes the audit testable: a snapshot can be
built from recorded command output and run through the rules with nothing
touching the machine.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

__all__ = [
    "AuditReport",
    "Category",
    "DnsConfig",
    "Finding",
    "FirewallState",
    "Interface",
    "Listener",
    "Neighbour",
    "PeerConnection",
    "ProxyConfig",
    "RouteInfo",
    "Scope",
    "Severity",
    "SharingService",
    "Snapshot",
    "WirelessInfo",
    "address_scope",
    "is_private_address",
]


# --------------------------------------------------------------------------
# scales
# --------------------------------------------------------------------------


class Severity(str, Enum):
    """How much a finding should worry the person reading it."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Sort key. Higher is worse, so findings sort worst-first."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @property
    def label(self) -> str:
        return {
            Severity.CRITICAL: "Critical",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium",
            Severity.LOW: "Low",
            Severity.INFO: "Information",
        }[self]

    @property
    def weight(self) -> int:
        """Points taken off the posture score.

        Deliberately steep at the top: one service left open to the whole
        internet matters more than a dozen cosmetic notes.
        """
        return {
            Severity.CRITICAL: 34,
            Severity.HIGH: 18,
            Severity.MEDIUM: 7,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    @property
    def tone(self) -> str:
        """Which palette colour the interface should draw this in."""
        return {
            Severity.CRITICAL: "danger",
            Severity.HIGH: "danger",
            Severity.MEDIUM: "warn",
            Severity.LOW: "muted",
            Severity.INFO: "muted",
        }[self]


class Category(str, Enum):
    """Which part of the machine's network posture a finding is about."""

    EXPOSURE = "exposure"
    FIREWALL = "firewall"
    SHARING = "sharing"
    REMOTE_ACCESS = "remote_access"
    DNS = "dns"
    WIRELESS = "wireless"
    ADDRESSING = "addressing"
    NEIGHBOURS = "neighbours"
    TRAFFIC = "traffic"
    PRIVACY = "privacy"

    @property
    def label(self) -> str:
        return {
            Category.EXPOSURE: "Listening services",
            Category.FIREWALL: "Firewall",
            Category.SHARING: "Sharing",
            Category.REMOTE_ACCESS: "Remote access",
            Category.DNS: "DNS",
            Category.WIRELESS: "Wi-Fi",
            Category.ADDRESSING: "Addressing",
            Category.NEIGHBOURS: "Local network",
            Category.TRAFFIC: "Outbound traffic",
            Category.PRIVACY: "Privacy",
        }[self]


class Scope(str, Enum):
    """How far a bound socket can be reached from."""

    LOOPBACK = "loopback"
    ALL_INTERFACES = "all"
    ROUTABLE = "routable"
    LINK_LOCAL = "link_local"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {
            Scope.LOOPBACK: "This Mac only",
            Scope.ALL_INTERFACES: "Every network",
            Scope.ROUTABLE: "Local network",
            Scope.LINK_LOCAL: "Link-local",
            Scope.UNKNOWN: "Unknown",
        }[self]

    @property
    def reachable_off_device(self) -> bool:
        return self in (Scope.ALL_INTERFACES, Scope.ROUTABLE, Scope.LINK_LOCAL)


# --------------------------------------------------------------------------
# address helpers
# --------------------------------------------------------------------------


def _parse_address(text: str) -> ipaddress._BaseAddress | None:
    """Turn a printed address into an object, tolerating what tools emit.

    ``lsof`` writes IPv6 in brackets, ``netstat`` appends the zone with ``%``,
    and both use ``*`` for "any". None of that should raise.
    """
    candidate = (text or "").strip().strip("[]")
    if not candidate or candidate == "*":
        return None
    candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def address_scope(text: str) -> Scope:
    """Where a socket bound to this address can be reached from."""
    raw = (text or "").strip().strip("[]")
    if raw in ("*", "", "0.0.0.0", "::", "[::]"):
        return Scope.ALL_INTERFACES

    address = _parse_address(raw)
    if address is None:
        return Scope.UNKNOWN
    if address.is_unspecified:
        return Scope.ALL_INTERFACES
    if address.is_loopback:
        return Scope.LOOPBACK
    if address.is_link_local:
        return Scope.LINK_LOCAL
    return Scope.ROUTABLE


def is_private_address(text: str) -> bool:
    """True for anything that cannot be routed across the public internet."""
    address = _parse_address(text)
    if address is None:
        return True
    if address.is_private or address.is_loopback or address.is_link_local:
        return True
    # Carrier-grade NAT: not marked private by the stdlib, but not the
    # public internet either, and common on mobile hotspots.
    return address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10")


# --------------------------------------------------------------------------
# observations
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Listener:
    """One socket accepting connections."""

    protocol: str
    address: str
    port: int
    process: str = ""
    pid: int = 0
    user: str = ""
    family: str = "ipv4"
    path: str = ""

    @property
    def scope(self) -> Scope:
        return address_scope(self.address)

    @property
    def exposed(self) -> bool:
        """Reachable from somewhere other than this Mac."""
        return self.scope.reachable_off_device

    @property
    def endpoint(self) -> str:
        shown = self.address if self.address not in ("", "*") else "*"
        if ":" in shown and not shown.startswith("["):
            shown = f"[{shown}]"
        return f"{shown}:{self.port}"

    @property
    def key(self) -> tuple[str, str, int, int]:
        return (self.protocol, self.address, self.port, self.pid)


@dataclass(frozen=True)
class PeerConnection:
    """One established connection to somewhere else."""

    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str = ""
    process: str = ""
    pid: int = 0

    @property
    def remote_is_public(self) -> bool:
        return not is_private_address(self.remote_address)

    @property
    def remote_endpoint(self) -> str:
        shown = self.remote_address
        if ":" in shown and not shown.startswith("["):
            shown = f"[{shown}]"
        return f"{shown}:{self.remote_port}"


@dataclass(frozen=True)
class Interface:
    """A network interface and the addresses bound to it."""

    name: str
    active: bool = False
    mac: str = ""
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    kind: str = ""

    @property
    def public_ipv4(self) -> tuple[str, ...]:
        return tuple(a for a in self.ipv4 if not is_private_address(a))

    @property
    def global_ipv6(self) -> tuple[str, ...]:
        """Globally routable IPv6, which NAT does not hide."""
        found = []
        for candidate in self.ipv6:
            address = _parse_address(candidate)
            if address is None or address.version != 6:
                continue
            if address.is_global and not address.is_private:
                found.append(candidate)
        return tuple(found)


@dataclass(frozen=True)
class FirewallState:
    """macOS has two firewalls; this covers both."""

    available: bool = False
    enabled: bool | None = None
    stealth: bool | None = None
    block_all: bool | None = None
    logging: bool | None = None
    allow_signed: bool | None = None
    allow_downloaded_signed: bool | None = None
    packet_filter: bool | None = None
    detail: str = ""


@dataclass(frozen=True)
class DnsConfig:
    resolvers: tuple[str, ...] = ()
    search_domains: tuple[str, ...] = ()
    encrypted: bool = False
    encrypted_detail: str = ""


@dataclass(frozen=True)
class WirelessInfo:
    present: bool = False
    ssid: str = ""
    security: str = ""
    channel: str = ""
    detail: str = ""

    @property
    def open_network(self) -> bool:
        text = self.security.lower()
        return bool(text) and ("none" in text or "open" in text)

    @property
    def weak_security(self) -> bool:
        text = self.security.lower()
        return any(weak in text for weak in ("wep", "tkip", "wpa personal", "wpa/wpa2"))


@dataclass(frozen=True)
class SharingService:
    """A macOS sharing feature, and whether this Mac is offering it."""

    key: str
    label: str
    running: bool
    detail: str = ""
    ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class Neighbour:
    """One entry from the ARP table: something else on this network."""

    address: str
    mac: str
    interface: str = ""
    permanent: bool = False


@dataclass(frozen=True)
class RouteInfo:
    gateway: str = ""
    interface: str = ""
    gateway_v6: str = ""


@dataclass(frozen=True)
class ProxyConfig:
    http: str = ""
    https: str = ""
    socks: str = ""
    pac_url: str = ""
    auto_discovery: bool = False

    @property
    def any_configured(self) -> bool:
        return bool(self.http or self.https or self.socks or self.pac_url or self.auto_discovery)


@dataclass
class Snapshot:
    """Everything one audit observed, with no interpretation applied."""

    captured_at: str = ""
    hostname: str = ""
    platform: str = ""
    elevated: bool = False
    listeners: list[Listener] = field(default_factory=list)
    connections: list[PeerConnection] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    firewall: FirewallState = field(default_factory=FirewallState)
    dns: DnsConfig = field(default_factory=DnsConfig)
    wireless: WirelessInfo = field(default_factory=WirelessInfo)
    sharing: list[SharingService] = field(default_factory=list)
    neighbours: list[Neighbour] = field(default_factory=list)
    route: RouteInfo = field(default_factory=RouteInfo)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    hosts_overrides: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    #: Things the audit could not determine, and why.
    limitations: list[str] = field(default_factory=list)

    @property
    def exposed_listeners(self) -> list[Listener]:
        return [listener for listener in self.listeners if listener.exposed]

    @property
    def loopback_listeners(self) -> list[Listener]:
        return [listener for listener in self.listeners if listener.scope is Scope.LOOPBACK]

    @property
    def public_connections(self) -> list[PeerConnection]:
        return [c for c in self.connections if c.remote_is_public]


# --------------------------------------------------------------------------
# judgements
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One thing the audit wants the user to know about."""

    check_id: str
    title: str
    severity: Severity
    category: Category
    summary: str
    recommendation: str = ""
    evidence: tuple[str, ...] = ()
    reference: str = ""

    @property
    def sort_key(self) -> tuple[int, str, str]:
        return (-self.severity.rank, self.category.value, self.check_id)


_GRADES = ((90, "A"), (80, "B"), (70, "C"), (55, "D"), (0, "F"))


@dataclass
class AuditReport:
    """A snapshot, the findings drawn from it, and the headline number."""

    audit_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration: float = 0.0
    snapshot: Snapshot = field(default_factory=Snapshot)
    findings: list[Finding] = field(default_factory=list)

    # -- headline ------------------------------------------------------

    @property
    def score(self) -> int:
        """0-100. Starts perfect and loses points for every finding."""
        total = 100
        for finding in self.findings:
            total -= finding.severity.weight
        return max(0, min(100, total))

    @property
    def grade(self) -> str:
        score = self.score
        for threshold, letter in _GRADES:
            if score >= threshold:
                return letter
        return "F"

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def headline(self) -> str:
        counts = self.counts
        if counts[Severity.CRITICAL]:
            return "Your Mac is exposed"
        if counts[Severity.HIGH]:
            return "Needs attention"
        if counts[Severity.MEDIUM]:
            return "Mostly in good shape"
        return "Nothing exposed"

    @property
    def counts(self) -> dict[Severity, int]:
        tally = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            tally[finding.severity] += 1
        return tally

    @property
    def actionable(self) -> list[Finding]:
        """Findings worth doing something about, worst first."""
        return sorted(
            (f for f in self.findings if f.severity is not Severity.INFO),
            key=lambda f: f.sort_key,
        )

    @property
    def ordered(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)

    def by_category(self) -> dict[Category, list[Finding]]:
        grouped: dict[Category, list[Finding]] = {}
        for finding in self.ordered:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped

    @property
    def started(self) -> datetime:
        try:
            parsed = datetime.fromisoformat(self.started_at)
        except (TypeError, ValueError):
            return datetime.now(UTC)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
