"""The network security audit: what this Mac exposes, and what that means.

A point-in-time, read-only examination of the machine it runs on. It reads
local configuration -- listening sockets, firewall settings, DNS, Wi-Fi, the
routing and address tables -- applies a rule set to what it finds, and produces
a report with a posture score and specific, actionable findings.

It is not a network scanner. Nothing here contacts, probes, or enumerates any
other device: the ARP table is read, not built, and no packet is sent to
anything. That keeps the feature squarely inside "audit the machine you are
sitting at", which is the only place a desktop antivirus has any business
looking.

The layering mirrors the rest of ClamMac's core: ``probe`` talks to the
system, ``model`` describes what came back, ``catalog`` and ``checks`` decide
what it means, ``audit`` runs the whole thing on a thread, and ``report``
writes it out. None of it imports Qt.
"""

from __future__ import annotations

from .audit import AuditProgress, AuditState, NetworkAudit, capture, run_audit
from .catalog import ServiceProfile, known_ports, profile_for
from .checks import derive_sharing, evaluate
from .model import (
    AuditReport,
    Category,
    DnsConfig,
    Finding,
    FirewallState,
    Interface,
    Listener,
    Neighbour,
    PeerConnection,
    ProxyConfig,
    RouteInfo,
    Scope,
    Severity,
    SharingService,
    Snapshot,
    WirelessInfo,
)

__all__ = [
    "AuditProgress",
    "AuditReport",
    "AuditState",
    "Category",
    "DnsConfig",
    "Finding",
    "FirewallState",
    "Interface",
    "Listener",
    "Neighbour",
    "NetworkAudit",
    "PeerConnection",
    "ProxyConfig",
    "RouteInfo",
    "Scope",
    "ServiceProfile",
    "Severity",
    "SharingService",
    "Snapshot",
    "WirelessInfo",
    "capture",
    "derive_sharing",
    "evaluate",
    "known_ports",
    "profile_for",
    "run_audit",
]
