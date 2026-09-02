"""Turning a snapshot into findings: the rules, and why each one exists.

Every rule is a pure function of the snapshot, so the whole rule set can be
run against recorded command output. That matters more here than elsewhere in
ClamMac -- the interesting cases are the dangerous ones, and the only sane way
to test "Ollama is answering the whole internet" is to describe it rather than
arrange it.

Severity is not fixed. A database bound to every interface behind a firewall
that drops unsolicited connections is a different problem from the same
database on a Mac holding a public address, and the report says so.
"""

from __future__ import annotations

from .catalog import ServiceProfile, profile_for, profile_for_process
from .model import (
    Category,
    Finding,
    Listener,
    Scope,
    Severity,
    SharingService,
    Snapshot,
    is_private_address,
)

__all__ = ["derive_sharing", "evaluate"]


def _slug(text: str) -> str:
    """A stable identifier for a check, so history can be compared over time."""
    return "".join(character if character.isalnum() else "-" for character in text.upper()).strip(
        "-"
    )


_LADDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def _shift(severity: Severity, steps: int) -> Severity:
    index = _LADDER.index(severity) + steps
    return _LADDER[max(0, min(len(_LADDER) - 1, index))]


# Resolvers whose operators are publicly known. Anything else answering DNS
# for this Mac is worth a second look: rogue DNS is how traffic gets quietly
# redirected, and it survives a browser reset.
_KNOWN_RESOLVERS = {
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.1.1.3",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112", "9.9.9.11",
    "208.67.222.222", "208.67.220.220",
    "94.140.14.14", "94.140.15.15",
    "76.76.2.0", "76.76.10.0",
    "185.228.168.9", "185.228.169.9",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2620:fe::fe", "2620:fe::9",
}

# Hostnames whose redirection in /etc/hosts is a recognised way of disabling
# security software or blocking updates.
_SENSITIVE_HOST_FRAGMENTS = (
    "clamav", "sophos", "avast", "avg.", "kaspersky", "mcafee", "norton",
    "malwarebytes", "bitdefender", "eset", "trendmicro", "windowsupdate",
    "apple.com", "icloud.com", "microsoft.com", "google.com", "mozilla.org",
    "virustotal", "sourceforge",
)

_CLEARTEXT_OUTBOUND = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 25: "SMTP"}

# Ports that carry ordinary outbound traffic, so they say nothing on their own.
_ORDINARY_OUTBOUND = {80, 443, 853, 993, 995, 465, 587, 5228, 5223, 8443, 22}


# --------------------------------------------------------------------------
# sharing
# --------------------------------------------------------------------------

# (key, label, ports, process fragments)
_SHARING = (
    ("remote_login", "Remote Login (SSH)", (22,), ("sshd",)),
    ("screen_sharing", "Screen Sharing", (5900, 5901), ("screensharingd",)),
    ("remote_management", "Remote Management", (3283, 5988), ("ardagent", "remotedesktop")),
    ("file_sharing_smb", "File Sharing (SMB)", (445, 139), ("smbd",)),
    ("file_sharing_afp", "File Sharing (AFP)", (548,), ("appplefileserver", "afpovertcp")),
    ("printer_sharing", "Printer Sharing", (631,), ()),
    ("media_sharing", "Media Sharing", (3689,), ()),
    ("airplay", "AirPlay Receiver", (7000, 7100), ()),
    ("remote_apple_events", "Remote Apple Events", (3031,), ()),
    ("content_caching", "Content Caching", (49152, 49153), ("assetcache",)),
    ("internet_sharing", "Internet Sharing", (67,), ("bootpd", "natpmpd")),
)


def derive_sharing(snapshot: Snapshot) -> list[SharingService]:
    """Which macOS sharing features this Mac is currently offering.

    Read off the sockets rather than the settings database: a service is only
    interesting when it is actually answering, and this needs no privileges.
    """
    exposed_ports = {
        listener.port for listener in snapshot.listeners if listener.exposed
    }
    running_names = " ".join(snapshot.processes).lower()
    running_names += " " + " ".join(listener.process for listener in snapshot.listeners).lower()

    services: list[SharingService] = []
    for key, label, ports, fragments in _SHARING:
        by_port = sorted(port for port in ports if port in exposed_ports)
        by_process = [name for name in fragments if name in running_names]
        running = bool(by_port) or bool(by_process)
        if by_port:
            detail = "Answering on port " + ", ".join(str(p) for p in by_port)
        elif by_process:
            detail = "Its background service is running"
        else:
            detail = "Off"
        services.append(
            SharingService(
                key=key, label=label, running=running, detail=detail, ports=tuple(ports)
            )
        )
    return services


# --------------------------------------------------------------------------
# the rules
# --------------------------------------------------------------------------


def evaluate(snapshot: Snapshot) -> list[Finding]:
    """Every finding this snapshot supports, worst first."""
    findings: list[Finding] = []
    findings.extend(_check_firewall(snapshot))
    findings.extend(_check_listeners(snapshot))
    findings.extend(_check_remote_agents(snapshot))
    findings.extend(_check_addressing(snapshot))
    findings.extend(_check_wireless(snapshot))
    findings.extend(_check_dns(snapshot))
    findings.extend(_check_proxy(snapshot))
    findings.extend(_check_neighbours(snapshot))
    findings.extend(_check_traffic(snapshot))
    return sorted(findings, key=lambda finding: finding.sort_key)


# -- firewall ---------------------------------------------------------------


def _check_firewall(snapshot: Snapshot) -> list[Finding]:
    firewall = snapshot.firewall
    findings: list[Finding] = []

    if not firewall.available:
        return [
            Finding(
                check_id="NET-FW-000",
                title="Firewall state could not be read",
                severity=Severity.LOW,
                category=Category.FIREWALL,
                summary=firewall.detail or "The macOS firewall tool did not answer.",
                recommendation="Check the firewall by hand in System Settings > Network > "
                "Firewall.",
            )
        ]

    unexpected = [
        listener
        for listener in snapshot.exposed_listeners
        if not _is_expected(listener)
    ]

    if firewall.enabled is False:
        severity = Severity.CRITICAL if unexpected else Severity.HIGH
        findings.append(
            Finding(
                check_id="NET-FW-001",
                title="The firewall is off",
                severity=severity,
                category=Category.FIREWALL,
                summary=(
                    "Nothing is filtering incoming connections, so every listening "
                    f"service on this Mac is reachable from the networks it joins. "
                    f"{len(unexpected)} such service"
                    f"{'s are' if len(unexpected) != 1 else ' is'} listening right now."
                )
                if unexpected
                else "Nothing is filtering incoming connections. Any service that starts "
                "listening later is immediately reachable.",
                recommendation="Turn it on in System Settings > Network > Firewall. It "
                "costs nothing on a laptop and blocks unsolicited incoming connections.",
                evidence=tuple(listener.endpoint for listener in unexpected[:8]),
                reference="CIS macOS Benchmark 2.2 / mSCP os_firewall_enable",
            )
        )
    elif firewall.enabled is None:
        findings.append(
            Finding(
                check_id="NET-FW-002",
                title="Firewall state is unclear",
                severity=Severity.LOW,
                category=Category.FIREWALL,
                summary="macOS did not give a readable answer about the firewall.",
                recommendation="Check it in System Settings > Network > Firewall.",
            )
        )

    if firewall.enabled and firewall.stealth is False:
        findings.append(
            Finding(
                check_id="NET-FW-003",
                title="Stealth mode is off",
                severity=Severity.LOW,
                category=Category.FIREWALL,
                summary="This Mac answers pings and connection attempts to closed ports, "
                "which confirms to anyone scanning the network that it is here.",
                recommendation="Turn on stealth mode in System Settings > Network > "
                "Firewall > Options.",
                reference="CIS macOS Benchmark 2.2.3 / mSCP os_firewall_stealth_mode",
            )
        )

    if firewall.enabled and firewall.allow_downloaded_signed:
        findings.append(
            Finding(
                check_id="NET-FW-004",
                title="Downloaded signed software is allowed in automatically",
                severity=Severity.LOW,
                category=Category.FIREWALL,
                summary="Any application with a valid developer signature may accept "
                "incoming connections without asking you first. A signature says who "
                "wrote something, not whether you wanted it listening.",
                recommendation="Turn off 'Automatically allow downloaded signed software' "
                "in the firewall options so each application has to ask.",
            )
        )

    if firewall.enabled and firewall.logging is False:
        findings.append(
            Finding(
                check_id="NET-FW-005",
                title="Firewall logging is off",
                severity=Severity.INFO,
                category=Category.FIREWALL,
                summary="Blocked connection attempts are not being recorded, so there is "
                "nothing to look at afterwards.",
                recommendation="Turn on firewall logging in the firewall options.",
            )
        )

    return findings


def _is_expected(listener: Listener) -> bool:
    profile = profile_for(listener.port, listener.process)
    return bool(profile and profile.expected)


# -- listening services -----------------------------------------------------


def _check_listeners(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    firewall_on = snapshot.firewall.enabled is True
    blocking_all = snapshot.firewall.block_all is True
    public_host = any(interface.public_ipv4 for interface in snapshot.interfaces)

    grouped: dict[tuple[int, str], list[Listener]] = {}
    for listener in snapshot.listeners:
        if not listener.exposed:
            continue
        grouped.setdefault((listener.port, listener.process.lower()), []).append(listener)

    for (port, _), listeners in sorted(grouped.items()):
        first = listeners[0]
        profile = profile_for(port, first.process)
        findings.append(
            _exposure_finding(first, listeners, profile, firewall_on, blocking_all, public_host)
        )

    findings.extend(_check_local_only_services(snapshot))
    return findings


def _exposure_finding(
    listener: Listener,
    group: list[Listener],
    profile: ServiceProfile | None,
    firewall_on: bool,
    blocking_all: bool,
    public_host: bool,
) -> Finding:
    who = listener.process or "an unidentified process"
    where = "every network this Mac joins" if listener.scope is Scope.ALL_INTERFACES else (
        f"anything that can reach {listener.address}"
    )
    evidence = tuple(
        f"{item.protocol.upper()} {item.endpoint}"
        + (f" — {item.process} (pid {item.pid})" if item.process else "")
        for item in group
    )

    if profile is None:
        severity = Severity.MEDIUM if not public_host else Severity.HIGH
        severity = _adjust(severity, firewall_on, blocking_all, public_host, tunnel=False)
        return Finding(
            check_id=f"NET-EXP-{listener.port:05d}",
            title=f"Port {listener.port} is open to the network",
            severity=severity,
            category=Category.EXPOSURE,
            summary=f"{who} is listening on {listener.protocol.upper()} port "
            f"{listener.port}, reachable from {where}. ClamMac does not recognise this "
            "port, so it cannot say whether it needs a password.",
            recommendation="Work out which application this is and whether it should be "
            "answering the network. If it is only needed on this Mac, configure it to "
            "bind to 127.0.0.1.",
            evidence=evidence,
        )

    severity = _adjust(
        profile.severity,
        firewall_on,
        blocking_all,
        public_host,
        tunnel="tunnel" in profile.tags,
    )
    category = (
        Category.SHARING
        if "sharing" in profile.tags
        else Category.REMOTE_ACCESS
        if "remote" in profile.tags
        else Category.EXPOSURE
    )

    if profile.expected:
        summary = f"{profile.description} It is reachable from {where}."
        return Finding(
            check_id=f"NET-EXP-{listener.port:05d}",
            title=f"{profile.name} is answering on the network",
            severity=Severity.INFO,
            category=category,
            summary=summary,
            recommendation=profile.guidance,
            evidence=evidence,
        )

    qualifier = ""
    if firewall_on and not blocking_all:
        qualifier = (
            " The firewall is on, which blocks unsolicited connections from outside — "
            "but only for applications it has not already been told to allow."
        )
    if blocking_all:
        qualifier = " The firewall is set to block all incoming connections, which "
        qualifier += "greatly reduces the risk here."
    if public_host:
        qualifier += (
            " This Mac holds a public address, so there is no router in the way: this "
            "port is reachable from the internet."
        )

    return Finding(
        check_id=f"NET-EXP-{listener.port:05d}",
        title=f"{profile.name} is reachable from the network",
        severity=severity,
        category=category,
        summary=f"{who} is listening on {listener.protocol.upper()} port {listener.port}, "
        f"reachable from {where}. {profile.description}{qualifier}",
        recommendation=profile.guidance,
        evidence=evidence,
    )


def _adjust(
    severity: Severity,
    firewall_on: bool,
    blocking_all: bool,
    public_host: bool,
    *,
    tunnel: bool,
) -> Severity:
    """Weigh the machine's actual situation against the baseline risk.

    A firewall helps, but only against connections arriving on an interface --
    which is exactly why a tunnelling agent, whose whole job is to bypass that,
    gets no discount.
    """
    adjusted = severity
    if not tunnel:
        if blocking_all:
            adjusted = _shift(adjusted, -2)
        elif firewall_on:
            adjusted = _shift(adjusted, -1)
    if public_host:
        adjusted = _shift(adjusted, +1)
    return adjusted


def _check_local_only_services(snapshot: Snapshot) -> list[Finding]:
    """Name the AI and developer services bound to loopback.

    They are not a problem -- that is the point of saying so. People are
    routinely surprised by how many model servers, notebooks and databases are
    running on their machine, and the list is the most useful thing on the
    page for deciding what to turn off.
    """
    interesting: list[Listener] = []
    for listener in snapshot.loopback_listeners:
        profile = profile_for(listener.port, listener.process)
        if profile is None or profile.expected:
            continue
        if not ({"ai", "database", "dev", "container", "webui"} & set(profile.tags)):
            continue
        interesting.append(listener)

    if not interesting:
        return []

    names = []
    for listener in sorted(interesting, key=lambda item: item.port):
        profile = profile_for(listener.port, listener.process)
        label = profile.name if profile else f"port {listener.port}"
        names.append(f"{label} — {listener.endpoint}")

    return [
        Finding(
            check_id="NET-EXP-LOCAL",
            title=f"{len(interesting)} local service"
            f"{'s are' if len(interesting) != 1 else ' is'} bound to this Mac only",
            severity=Severity.INFO,
            category=Category.EXPOSURE,
            summary="These are listening on the loopback interface, so nothing on the "
            "network can reach them. That is the right way to run them. They are listed "
            "because it is worth knowing what is running, and because a configuration "
            "change is all that stands between this and the network.",
            recommendation="Nothing to do. If any of these should not be running at all, "
            "quitting the application is the simplest fix.",
            evidence=tuple(names),
        )
    ]


# -- remote access agents ---------------------------------------------------


def _check_remote_agents(snapshot: Snapshot) -> list[Finding]:
    """Tunnels and remote-control tools, which no port check would catch.

    ngrok and its relatives make an outbound connection and publish a local
    port on the public internet. Nothing is listening on an external interface,
    the firewall is untouched, and the service is on the internet anyway.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    candidates = list(snapshot.processes) + [
        listener.process for listener in snapshot.listeners
    ] + [connection.process for connection in snapshot.connections]

    for raw in candidates:
        name = raw.rsplit("/", 1)[-1]
        profile = profile_for_process(name)
        if profile is None or profile.name in seen:
            continue
        if "tunnel" not in profile.tags and "remote" not in profile.tags:
            continue
        seen.add(profile.name)
        findings.append(
            Finding(
                check_id=f"NET-RMT-{_slug(profile.name)}",
                title=f"{profile.name} is running",
                severity=profile.severity,
                category=Category.REMOTE_ACCESS,
                summary=profile.description,
                recommendation=profile.guidance,
                evidence=(name,),
            )
        )
    return findings


# -- addressing -------------------------------------------------------------


def _check_addressing(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []

    public = [
        (interface.name, address)
        for interface in snapshot.interfaces
        for address in interface.public_ipv4
    ]
    if public:
        findings.append(
            Finding(
                check_id="NET-ADR-001",
                title="This Mac holds a public address",
                severity=Severity.HIGH,
                category=Category.ADDRESSING,
                summary="One of this Mac's interfaces has an address that is routable on "
                "the public internet. There is no home router translating addresses in "
                "front of it, so anything listening here can be reached directly, and "
                "will be found by automated scanning within minutes.",
                recommendation="Turn the firewall on, and make sure every listening "
                "service either requires authentication or is bound to 127.0.0.1.",
                evidence=tuple(f"{name}: {address}" for name, address in public),
            )
        )

    global_v6 = [
        (interface.name, address)
        for interface in snapshot.interfaces
        for address in interface.global_ipv6
    ]
    if global_v6:
        findings.append(
            Finding(
                check_id="NET-ADR-002",
                title="This Mac has globally routable IPv6 addresses",
                severity=Severity.INFO,
                category=Category.ADDRESSING,
                summary="IPv6 addresses are reachable end to end. The address translation "
                "that hides IPv4 machines behind a home router does not apply, so whether "
                "these are reachable depends entirely on your router's IPv6 firewall and "
                "on the macOS firewall.",
                recommendation="Confirm your router blocks unsolicited inbound IPv6, and "
                "keep the macOS firewall on.",
                evidence=tuple(f"{name}: {address}" for name, address in global_v6),
            )
        )

    return findings


# -- wireless ---------------------------------------------------------------


def _check_wireless(snapshot: Snapshot) -> list[Finding]:
    wireless = snapshot.wireless
    if not wireless.present or not wireless.ssid:
        return []

    if wireless.open_network:
        return [
            Finding(
                check_id="NET-WIFI-001",
                title="This Wi-Fi network has no encryption",
                severity=Severity.HIGH,
                category=Category.WIRELESS,
                summary=f"'{wireless.ssid}' is an open network. Everything not carried "
                "inside HTTPS is readable by anyone within radio range, and any device on "
                "the same network can reach this Mac's listening services directly.",
                recommendation="Use a VPN on this network, turn the firewall on, and turn "
                "off every sharing service until you are back on a network you trust.",
                evidence=(f"SSID: {wireless.ssid}", f"Security: {wireless.security or 'None'}"),
            )
        ]

    if wireless.weak_security:
        return [
            Finding(
                check_id="NET-WIFI-002",
                title="This Wi-Fi network uses outdated encryption",
                severity=Severity.HIGH,
                category=Category.WIRELESS,
                summary=f"'{wireless.ssid}' is using {wireless.security}, which has known "
                "breaks. WEP can be recovered in minutes and TKIP is not much better.",
                recommendation="Change the router to WPA2 (AES) at minimum, and WPA3 if "
                "every device supports it.",
                evidence=(f"SSID: {wireless.ssid}", f"Security: {wireless.security}"),
            )
        ]

    return [
        Finding(
            check_id="NET-WIFI-003",
            title=f"Connected to '{wireless.ssid}'",
            severity=Severity.INFO,
            category=Category.WIRELESS,
            summary=f"The link is encrypted with {wireless.security}.",
            recommendation="WPA3 is stronger than WPA2 where your router and devices "
            "support it.",
            evidence=(f"Channel: {wireless.channel}",) if wireless.channel else (),
        )
    ]


# -- DNS --------------------------------------------------------------------


def _check_dns(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    dns = snapshot.dns
    gateway = snapshot.route.gateway

    unrecognised = [
        resolver
        for resolver in dns.resolvers
        if resolver != gateway
        and resolver not in _KNOWN_RESOLVERS
        and not is_private_address(resolver)
    ]
    if unrecognised:
        findings.append(
            Finding(
                check_id="NET-DNS-001",
                title="An unrecognised DNS server is in use",
                severity=Severity.MEDIUM,
                category=Category.DNS,
                summary="Whoever runs your DNS server sees every site you visit and "
                "decides what each name resolves to. These resolvers are neither your "
                "router nor one of the well-known public services, which is worth "
                "confirming: changing the resolver is a common way to redirect traffic "
                "quietly, and it survives clearing a browser.",
                recommendation="If you did not set these deliberately, reset DNS in "
                "System Settings > Network > your connection > Details > DNS.",
                evidence=tuple(unrecognised),
            )
        )

    if dns.resolvers and not dns.encrypted:
        findings.append(
            Finding(
                check_id="NET-DNS-002",
                title="DNS queries are not encrypted",
                severity=Severity.LOW,
                category=Category.PRIVACY,
                summary="Plain DNS is sent in clear text, so every name this Mac looks up "
                "is visible to the network it is on and can be altered in transit.",
                recommendation="Turn on encrypted DNS (DNS over HTTPS or over TLS) with a "
                "configuration profile, or use a resolver application that provides it.",
                evidence=tuple(dns.resolvers),
            )
        )

    sensitive = [
        entry
        for entry in snapshot.hosts_overrides
        if any(fragment in entry.lower() for fragment in _SENSITIVE_HOST_FRAGMENTS)
    ]
    if sensitive:
        findings.append(
            Finding(
                check_id="NET-DNS-003",
                title="Security or update domains are redirected in /etc/hosts",
                severity=Severity.HIGH,
                category=Category.DNS,
                summary="Entries in /etc/hosts override DNS for the whole machine. These "
                "redirect names belonging to security vendors or software update services, "
                "which is a long-standing way of stopping a machine from updating or "
                "reaching its antivirus while everything still looks normal.",
                recommendation="Unless you added these yourself, remove them: edit "
                "/etc/hosts as an administrator and delete the lines below.",
                evidence=tuple(sensitive[:12]),
            )
        )
    elif snapshot.hosts_overrides:
        findings.append(
            Finding(
                check_id="NET-DNS-004",
                title=f"{len(snapshot.hosts_overrides)} custom entries in /etc/hosts",
                severity=Severity.INFO,
                category=Category.DNS,
                summary="These names resolve to fixed addresses on this Mac regardless of "
                "DNS. Usually that is a developer's own doing, or an ad blocker.",
                recommendation="Confirm you recognise them.",
                evidence=tuple(snapshot.hosts_overrides[:12]),
            )
        )

    return findings


# -- proxies ----------------------------------------------------------------


def _check_proxy(snapshot: Snapshot) -> list[Finding]:
    proxy = snapshot.proxy
    findings: list[Finding] = []

    active = [
        (name, value)
        for name, value in (
            ("HTTP", proxy.http),
            ("HTTPS", proxy.https),
            ("SOCKS", proxy.socks),
            ("Auto-configuration URL", proxy.pac_url),
        )
        if value
    ]
    if active:
        findings.append(
            Finding(
                check_id="NET-PRX-001",
                title="A network proxy is configured",
                severity=Severity.MEDIUM,
                category=Category.PRIVACY,
                summary="Traffic from this Mac is routed through a proxy, which can see "
                "and change what passes through it. That is normal on a managed work "
                "network and a classic adware installation everywhere else.",
                recommendation="If you did not set this up, remove it in System Settings > "
                "Network > your connection > Details > Proxies.",
                evidence=tuple(f"{name}: {value}" for name, value in active),
            )
        )

    if proxy.auto_discovery:
        findings.append(
            Finding(
                check_id="NET-PRX-002",
                title="Automatic proxy discovery is on",
                severity=Severity.LOW,
                category=Category.PRIVACY,
                summary="This Mac asks the network to tell it which proxy to use (WPAD). "
                "On an untrusted network, anything can answer that question.",
                recommendation="Turn off 'Auto Proxy Discovery' in the network's proxy "
                "settings.",
            )
        )

    return findings


# -- neighbours -------------------------------------------------------------


def _check_neighbours(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    neighbours = [n for n in snapshot.neighbours if not n.permanent]
    if not neighbours:
        return findings

    by_mac: dict[str, list[str]] = {}
    for neighbour in neighbours:
        if neighbour.mac in ("ff:ff:ff:ff:ff:ff", ""):
            continue
        by_mac.setdefault(neighbour.mac, []).append(neighbour.address)

    duplicates = {mac: ips for mac, ips in by_mac.items() if len(ips) > 1}
    if duplicates:
        evidence = tuple(
            f"{mac} answers for {', '.join(sorted(ips))}" for mac, ips in duplicates.items()
        )
        findings.append(
            Finding(
                check_id="NET-ARP-001",
                title="One device is answering for several addresses",
                severity=Severity.MEDIUM,
                category=Category.NEIGHBOURS,
                summary="A single hardware address is claiming more than one IP address on "
                "this network. That happens legitimately — a router with several "
                "addresses, or a virtualisation bridge — but it is also exactly what ARP "
                "spoofing looks like, where one machine impersonates the gateway to read "
                "everyone else's traffic.",
                recommendation="If you do not recognise the device, treat this network as "
                "untrusted: use a VPN, and avoid anything sensitive until you do.",
                evidence=evidence,
            )
        )

    findings.append(
        Finding(
            check_id="NET-ARP-002",
            title=f"{len(neighbours)} other devices seen on this network",
            severity=Severity.INFO,
            category=Category.NEIGHBOURS,
            summary="Devices this Mac has exchanged traffic with recently, taken from its "
            "own address table. Nothing was scanned or contacted to build this list.",
            recommendation="On a network you do not control, assume every one of these can "
            "reach any service this Mac is offering.",
            evidence=tuple(
                f"{neighbour.address} — {neighbour.mac}"
                + (f" ({neighbour.interface})" if neighbour.interface else "")
                for neighbour in neighbours[:20]
            ),
        )
    )
    return findings


# -- outbound traffic -------------------------------------------------------


def _check_traffic(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    if not snapshot.connections:
        return findings

    cleartext = [
        connection
        for connection in snapshot.connections
        if connection.remote_port in _CLEARTEXT_OUTBOUND and connection.remote_is_public
    ]
    if cleartext:
        findings.append(
            Finding(
                check_id="NET-TRF-001",
                title="Something is using an unencrypted protocol",
                severity=Severity.MEDIUM,
                category=Category.TRAFFIC,
                summary="These connections use protocols that send their contents, "
                "credentials included, in clear text over the internet.",
                recommendation="Find the application and switch it to the encrypted "
                "equivalent: SFTP instead of FTP, IMAPS instead of IMAP, SSH instead of "
                "telnet.",
                evidence=tuple(
                    f"{connection.process or 'unknown'} → {connection.remote_endpoint} "
                    f"({_CLEARTEXT_OUTBOUND[connection.remote_port]})"
                    for connection in cleartext[:10]
                ),
            )
        )

    unusual = [
        connection
        for connection in snapshot.connections
        if connection.remote_is_public and connection.remote_port not in _ORDINARY_OUTBOUND
    ]
    remotes = sorted({connection.remote_address for connection in snapshot.connections if connection.remote_is_public})
    if remotes:
        findings.append(
            Finding(
                check_id="NET-TRF-002",
                title=f"{len(remotes)} external addresses currently connected",
                severity=Severity.INFO,
                category=Category.TRAFFIC,
                summary="Every established connection this Mac has to an address outside "
                "your own network, and which application owns it. Most of this is browsers "
                "and system services; it is worth a look for anything you do not recognise."
                + (
                    f" {len(unusual)} of them use a port other than the usual web and mail "
                    "ports."
                    if unusual
                    else ""
                ),
                recommendation="Look for connections belonging to applications you did not "
                "start, or to ports you do not expect.",
                evidence=tuple(
                    f"{connection.process or 'unknown'} → {connection.remote_endpoint}"
                    for connection in sorted(
                        snapshot.public_connections, key=lambda c: c.remote_port
                    )[:20]
                ),
            )
        )

    return findings
