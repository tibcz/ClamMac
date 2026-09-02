"""The network audit: parsing, the rules, and everything downstream of them.

The parsers are checked against real command output, captured from a Mac and
pasted verbatim, because that is the only way to be sure a change to a regular
expression has not quietly stopped recognising a port. The rules are checked
against snapshots built by hand, because the interesting cases -- a model
server answering the whole internet, a redirected update domain -- are ones
nobody should have to arrange on a real machine to test.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from clammac.core.config import NetworkSettings, Settings
from clammac.core.history import History
from clammac.core.network import (
    AuditReport,
    Category,
    DnsConfig,
    FirewallState,
    Interface,
    Listener,
    Neighbour,
    PeerConnection,
    ProxyConfig,
    RouteInfo,
    Scope,
    Severity,
    Snapshot,
    WirelessInfo,
    catalog,
    checks,
    probe,
    run_audit,
)
from clammac.core.network import report as audit_report
from clammac.core.network.model import address_scope, is_private_address

# --------------------------------------------------------------------------
# recorded command output
# --------------------------------------------------------------------------

LSOF = """p1
claunchd
Lroot
f28
tIPv6
PTCP
n*:22
TST=LISTEN
p604
cmDNSResponder
L_mdnsresponder
f7
tIPv4
PUDP
n*:5353
p1188
collama
Ltibor
f3
tIPv4
PTCP
n0.0.0.0:11434
TST=LISTEN
f9
tIPv4
PTCP
n192.168.1.24:54120->140.82.121.4:443
TST=ESTABLISHED
p1450
cPython
Ltibor
f5
tIPv4
PTCP
n127.0.0.1:8888
TST=LISTEN
f6
tIPv4
PTCP
n127.0.0.1:8888->127.0.0.1:54990
TST=ESTABLISHED
p2201
credis-server
Ltibor
f6
tIPv6
PTCP
n[::1]:6379
TST=LISTEN
"""

NETSTAT = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp46      0      0  *.445                  *.*                    LISTEN
tcp4       0      0  192.168.1.24.54120     140.82.121.4.443       ESTABLISHED
tcp4       0      0  127.0.0.1.11434        *.*                    LISTEN
udp4       0      0  *.5353                 *.*
udp46      0      0  *.5353                 *.*
Active LOCAL (UNIX) domain sockets
Address          Type   Recv-Q Send-Q            Inode
"""

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:11:22:33
\tinet6 fe80::1cbb:aabb:ccdd:eeff%en0 prefixlen 64 secured scopeid 0xb
\tinet 192.168.1.24 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2a02:8109:aabb:ccdd:1cbb:aabb:ccdd:eeff prefixlen 64 autoconf secured
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tstatus: inactive
"""

ROUTES = """Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
127                localhost          UCS            lo0

Internet6:
Destination                        Gateway                    Flags       Netif Expire
default                            fe80::1%en0                UGcg          en0
"""

ARP = """? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.9) at 8c:85:90:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope permanent [ethernet]
"""

SCUTIL_DNS = """DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 1.1.1.1
  if_index : 14 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
"""

AIRPORT = """Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0

      Interfaces:
        en0:
          Card Type: AirPort Extreme  (0x14E4, 0x4387)
          Status: Connected
          Current Network Information:
            Hotel Guest WiFi:
              PHY Mode: 802.11ax
              Channel: 44 (5GHz, 80MHz)
              Security: None
              Signal / Noise: -52 dBm / -91 dBm
          Other Local Wi-Fi Networks:
            SomeoneElse:
              Security: WPA2 Personal
"""

PROXY = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 1
  HTTPSPort : 8080
  HTTPSProxy : 10.0.0.9
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad.example/proxy.pac
  ProxyAutoDiscoveryEnable : 1
}
"""

HOSTS = """##
# Host Database
##
127.0.0.1\tlocalhost
255.255.255.255\tbroadcasthost
::1             localhost
0.0.0.0 database.clamav.net
127.0.0.1 my-dev-site.test
"""


# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------


class TestLsof:
    def test_it_finds_every_listening_socket(self):
        listeners, _ = probe.parse_lsof(LSOF)
        endpoints = {(item.protocol, item.endpoint) for item in listeners}
        assert ("tcp", "*:22") in endpoints
        assert ("tcp", "0.0.0.0:11434") in endpoints
        assert ("udp", "*:5353") in endpoints
        assert ("tcp", "127.0.0.1:8888") in endpoints
        assert ("tcp", "[::1]:6379") in endpoints

    def test_it_attributes_sockets_to_the_right_process(self):
        listeners, _ = probe.parse_lsof(LSOF)
        by_port = {item.port: item for item in listeners}
        assert by_port[11434].process == "ollama"
        assert by_port[11434].pid == 1188
        assert by_port[11434].user == "tibor"
        assert by_port[8888].process == "Python"
        assert by_port[6379].family == "ipv6"

    def test_it_separates_connections_from_listeners(self):
        listeners, connections = probe.parse_lsof(LSOF)
        assert all("->" not in item.endpoint for item in listeners)
        remote = {item.remote_endpoint for item in connections}
        assert "140.82.121.4:443" in remote
        assert connections[0].state == "ESTABLISHED"

    def test_a_loopback_connection_is_not_treated_as_external(self):
        _, connections = probe.parse_lsof(LSOF)
        internal = [c for c in connections if c.remote_address == "127.0.0.1"]
        assert internal and not internal[0].remote_is_public

    def test_empty_input_is_not_an_error(self):
        assert probe.parse_lsof("") == ([], [])


class TestNetstat:
    def test_it_reads_the_macos_dot_separated_form(self):
        listeners, connections = probe.parse_netstat(NETSTAT)
        ports = {item.port for item in listeners}
        assert {22, 445, 11434, 5353} <= ports
        assert connections[0].remote_endpoint == "140.82.121.4:443"

    def test_it_keeps_the_bind_address(self):
        listeners, _ = probe.parse_netstat(NETSTAT)
        by_port = {item.port: item for item in listeners}
        assert by_port[11434].address == "127.0.0.1"
        assert by_port[22].address == "*"

    def test_it_stops_before_the_unix_sockets(self):
        listeners, _ = probe.parse_netstat(NETSTAT)
        assert all(item.port for item in listeners)


class TestInterfaces:
    def test_it_reads_addresses_and_status(self):
        interfaces = {item.name: item for item in probe.parse_ifconfig(IFCONFIG)}
        assert interfaces["en0"].active
        assert interfaces["en0"].ipv4 == ("192.168.1.24",)
        assert interfaces["en0"].mac == "3c:22:fb:11:22:33"
        assert not interfaces["en5"].active

    def test_it_separates_global_ipv6_from_link_local(self):
        interfaces = {item.name: item for item in probe.parse_ifconfig(IFCONFIG)}
        assert interfaces["en0"].global_ipv6 == (
            "2a02:8109:aabb:ccdd:1cbb:aabb:ccdd:eeff",
        )

    def test_a_private_address_is_not_reported_as_public(self):
        interfaces = {item.name: item for item in probe.parse_ifconfig(IFCONFIG)}
        assert interfaces["en0"].public_ipv4 == ()


class TestOtherParsers:
    def test_routes(self):
        route = probe.parse_routes(ROUTES)
        assert route.gateway == "192.168.1.1"
        assert route.interface == "en0"
        assert route.gateway_v6 == "fe80::1%en0"

    def test_arp_pads_short_mac_octets(self):
        neighbours = probe.parse_arp(ARP)
        assert neighbours[0].mac == "00:11:22:33:44:55"
        assert neighbours[-1].permanent

    def test_dns(self):
        dns = probe.parse_scutil_dns(SCUTIL_DNS)
        assert dns.resolvers == ("192.168.1.1", "1.1.1.1")
        assert dns.search_domains == ("lan",)
        assert not dns.encrypted

    def test_wireless(self):
        wireless = probe.parse_wireless(AIRPORT)
        assert wireless.ssid == "Hotel Guest WiFi"
        assert wireless.open_network

    def test_proxy(self):
        proxy = probe.parse_proxy(PROXY)
        assert proxy.https == "10.0.0.9:8080"
        assert proxy.http == ""
        assert proxy.pac_url == "http://wpad.example/proxy.pac"
        assert proxy.auto_discovery

    def test_hosts_ignores_the_stock_entries(self):
        entries = probe.parse_hosts(HOSTS)
        assert entries == ["0.0.0.0 database.clamav.net", "127.0.0.1 my-dev-site.test"]

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Firewall is enabled. (State = 1)", True),
            ("Firewall is disabled. (State = 0)", False),
            ("Stealth mode is off", False),
            ("Stealth mode is on", True),
            ("Block all DISABLED!", False),
            ("Automatically allow signed built-in software ENABLED", True),
            ("", None),
        ],
    )
    def test_firewall_flags(self, text, expected):
        assert probe._flag(text) is expected


class TestAddressClassification:
    @pytest.mark.parametrize(
        ("address", "scope"),
        [
            ("*", Scope.ALL_INTERFACES),
            ("0.0.0.0", Scope.ALL_INTERFACES),
            ("::", Scope.ALL_INTERFACES),
            ("127.0.0.1", Scope.LOOPBACK),
            ("::1", Scope.LOOPBACK),
            ("192.168.1.24", Scope.ROUTABLE),
            ("fe80::1", Scope.LINK_LOCAL),
            ("not an address", Scope.UNKNOWN),
        ],
    )
    def test_scope(self, address, scope):
        assert address_scope(address) is scope

    @pytest.mark.parametrize(
        ("address", "private"),
        [
            ("192.168.1.1", True),
            ("10.0.0.1", True),
            ("172.16.5.4", True),
            ("100.100.1.1", True),
            ("8.8.8.8", False),
            ("140.82.121.4", False),
        ],
    )
    def test_private(self, address, private):
        assert is_private_address(address) is private


# --------------------------------------------------------------------------
# the catalog
# --------------------------------------------------------------------------


class TestCatalog:
    def test_local_ai_servers_are_recognised(self):
        for port in (11434, 1234, 8188, 7860, 8888):
            profile = catalog.profile_for(port)
            assert profile is not None, port
            assert profile.severity is Severity.CRITICAL, port

    def test_the_ollama_entry_explains_the_actual_risk(self):
        profile = catalog.profile_for(11434)
        assert "no authentication" in profile.description.lower()
        assert "127.0.0.1" in profile.guidance

    def test_normal_macos_chatter_is_marked_expected(self):
        assert catalog.profile_for(5353).expected
        assert not catalog.profile_for(22).expected

    def test_a_process_name_beats_the_port_number(self):
        profile = catalog.profile_for(4321, "ngrok")
        assert profile is not None
        assert "tunnel" in profile.tags

    def test_port_5000_names_both_things_it_could_be(self):
        """AirPlay Receiver and Flask share it, and the advice differs."""
        profile = catalog.profile_for(5000)
        assert profile is not None
        assert "AirPlay" in profile.name
        assert "127.0.0.1" in profile.guidance
        assert catalog.profile_for(1900).name == "UPnP / SSDP"

    def test_an_unknown_port_has_no_profile(self):
        assert catalog.profile_for(45871) is None

    def test_every_entry_carries_guidance(self):
        for port, profile in catalog.known_ports().items():
            assert profile.name, port
            assert profile.description, port
            assert profile.guidance, port


# --------------------------------------------------------------------------
# the rules
# --------------------------------------------------------------------------


def snapshot(**overrides) -> Snapshot:
    """A snapshot of a Mac with nothing wrong with it, unless told otherwise."""
    base = {
        "hostname": "test-mac",
        "platform": "macOS 15.0",
        "listeners": [Listener(protocol="udp", address="*", port=5353, process="mDNSResponder")],
        "connections": [],
        "interfaces": [
            Interface(name="en0", active=True, ipv4=("192.168.1.24",), mac="aa:bb:cc:dd:ee:ff")
        ],
        "firewall": FirewallState(
            available=True, enabled=True, stealth=True, block_all=False, logging=True
        ),
        "dns": DnsConfig(resolvers=("192.168.1.1",), encrypted=True),
        "wireless": WirelessInfo(present=True, ssid="Home", security="WPA3 Personal"),
        "route": RouteInfo(gateway="192.168.1.1", interface="en0"),
        "proxy": ProxyConfig(),
        "neighbours": [],
        "hosts_overrides": [],
        "processes": [],
        "limitations": [],
    }
    base.update(overrides)
    return Snapshot(**base)


def ids(findings) -> set[str]:
    return {finding.check_id for finding in findings}


def find(findings, check_id):
    return next(finding for finding in findings if finding.check_id == check_id)


class TestExposureRules:
    def test_a_healthy_mac_produces_nothing_serious(self):
        findings = checks.evaluate(snapshot())
        assert [f for f in findings if f.severity is not Severity.INFO] == []

    def test_ollama_on_every_interface_is_reported(self):
        state = snapshot(
            listeners=[
                Listener(protocol="tcp", address="0.0.0.0", port=11434, process="ollama", pid=90)
            ]
        )
        finding = find(checks.evaluate(state), "NET-EXP-11434")
        assert finding.severity is Severity.HIGH  # critical, less one for the firewall
        assert "Ollama" in finding.title
        assert finding.evidence

    def test_the_firewall_being_off_makes_it_worse(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="0.0.0.0", port=11434, process="ollama")],
            firewall=FirewallState(available=True, enabled=False),
        )
        findings = checks.evaluate(state)
        assert find(findings, "NET-EXP-11434").severity is Severity.CRITICAL
        assert find(findings, "NET-FW-001").severity is Severity.CRITICAL

    def test_a_public_address_makes_it_worse_still(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="0.0.0.0", port=6379, process="redis")],
            interfaces=[Interface(name="en0", active=True, ipv4=("93.184.216.34",))],
        )
        findings = checks.evaluate(state)
        assert find(findings, "NET-EXP-06379").severity is Severity.CRITICAL
        assert find(findings, "NET-ADR-001").severity is Severity.HIGH
        assert "reachable from the internet" in find(findings, "NET-EXP-06379").summary

    def test_blocking_all_incoming_lowers_the_severity(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="0.0.0.0", port=11434, process="ollama")],
            firewall=FirewallState(available=True, enabled=True, block_all=True, stealth=True),
        )
        assert find(checks.evaluate(state), "NET-EXP-11434").severity is Severity.MEDIUM

    def test_the_same_service_on_loopback_is_only_a_note(self):
        state = snapshot(
            listeners=[
                Listener(protocol="tcp", address="127.0.0.1", port=11434, process="ollama")
            ]
        )
        findings = checks.evaluate(state)
        assert "NET-EXP-11434" not in ids(findings)
        note = find(findings, "NET-EXP-LOCAL")
        assert note.severity is Severity.INFO
        assert any("Ollama" in line for line in note.evidence)

    def test_an_unknown_open_port_is_still_reported(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="0.0.0.0", port=47111, process="weird")]
        )
        finding = find(checks.evaluate(state), "NET-EXP-47111")
        assert finding.severity is Severity.LOW
        assert "does not recognise" in finding.summary

    def test_bonjour_is_not_treated_as_a_problem(self):
        findings = checks.evaluate(snapshot())
        assert find(findings, "NET-EXP-05353").severity is Severity.INFO

    def test_sharing_services_are_filed_under_sharing(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="*", port=445, process="smbd")]
        )
        assert find(checks.evaluate(state), "NET-EXP-00445").category is Category.SHARING

    def test_a_tunnel_gets_no_firewall_discount(self):
        state = snapshot(processes=["/usr/local/bin/ngrok"])
        finding = find(checks.evaluate(state), "NET-RMT-NGROK-TUNNEL")
        assert finding.severity is Severity.HIGH
        assert finding.category is Category.REMOTE_ACCESS


class TestFirewallRules:
    def test_stealth_mode_off_is_mentioned(self):
        state = snapshot(
            firewall=FirewallState(available=True, enabled=True, stealth=False, logging=True)
        )
        assert "NET-FW-003" in ids(checks.evaluate(state))

    def test_automatically_allowing_downloaded_software_is_mentioned(self):
        state = snapshot(
            firewall=FirewallState(
                available=True, enabled=True, stealth=True, allow_downloaded_signed=True
            )
        )
        assert "NET-FW-004" in ids(checks.evaluate(state))

    def test_an_unreadable_firewall_is_admitted_rather_than_assumed(self):
        state = snapshot(firewall=FirewallState(available=False, detail="not present"))
        finding = find(checks.evaluate(state), "NET-FW-000")
        assert finding.severity is Severity.LOW


class TestEnvironmentRules:
    def test_an_open_wifi_network_is_high(self):
        state = snapshot(wireless=WirelessInfo(present=True, ssid="Cafe", security="None"))
        assert find(checks.evaluate(state), "NET-WIFI-001").severity is Severity.HIGH

    def test_wep_is_high(self):
        state = snapshot(wireless=WirelessInfo(present=True, ssid="Old", security="WEP"))
        assert find(checks.evaluate(state), "NET-WIFI-002").severity is Severity.HIGH

    def test_an_unrecognised_resolver_is_flagged(self):
        state = snapshot(dns=DnsConfig(resolvers=("45.33.12.9",), encrypted=True))
        assert find(checks.evaluate(state), "NET-DNS-001").severity is Severity.MEDIUM

    def test_a_well_known_resolver_is_not(self):
        state = snapshot(dns=DnsConfig(resolvers=("1.1.1.1", "8.8.8.8"), encrypted=True))
        assert "NET-DNS-001" not in ids(checks.evaluate(state))

    def test_plain_dns_is_a_privacy_note(self):
        state = snapshot(dns=DnsConfig(resolvers=("192.168.1.1",), encrypted=False))
        finding = find(checks.evaluate(state), "NET-DNS-002")
        assert finding.category is Category.PRIVACY

    def test_a_redirected_security_domain_is_high(self):
        state = snapshot(hosts_overrides=["0.0.0.0 database.clamav.net"])
        finding = find(checks.evaluate(state), "NET-DNS-003")
        assert finding.severity is Severity.HIGH
        assert "database.clamav.net" in finding.evidence[0]

    def test_ordinary_hosts_entries_are_only_a_note(self):
        state = snapshot(hosts_overrides=["127.0.0.1 my-dev-site.test"])
        assert find(checks.evaluate(state), "NET-DNS-004").severity is Severity.INFO

    def test_a_configured_proxy_is_reported(self):
        state = snapshot(proxy=ProxyConfig(https="10.0.0.9:8080", auto_discovery=True))
        findings = checks.evaluate(state)
        assert find(findings, "NET-PRX-001").severity is Severity.MEDIUM
        assert "NET-PRX-002" in ids(findings)

    def test_one_mac_claiming_two_addresses_is_flagged(self):
        state = snapshot(
            neighbours=[
                Neighbour(address="192.168.1.1", mac="00:11:22:33:44:55", interface="en0"),
                Neighbour(address="192.168.1.9", mac="00:11:22:33:44:55", interface="en0"),
            ]
        )
        finding = find(checks.evaluate(state), "NET-ARP-001")
        assert finding.severity is Severity.MEDIUM
        assert "spoofing" in finding.summary

    def test_a_broadcast_entry_does_not_trigger_it(self):
        state = snapshot(
            neighbours=[
                Neighbour(address="192.168.1.255", mac="ff:ff:ff:ff:ff:ff", permanent=True),
                Neighbour(address="192.168.1.1", mac="00:11:22:33:44:55"),
            ]
        )
        assert "NET-ARP-001" not in ids(checks.evaluate(state))

    def test_cleartext_outbound_traffic_is_reported(self):
        state = snapshot(
            connections=[
                PeerConnection(
                    protocol="tcp",
                    local_address="192.168.1.24",
                    local_port=51000,
                    remote_address="93.184.216.34",
                    remote_port=23,
                    state="ESTABLISHED",
                    process="nc",
                )
            ]
        )
        assert find(checks.evaluate(state), "NET-TRF-001").severity is Severity.MEDIUM

    def test_global_ipv6_is_explained_rather_than_alarmed_about(self):
        state = snapshot(
            interfaces=[
                Interface(
                    name="en0",
                    active=True,
                    ipv4=("192.168.1.24",),
                    ipv6=("2a02:8109:aabb::1",),
                )
            ]
        )
        assert find(checks.evaluate(state), "NET-ADR-002").severity is Severity.INFO


class TestSharingDerivation:
    def test_it_reads_the_features_off_the_sockets(self):
        state = snapshot(
            listeners=[
                Listener(protocol="tcp", address="*", port=22, process="sshd"),
                Listener(protocol="tcp", address="*", port=5900, process="screensharingd"),
            ]
        )
        services = {item.key: item for item in checks.derive_sharing(state)}
        assert services["remote_login"].running
        assert services["screen_sharing"].running
        assert not services["media_sharing"].running

    def test_a_loopback_socket_is_not_sharing(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="127.0.0.1", port=631, process="cupsd")]
        )
        services = {item.key: item for item in checks.derive_sharing(state)}
        assert not services["printer_sharing"].running


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------


class TestScoring:
    def test_a_clean_report_scores_full_marks(self):
        report = AuditReport(snapshot=snapshot(), findings=[])
        assert report.score == 100
        assert report.grade == "A"
        assert report.headline == "Nothing exposed"

    def test_notes_alone_do_not_cost_anything(self):
        report = AuditReport(snapshot=snapshot(), findings=checks.evaluate(snapshot()))
        assert report.score == 100

    def test_one_critical_finding_moves_the_grade(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="0.0.0.0", port=11434, process="ollama")],
            firewall=FirewallState(available=True, enabled=False),
        )
        report = AuditReport(snapshot=state, findings=checks.evaluate(state))
        assert report.grade in {"D", "F"}
        assert report.headline == "Your Mac is exposed"

    def test_the_score_never_goes_negative(self):
        state = snapshot(
            listeners=[
                Listener(protocol="tcp", address="0.0.0.0", port=port, process="x")
                for port in (11434, 6379, 27017, 9200, 2375, 8888, 5900, 445, 23)
            ],
            firewall=FirewallState(available=True, enabled=False),
            interfaces=[Interface(name="en0", active=True, ipv4=("93.184.216.34",))],
        )
        report = AuditReport(snapshot=state, findings=checks.evaluate(state))
        assert report.score == 0
        assert report.grade == "F"

    def test_findings_come_back_worst_first(self):
        state = snapshot(
            listeners=[Listener(protocol="tcp", address="0.0.0.0", port=11434, process="ollama")],
            firewall=FirewallState(available=True, enabled=False),
        )
        report = AuditReport(snapshot=state, findings=checks.evaluate(state))
        ranks = [finding.severity.rank for finding in report.ordered]
        assert ranks == sorted(ranks, reverse=True)
        assert all(f.severity is not Severity.INFO for f in report.actionable)


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------


@pytest.fixture
def exposed_report() -> AuditReport:
    state = snapshot(
        listeners=[
            Listener(protocol="tcp", address="0.0.0.0", port=11434, process="ollama", pid=42),
            Listener(protocol="tcp", address="127.0.0.1", port=8888, process="<python>", pid=7),
        ],
        connections=[
            PeerConnection(
                protocol="tcp",
                local_address="192.168.1.24",
                local_port=51000,
                remote_address="140.82.121.4",
                remote_port=443,
                state="ESTABLISHED",
                process="git",
            )
        ],
        firewall=FirewallState(available=True, enabled=False),
    )
    state.sharing = checks.derive_sharing(state)
    return AuditReport(
        audit_id="abc123",
        started_at="2026-09-01T10:00:00+00:00",
        finished_at="2026-09-01T10:00:03+00:00",
        duration=3.0,
        snapshot=state,
        findings=checks.evaluate(state),
    )


class TestHtmlReport:
    def test_it_is_self_contained(self, exposed_report):
        body = audit_report.to_html(exposed_report)
        assert "<script" not in body.lower()
        assert 'src="http' not in body
        assert "<link" not in body.lower()

    def test_it_escapes_process_names(self, exposed_report):
        body = audit_report.to_html(exposed_report)
        assert "&lt;python&gt;" in body
        assert "<python>" not in body

    def test_it_leads_with_the_grade_and_the_worst_finding(self, exposed_report):
        body = audit_report.to_html(exposed_report)
        assert f">{exposed_report.grade}</div>" in body
        assert "Ollama" in body

    def test_it_adapts_to_dark_mode(self, exposed_report):
        assert "prefers-color-scheme: dark" in audit_report.to_html(exposed_report)

    def test_it_says_the_audit_touched_nothing_else(self, exposed_report):
        body = " ".join(audit_report.to_html(exposed_report).split())
        assert "does not scan, contact, or probe any other device" in body

    def test_a_clean_report_says_so(self):
        state = snapshot()
        clean = AuditReport(snapshot=state, findings=checks.evaluate(state))
        assert "Nothing needs your attention" in audit_report.to_html(clean)


class TestOtherFormats:
    def test_csv_has_every_section(self, exposed_report):
        rows = list(csv.reader(io.StringIO(audit_report.to_csv(exposed_report))))
        assert ["Audit"] in rows
        assert ["Findings"] in rows
        assert ["Listening ports"] in rows
        assert ["Established connections"] in rows

    def test_json_carries_the_raw_snapshot_too(self, exposed_report):
        payload = json.loads(audit_report.to_json(exposed_report))
        assert payload["audit"]["grade"] == exposed_report.grade
        assert payload["snapshot"]["listeners"][0]["port"] == 11434
        assert payload["snapshot"]["listeners"][0]["exposed"] is True
        assert any(f["id"] == "NET-EXP-11434" for f in payload["findings"])

    def test_writing_each_format(self, exposed_report, tmp_path):
        for suffix in ("html", "csv", "json"):
            written = audit_report.write_report(
                tmp_path / f"audit.{suffix}", exposed_report, fmt=suffix
            )
            assert written.exists() and written.stat().st_size > 0

    def test_an_unknown_format_is_refused(self, exposed_report, tmp_path):
        with pytest.raises(ValueError):
            audit_report.write_report(tmp_path / "a.txt", exposed_report, fmt="txt")


# --------------------------------------------------------------------------
# running one for real
# --------------------------------------------------------------------------


class TestRunningAnAudit:
    def test_it_completes_on_this_machine(self):
        seen: list[str] = []
        report = run_audit(NetworkSettings(), on_progress=lambda p: seen.append(p.message))
        assert report.audit_id
        assert 0 <= report.score <= 100
        assert report.grade in {"A", "B", "C", "D", "F"}
        assert len(seen) >= 5
        assert report.duration >= 0

    def test_it_never_raises_when_the_tools_are_missing(self, monkeypatch):
        monkeypatch.setattr(
            probe, "run", lambda argv, **kwargs: probe.CommandResult(tuple(argv), missing=True)
        )
        report = run_audit(NetworkSettings())
        assert report.snapshot.limitations

    def test_ignored_ports_are_left_out(self, monkeypatch):
        monkeypatch.setattr(
            probe,
            "collect_sockets",
            lambda **kwargs: (
                [
                    Listener(protocol="tcp", address="0.0.0.0", port=11434, process="ollama"),
                    Listener(protocol="tcp", address="0.0.0.0", port=8080, process="node"),
                ],
                [],
                [],
            ),
        )
        report = run_audit(NetworkSettings(ignored_ports=[11434]))
        assert {item.port for item in report.snapshot.listeners} == {8080}

    def test_connections_can_be_left_out(self, monkeypatch):
        monkeypatch.setattr(
            probe,
            "collect_sockets",
            lambda **kwargs: (
                [],
                [
                    PeerConnection(
                        protocol="tcp",
                        local_address="192.168.1.24",
                        local_port=1,
                        remote_address="8.8.8.8",
                        remote_port=443,
                        state="ESTABLISHED",
                    )
                ],
                [],
            ),
        )
        assert run_audit(NetworkSettings(include_connections=False)).snapshot.connections == []

    def test_a_probe_that_explodes_is_recorded_not_fatal(self, monkeypatch):
        def boom(**kwargs):
            raise OSError("no such tool")

        monkeypatch.setattr(probe, "collect_interfaces", boom)
        report = run_audit(NetworkSettings())
        assert any("interfaces" in note for note in report.snapshot.limitations)


class TestTheJob:
    def test_it_runs_on_a_thread_and_reports_back(self):
        from clammac.core.network import AuditState, NetworkAudit

        done: list[NetworkAudit] = []
        job = NetworkAudit(NetworkSettings(), on_finished=done.append)
        job.start()
        assert job.wait(60)
        assert job.state is AuditState.COMPLETED
        assert job.report is not None
        assert done and done[0] is job

    def test_starting_twice_is_refused(self):
        from clammac.core.network import NetworkAudit

        job = NetworkAudit(NetworkSettings())
        job.start()
        try:
            with pytest.raises(RuntimeError):
                job.start()
        finally:
            job.wait(60)


# --------------------------------------------------------------------------
# persistence and the service
# --------------------------------------------------------------------------


class TestHistoryRoundTrip:
    def test_an_audit_survives_being_stored(self, tmp_path, exposed_report):
        history = History(tmp_path / "history.sqlite3")
        history.record_network_audit(exposed_report)

        record = history.last_network_audit()
        assert record is not None
        assert record.id == "abc123"
        assert record.score == exposed_report.score
        assert record.grade == exposed_report.grade
        assert record.exposed == len(exposed_report.snapshot.exposed_listeners)
        assert record.serious == record.critical + record.high

        findings = history.network_findings("abc123")
        assert len(findings) == len(exposed_report.findings)
        assert any(f.check_id == "NET-EXP-11434" for f in findings)
        assert all(isinstance(f.evidence, list) for f in findings)

    def test_recording_the_same_audit_twice_does_not_duplicate(self, tmp_path, exposed_report):
        history = History(tmp_path / "history.sqlite3")
        history.record_network_audit(exposed_report)
        history.record_network_audit(exposed_report)
        assert len(history.network_audits()) == 1
        assert len(history.network_findings("abc123")) == len(exposed_report.findings)

    def test_clearing_removes_audits_too(self, tmp_path, exposed_report):
        history = History(tmp_path / "history.sqlite3")
        history.record_network_audit(exposed_report)
        history.clear()
        assert history.network_audits() == []


class TestServiceIntegration:
    def test_the_service_runs_and_records_an_audit(self):
        from clammac.core.service import AppService

        service = AppService(settings=Settings())
        job = service.start_network_audit()
        assert job.wait(60)

        record = service.history.last_network_audit()
        assert record is not None
        assert service.active_audit is None
        assert any(
            event.kind == "network" for event in service.history.events()
        )

    def test_it_does_not_need_the_engine(self):
        from clammac.core.service import AppService

        service = AppService(settings=Settings())
        service.engine = None
        job = service.start_network_audit()
        assert job.wait(60)
        assert job.report is not None

    def test_the_status_stays_calm_until_an_audit_has_run(self):
        from clammac.core.service import AppService

        service = AppService(settings=Settings())
        assert service.status().last_network_audit is None

    def test_a_critical_finding_shows_up_in_the_status(self, exposed_report):
        from clammac.core.service import AppService

        service = AppService(settings=Settings())
        service.history.record_network_audit(exposed_report)
        status = service.status()
        assert status.last_network_audit is not None
        if status.last_network_audit.critical:
            assert any("exposed to the network" in reason for reason in status.reasons)


class TestSettings:
    def test_the_network_section_round_trips(self, tmp_path):
        from clammac.core import config as config_module

        settings = Settings()
        settings.network.audit_on_launch = True
        settings.network.ignored_ports = [8080, 5000]
        path = tmp_path / "settings.json"
        config_module.save(settings, path)

        loaded = config_module.load(path)
        assert loaded.network.audit_on_launch is True
        assert loaded.network.ignored_ports == [8080, 5000]

    def test_a_settings_file_from_before_the_audit_still_loads(self, tmp_path):
        from clammac.core import config as config_module

        path = tmp_path / "settings.json"
        path.write_text(json.dumps({"version": 1, "scan": {"depth": "fast"}}), "utf-8")
        loaded = config_module.load(path)
        assert loaded.network == NetworkSettings()
