# The network audit

ClamMac's antivirus half answers "is there something bad on this disk". The
network audit answers a different question that has become at least as
important: **what is this Mac offering to the network, and who can reach it.**

It is a point-in-time, read-only examination of the machine it runs on. It
takes a couple of seconds, needs no administrator rights, and changes nothing.

---

## Why this exists

A modern developer machine listens on far more ports than its owner realises.
A single afternoon of experimenting can leave a model server, a vector
database, a notebook and two development servers running, and several of those
default to binding *every* interface rather than the loopback one.

The local-AI tooling is the sharpest example. Ollama, LM Studio's server mode,
ComfyUI, Gradio-based web UIs and Ray's dashboard all ship with no
authentication whatsoever, because they are designed for a machine you are
sitting at. Internet-wide scans have repeatedly turned up tens of thousands of
these answering the public internet, and a good proportion of them have
tool-calling enabled — which turns "someone can use your GPU" into "someone can
run commands on your Mac".

None of that is a file, so nothing a signature scanner does will ever find it.

## What it looks at

| Area | What is checked |
| --- | --- |
| **Listening sockets** | Every TCP and UDP socket that is bound, which address it is bound to, which process opened it, and which user owns that process |
| **Reachability** | Whether each socket answers only this Mac (loopback), the local network, or every interface |
| **Service identity** | The port and process are matched against a catalogue of around ninety services, so a finding says "Ollama" rather than "port 11434" |
| **Firewall** | Application firewall on or off, stealth mode, block-all mode, logging, and whether signed software is admitted automatically. The packet filter's state too, when it can be read |
| **Sharing** | Remote Login, Screen Sharing, Remote Management, File Sharing over SMB and AFP, Printer Sharing, Media Sharing, AirPlay Receiver, Remote Apple Events, Content Caching, Internet Sharing |
| **Remote access agents** | Tunnelling and remote-control tools — ngrok, Cloudflare Tunnel, localtunnel, Tailscale, ZeroTier, TeamViewer, AnyDesk, RustDesk — which publish a local service without touching a single listening port on an external interface |
| **Addressing** | Whether an interface holds a publicly routable IPv4 address (no router in front of it), and whether it holds globally routable IPv6, which NAT does not hide |
| **Wi-Fi** | The network's encryption: open networks and WEP/TKIP are called out |
| **DNS** | Which resolvers answer, whether they are the gateway or a recognised public service, and whether queries are encrypted |
| **`/etc/hosts`** | Custom entries, with redirected security-vendor and software-update domains treated as serious — that trick disables protection while every screen still says it is on |
| **Proxies** | A configured HTTP/HTTPS/SOCKS proxy or PAC URL, and whether automatic proxy discovery (WPAD) is on |
| **Local network** | The ARP table, and whether one hardware address is claiming several IP addresses, which is what ARP spoofing looks like |
| **Outbound traffic** | Established connections to addresses outside your own network, which application owns each, and any using a cleartext protocol |

## What it deliberately does not do

- **It does not scan the network.** No packet is sent to any other device. The
  ARP table is *read*, not built; the neighbour list is what this Mac has
  already spoken to. Pointing a port scanner at a network is a different
  activity with different rules about where you are allowed to point it, and it
  is not what a desktop antivirus should be doing.
- **It does not look anything up on the internet.** No reverse DNS, no
  reputation service, no "check my IP" request. Everything in the report came
  off this machine.
- **It does not change a setting.** Every command it runs is a query. The
  findings tell you what to change and where; you make the change.
- **It does not run continuously.** An audit happens when you ask for one, or
  at launch if you turn that on. Watching the network in real time would mean a
  privileged helper and a permanent packet path through this application, and
  neither is worth it to answer this question.
- **It does not need administrator rights.** Without them it cannot see sockets
  opened by other users or read the packet filter's rules, and it says so in
  the report rather than quietly leaving them out.

## How severity is decided

Every service in the catalogue has a **baseline** severity: how bad it is for
*that* service to be reachable from somewhere other than this Mac. Ollama with
no authentication is Critical; PostgreSQL, which at least asks for a password,
is High; a printer sharing its queue is Medium.

That baseline is then adjusted for the machine's actual situation:

| Situation | Effect |
| --- | --- |
| Firewall on | one level down |
| Firewall set to block all incoming connections | two levels down |
| An interface holds a public address | one level up |
| The service is a tunnelling agent | **no firewall discount** — bypassing the firewall is what it does |

A service bound to `127.0.0.1` produces no finding at all. Interesting ones are
still listed, as information, because knowing what is running is useful and
because a configuration change is all that separates that from the network.

The posture score starts at 100 and loses 34 points per Critical finding, 18
per High, 7 per Medium and 2 per Low. Information-level findings cost nothing.
The grade is A at 90, B at 80, C at 70, D at 55, and F below that.

## What it runs

Every one of these is a read-only query. If a tool is missing or refuses, the
audit records that as a limitation and carries on.

| Command | For |
| --- | --- |
| `lsof -nP -i -F pcLtPnT` | listening sockets and established connections, with their processes |
| `netstat -an` | the same, as a fallback when `lsof` is unavailable (without process names) |
| `netstat -rn` | the default gateways |
| `socketfilterfw --get*` | the application firewall's settings |
| `pfctl -s info` | the packet filter's state (needs administrator rights; skipped otherwise) |
| `ifconfig -a` | interfaces and their addresses |
| `arp -an` | the local address table |
| `scutil --dns` | resolvers and search domains |
| `scutil --proxy` | proxy configuration |
| `system_profiler SPAirPortDataType` | the Wi-Fi network and its encryption |
| `ps -axo comm=` | running processes, for the remote-access agent checks |
| reading `/etc/hosts` | name overrides |

## Reading the report

The screen leads with a grade and a one-line verdict, then the findings worst
first. Each finding says what was found, why it matters, and what to do about
it, with the evidence it was drawn from underneath. Below that are four tables:
every listening port, every established connection, the state of each sharing
feature, and a summary of this Mac's network configuration.

Reports export as HTML, CSV or JSON. The HTML is entirely self-contained — no
stylesheet, no font, no script, nothing fetched — so it survives being emailed
or archived. The JSON includes the raw snapshot as well as the findings, so
anyone who disagrees with a rule can re-derive their own answer from the same
observations.

## Settings

Under **Settings ▸ Network audit**:

- **Run an audit each time ClamMac starts** — off by default.
- **Include the connections other applications already have open** — on by
  default. Still an observation, not a probe.
- **Check which Wi-Fi network you are on** — on by default.
- **Ports to leave out of the audit** — an escape hatch for a port you have
  decided about. Keep the list short; every entry is something you have asked
  not to be told about again.

## Where the rules come from

The controls follow the published macOS hardening guidance — the
[CIS Apple macOS Benchmarks](https://www.cisecurity.org/benchmark/apple_os) and
the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security),
which builds on NIST SP 800-53 — for the firewall, sharing and remote-access
checks. Findings that map onto a specific control name it.

The severities for local AI and developer services come from the vendors' own
documented defaults: a service is rated Critical when it ships with no
authentication *and* binds every interface out of the box, because in that case
reaching it is the whole of the attack.
