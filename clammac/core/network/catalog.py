"""What is probably listening on a port, and how much it matters if it is.

A port number on its own tells a user nothing. This table turns 11434 into
"Ollama -- a local AI model server that answers anyone who asks, with no
password", which is the difference between a report that gets read and one
that gets closed.

The severities here are the *baseline* for a service reachable from off the
device. ``checks`` raises or lowers them for the machine's actual situation --
the firewall being on, or the Mac holding a public address -- rather than
pretending one number fits every setup.

Sources for the risk ratings are the vendors' own defaults: services listed as
``CRITICAL`` ship with no authentication at all and bind every interface out of
the box, so reaching them is the whole of the attack.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Severity

__all__ = ["ServiceProfile", "known_ports", "profile_for", "profile_for_process"]


@dataclass(frozen=True)
class ServiceProfile:
    name: str
    description: str
    severity: Severity
    guidance: str
    tags: tuple[str, ...] = ()
    #: True when a Mac is *supposed* to answer this on the local network, so
    #: finding it bound to every interface is not by itself a problem.
    expected: bool = False

    @property
    def is_ai(self) -> bool:
        return "ai" in self.tags


# (ports, name, tags, severity, description, guidance)
_TABLE: tuple[tuple[tuple[int, ...], str, tuple[str, ...], Severity, str, str], ...] = (
    # -- local AI and model servers -------------------------------------
    (
        (11434, 11435),
        "Ollama",
        ("ai", "inference"),
        Severity.CRITICAL,
        "Ollama's model API. It has no authentication of any kind: anyone who "
        "can reach this port can list your models, send prompts, pull new "
        "models onto your Mac, and burn your GPU on their work.",
        "Bind it to this Mac only by setting OLLAMA_HOST=127.0.0.1, then "
        "restart Ollama. Reach it from other machines over a VPN or an SSH "
        "tunnel rather than by opening the port.",
    ),
    (
        (1234,),
        "LM Studio server",
        ("ai", "inference"),
        Severity.CRITICAL,
        "LM Studio's OpenAI-compatible server. Its network-serving mode "
        "listens on every interface with no password, so anything on the "
        "network can use your models and your hardware.",
        "Turn off 'Serve on Local Network' in LM Studio's server settings so "
        "it binds to 127.0.0.1 only.",
    ),
    (
        (8188,),
        "ComfyUI",
        ("ai", "webui"),
        Severity.CRITICAL,
        "ComfyUI's web interface and API. It is unauthenticated, and custom "
        "nodes can read and write files, so exposure is close to handing over "
        "an account on this Mac.",
        "Start it with --listen 127.0.0.1, or put it behind a reverse proxy "
        "that requires a login.",
    ),
    (
        (7860, 7861),
        "Gradio web UI",
        ("ai", "webui"),
        Severity.CRITICAL,
        "The default port for Gradio apps — AUTOMATIC1111, text-generation-"
        "webui, and most published demos. Unless it was given credentials it "
        "is open to whoever reaches it.",
        "Run it without --listen, or pass --gradio-auth so it asks for a "
        "username and password.",
    ),
    (
        (8888, 8889),
        "Jupyter",
        ("ai", "notebook", "dev"),
        Severity.CRITICAL,
        "A Jupyter notebook server. A notebook runs arbitrary code as you, so "
        "an exposed one without a token is remote code execution.",
        "Leave it on 127.0.0.1 and connect through an SSH tunnel. Never run "
        "it with --ip=0.0.0.0 --NotebookApp.token='' on a shared network.",
    ),
    (
        (8000, 8001),
        "vLLM, Django or Chroma",
        ("ai", "dev"),
        Severity.HIGH,
        "Port 8000 is the default for vLLM's OpenAI-compatible server, Chroma's "
        "vector database, and Django's development server. None of them "
        "authenticate by default.",
        "Bind development servers to 127.0.0.1. If this is vLLM, set an API "
        "key and put it behind a proxy before letting anything else reach it.",
    ),
    (
        (8080, 8081, 3000, 3001),
        "Web application or AI front end",
        ("ai", "webui", "dev"),
        Severity.HIGH,
        "These are the usual ports for Open WebUI, AnythingLLM, Node "
        "development servers and self-hosted dashboards. Most ship without a "
        "login when run locally.",
        "Check what is listening and whether it needs a password. Bind "
        "development servers to 127.0.0.1 rather than every interface.",
    ),
    (
        (8501,),
        "Streamlit",
        ("ai", "webui", "dev"),
        Severity.HIGH,
        "A Streamlit app. Streamlit has no built-in authentication, and its "
        "apps commonly read local files and call other services.",
        "Bind it to 127.0.0.1 with --server.address, or place it behind an "
        "authenticating proxy.",
    ),
    (
        (6006,),
        "TensorBoard",
        ("ai", "dev"),
        Severity.MEDIUM,
        "TensorBoard. It exposes training runs, and can reveal file paths, "
        "hyper-parameters and sometimes data samples.",
        "Bind it to 127.0.0.1 with --host, and tunnel in rather than opening "
        "the port.",
    ),
    (
        (8265,),
        "Ray dashboard",
        ("ai", "dev"),
        Severity.CRITICAL,
        "Ray's dashboard and job submission API. Submitting a job is "
        "submitting code, and the API is unauthenticated by default.",
        "Never expose the Ray dashboard. Bind it to 127.0.0.1 and reach it "
        "over a tunnel.",
    ),
    (
        (5678,),
        "n8n",
        ("ai", "automation"),
        Severity.HIGH,
        "n8n workflow automation. Workflows usually hold credentials for other "
        "services and can run shell nodes.",
        "Enable n8n's basic authentication and keep it off the open network.",
    ),
    # -- databases and stores -------------------------------------------
    (
        (6333, 6334),
        "Qdrant",
        ("ai", "database"),
        Severity.CRITICAL,
        "The Qdrant vector database. It runs without an API key by default, so "
        "anyone reaching it can read and delete your embeddings — which "
        "usually reconstruct the documents they came from.",
        "Set an API key in the Qdrant configuration and bind it to 127.0.0.1.",
    ),
    (
        (19530, 9091),
        "Milvus",
        ("ai", "database"),
        Severity.HIGH,
        "The Milvus vector database. Authentication is off in the default "
        "configuration.",
        "Turn on authentication and keep the port on the loopback interface.",
    ),
    (
        (6379,),
        "Redis",
        ("database",),
        Severity.CRITICAL,
        "Redis. With no password set — the default — an exposed instance can "
        "be read, wiped, and in many configurations used to write files and "
        "gain persistence on the host.",
        "Set requirepass, and bind Redis to 127.0.0.1 in redis.conf.",
    ),
    (
        (27017, 27018),
        "MongoDB",
        ("database",),
        Severity.CRITICAL,
        "MongoDB. Local installations usually have authentication disabled, "
        "which means full read and write access to every collection.",
        "Enable authorisation and set bindIp to 127.0.0.1.",
    ),
    (
        (9200, 9300),
        "Elasticsearch or OpenSearch",
        ("database",),
        Severity.CRITICAL,
        "Elasticsearch. Security is commonly switched off for local work, "
        "leaving every index readable and writable.",
        "Enable the security plugin, or bind it to 127.0.0.1.",
    ),
    (
        (5432,),
        "PostgreSQL",
        ("database",),
        Severity.HIGH,
        "PostgreSQL. It does ask for a password, but exposing it invites "
        "credential guessing against whatever your local role happens to be.",
        "Set listen_addresses = 'localhost' unless another machine genuinely "
        "needs to connect.",
    ),
    (
        (3306, 33060),
        "MySQL or MariaDB",
        ("database",),
        Severity.HIGH,
        "MySQL. Development instances frequently keep a blank or well-known "
        "root password.",
        "Set bind-address = 127.0.0.1 and give root a real password.",
    ),
    (
        (8123, 9000),
        "ClickHouse or MinIO",
        ("database",),
        Severity.HIGH,
        "ClickHouse's HTTP interface and MinIO both use these ports, and both "
        "have default credentials that are widely known.",
        "Change the default credentials and bind the service to 127.0.0.1.",
    ),
    # -- container and orchestration control planes ---------------------
    (
        (2375,),
        "Docker API (no TLS)",
        ("container",),
        Severity.CRITICAL,
        "The Docker daemon's unencrypted API. It grants the equivalent of root "
        "on this Mac to anyone who can connect, with no authentication.",
        "Never expose 2375. Use the local socket, or 2376 with client "
        "certificates.",
    ),
    (
        (2376,),
        "Docker API (TLS)",
        ("container",),
        Severity.HIGH,
        "The Docker daemon's TLS API. Safe only if client certificate "
        "verification is genuinely enforced.",
        "Confirm --tlsverify is set, or stop exposing the daemon entirely.",
    ),
    (
        (6443, 10250, 10255),
        "Kubernetes API or kubelet",
        ("container",),
        Severity.CRITICAL,
        "A Kubernetes control-plane or kubelet port. The read-only kubelet "
        "port in particular has historically leaked cluster secrets.",
        "Keep cluster ports off untrusted networks entirely.",
    ),
    # -- remote access ---------------------------------------------------
    (
        (22,),
        "SSH (Remote Login)",
        ("remote", "sharing"),
        Severity.HIGH,
        "Remote Login is on, so this Mac accepts shell connections. On any "
        "network you do not control this is continuously probed.",
        "Turn it off in System Settings > General > Sharing if you do not use "
        "it. If you do, disable password authentication and use keys only.",
    ),
    (
        (23,),
        "Telnet",
        ("remote", "legacy"),
        Severity.CRITICAL,
        "Telnet. Everything it carries, passwords included, is sent in clear "
        "text.",
        "Turn this off. There is no configuration that makes telnet safe.",
    ),
    (
        (5900, 5901),
        "Screen Sharing (VNC)",
        ("remote", "sharing"),
        Severity.HIGH,
        "Screen Sharing is on. Anyone who reaches this port sees the login "
        "window and can try passwords against it.",
        "Turn off Screen Sharing when you are not using it, and never leave it "
        "reachable from a public network.",
    ),
    (
        (3283, 5988),
        "Apple Remote Desktop",
        ("remote", "sharing"),
        Severity.HIGH,
        "Remote Management is on. It allows full control of this Mac, and its "
        "reporting channel has been abused for reflection attacks.",
        "Turn off Remote Management unless your organisation requires it.",
    ),
    (
        (3031,),
        "Remote Apple Events",
        ("remote", "sharing", "legacy"),
        Severity.HIGH,
        "Remote Apple Events lets another Mac drive applications on this one.",
        "Turn it off in Sharing. Almost nothing needs it.",
    ),
    # -- file and device sharing -----------------------------------------
    (
        (445, 139, 137, 138),
        "Windows File Sharing (SMB)",
        ("sharing", "file"),
        Severity.HIGH,
        "File Sharing over SMB is on, so shared folders on this Mac are "
        "reachable from the network.",
        "Turn off File Sharing when you are not deliberately sharing, and "
        "never leave it on while using public Wi-Fi.",
    ),
    (
        (548,),
        "Apple File Sharing (AFP)",
        ("sharing", "file", "legacy"),
        Severity.HIGH,
        "The legacy AFP file sharing service is answering.",
        "Turn off File Sharing, or use SMB only — AFP is deprecated.",
    ),
    (
        (631,),
        "Printer Sharing (CUPS)",
        ("sharing",),
        Severity.MEDIUM,
        "The printing system is reachable from the network, which means this "
        "Mac is sharing its printers and its CUPS web interface.",
        "Turn off Printer Sharing in Sharing settings if you are not sharing "
        "a printer.",
    ),
    (
        (3689,),
        "Media Sharing (DAAP)",
        ("sharing",),
        Severity.MEDIUM,
        "Media Sharing is advertising your music and video library to the "
        "local network.",
        "Turn off Media Sharing in Sharing settings if you do not use it.",
    ),
    (
        (7000, 7100),
        "AirPlay Receiver",
        ("sharing",),
        Severity.MEDIUM,
        "AirPlay Receiver is on, so other devices can send their screen and "
        "audio to this Mac. On a shared network that is an invitation.",
        "Turn off AirPlay Receiver, or set it to 'Current User' only, in "
        "General > AirDrop & Handoff.",
    ),
    (
        (49152, 49153),
        "Content Caching",
        ("sharing",),
        Severity.LOW,
        "Content Caching is serving Apple software updates to other devices on "
        "this network.",
        "Harmless at home; turn it off in Sharing if you are on a network you "
        "do not control.",
    ),
    # -- classic network services ----------------------------------------
    (
        (21,),
        "FTP",
        ("file", "legacy"),
        Severity.HIGH,
        "An FTP server. FTP sends credentials in clear text.",
        "Replace it with SFTP, or turn it off.",
    ),
    (
        (25, 465, 587),
        "SMTP",
        ("mail",),
        Severity.HIGH,
        "A mail transfer service. An open relay on a laptop is a fast route to "
        "having your address blocklisted.",
        "Bind the mail service to 127.0.0.1 unless this Mac is deliberately a "
        "mail server.",
    ),
    (
        (110, 143, 993, 995),
        "Mail retrieval (POP/IMAP)",
        ("mail",),
        Severity.MEDIUM,
        "A mail retrieval service is listening.",
        "Confirm this is deliberate; local mail clients do not need to listen.",
    ),
    (
        (53,),
        "DNS server",
        ("infrastructure",),
        Severity.HIGH,
        "This Mac is answering DNS queries. Open resolvers are used to amplify "
        "denial-of-service attacks against other people.",
        "If this is a local development resolver, bind it to 127.0.0.1.",
    ),
    (
        (161, 162),
        "SNMP",
        ("infrastructure", "legacy"),
        Severity.HIGH,
        "SNMP is listening. Version 1 and 2c have no real authentication and "
        "leak a great deal about the host.",
        "Turn SNMP off unless a monitoring system genuinely needs it.",
    ),
    (
        (111,),
        "RPC portmapper",
        ("infrastructure", "legacy"),
        Severity.MEDIUM,
        "The RPC portmapper is reachable. It enumerates other services for "
        "whoever asks, and is used for amplification attacks.",
        "Turn off NFS and other RPC services if you are not using them.",
    ),
    (
        (1900,),
        "UPnP / SSDP",
        ("infrastructure",),
        Severity.MEDIUM,
        "A UPnP or SSDP endpoint. UPnP is how devices ask routers to open "
        "ports on their behalf, often without telling anyone.",
        "Confirm which application this is. Turning UPnP off at the router is "
        "worth doing regardless.",
    ),
    (
        (5000,),
        "AirPlay Receiver or a development server",
        ("sharing", "dev"),
        Severity.MEDIUM,
        "Port 5000 is shared between macOS's own AirPlay Receiver, which lets "
        "other devices send their screen to this Mac, and Flask's development "
        "server, which has no authentication and is not built to face a "
        "network. The process name says which this is.",
        "If it is Control Center, turn off AirPlay Receiver in General > "
        "AirDrop & Handoff. If it is a development server, bind it to "
        "127.0.0.1 rather than 0.0.0.0.",
    ),
    (
        (1080, 3128, 8118),
        "Proxy server",
        ("infrastructure",),
        Severity.HIGH,
        "A SOCKS or HTTP proxy. An open proxy lets strangers send traffic that "
        "appears to come from your connection.",
        "Bind the proxy to 127.0.0.1, or require authentication.",
    ),
    (
        (32400,),
        "Plex",
        ("media",),
        Severity.MEDIUM,
        "The Plex media server. Its remote-access feature has had "
        "authentication bypasses in the past.",
        "Keep Plex updated and turn off remote access if you do not use it.",
    ),
    (
        (5060, 5061),
        "SIP telephony",
        ("media",),
        Severity.MEDIUM,
        "A SIP endpoint. Exposed SIP is scanned constantly for toll fraud.",
        "Confirm which application this is and restrict it to your VPN.",
    ),
    (
        (80, 443, 8443),
        "Web server",
        ("web",),
        Severity.MEDIUM,
        "This Mac is serving web traffic to the network.",
        "Confirm this is deliberate, and that whatever it serves is meant to "
        "be public.",
    ),
    # -- normal macOS chatter --------------------------------------------
    (
        (5353,),
        "Bonjour (mDNS)",
        ("infrastructure", "normal"),
        Severity.INFO,
        "Bonjour, which is how macOS finds printers, AirPlay targets and other "
        "Macs. It also announces this Mac's name and services to the local "
        "network.",
        "Normal. Worth knowing that it makes this Mac visible on any network "
        "you join.",
    ),
    (
        (68, 546),
        "DHCP client",
        ("infrastructure", "normal"),
        Severity.INFO,
        "The DHCP client, which is how this Mac gets an address.",
        "Normal.",
    ),
    (
        (123,),
        "Network time",
        ("infrastructure", "normal"),
        Severity.INFO,
        "The clock synchronisation service.",
        "Normal.",
    ),
    (
        (88, 749),
        "Kerberos",
        ("infrastructure", "normal"),
        Severity.INFO,
        "Kerberos, used by macOS for single sign-on.",
        "Normal on a managed Mac.",
    ),
)

_NORMAL_PORTS = {5353, 68, 546, 123, 88, 749}


def _build() -> dict[int, ServiceProfile]:
    table: dict[int, ServiceProfile] = {}
    for ports, name, tags, severity, description, guidance in _TABLE:
        for port in ports:
            table[port] = ServiceProfile(
                name=name,
                description=description,
                severity=severity,
                guidance=guidance,
                tags=tags,
                expected=port in _NORMAL_PORTS,
            )
    return table


_PORTS = _build()


# Processes worth naming whatever port they picked. Tunnelling agents in
# particular can make a loopback-only service reachable from the internet, so
# a port-based view alone would miss them.
_PROCESSES: dict[str, ServiceProfile] = {
    "ngrok": ServiceProfile(
        name="ngrok tunnel",
        description="ngrok publishes a service on this Mac to a public URL, "
        "which bypasses your router and your firewall entirely.",
        severity=Severity.HIGH,
        guidance="Stop the tunnel when you are not using it, and put "
        "authentication on whatever it exposes.",
        tags=("tunnel", "remote"),
    ),
    "cloudflared": ServiceProfile(
        name="Cloudflare Tunnel",
        description="cloudflared publishes local services to the internet "
        "through Cloudflare, around your firewall.",
        severity=Severity.MEDIUM,
        guidance="Confirm which local service the tunnel points at, and that "
        "Cloudflare Access is in front of it.",
        tags=("tunnel", "remote"),
    ),
    "localtunnel": ServiceProfile(
        name="localtunnel",
        description="localtunnel exposes a local port on a public URL with no "
        "authentication.",
        severity=Severity.HIGH,
        guidance="Stop the tunnel when it is not needed.",
        tags=("tunnel", "remote"),
    ),
    "tailscaled": ServiceProfile(
        name="Tailscale",
        description="Tailscale puts this Mac on a private mesh network. That "
        "is usually the safe way to reach it, but its access rules decide who "
        "on the mesh can.",
        severity=Severity.INFO,
        guidance="Review your tailnet ACLs, and check whether this Mac is "
        "advertising itself as an exit node or subnet router.",
        tags=("vpn", "remote"),
    ),
    "zerotier-one": ServiceProfile(
        name="ZeroTier",
        description="ZeroTier joins this Mac to a virtual network, which "
        "bypasses the local firewall boundary.",
        severity=Severity.INFO,
        guidance="Check which networks this Mac is joined to.",
        tags=("vpn", "remote"),
    ),
    "teamviewer": ServiceProfile(
        name="TeamViewer",
        description="TeamViewer allows full remote control of this Mac and "
        "keeps an outbound connection open to do it.",
        severity=Severity.MEDIUM,
        guidance="Confirm you installed this. Remote-control tools are a "
        "favourite of support scammers.",
        tags=("remote",),
    ),
    "anydesk": ServiceProfile(
        name="AnyDesk",
        description="AnyDesk allows full remote control of this Mac.",
        severity=Severity.MEDIUM,
        guidance="Confirm you installed this, and set an access password.",
        tags=("remote",),
    ),
    "rustdesk": ServiceProfile(
        name="RustDesk",
        description="RustDesk allows full remote control of this Mac.",
        severity=Severity.MEDIUM,
        guidance="Confirm you installed this deliberately.",
        tags=("remote",),
    ),
    "ollama": ServiceProfile(
        name="Ollama",
        description="Ollama's model server. Its API has no authentication.",
        severity=Severity.CRITICAL,
        guidance="Set OLLAMA_HOST=127.0.0.1 so it only answers this Mac.",
        tags=("ai", "inference"),
    ),
}


def profile_for(port: int, process: str = "") -> ServiceProfile | None:
    """The best guess at what is listening, by process first then port."""
    by_process = profile_for_process(process)
    if by_process is not None:
        return by_process
    return _PORTS.get(port)


def profile_for_process(process: str) -> ServiceProfile | None:
    name = (process or "").strip().lower()
    if not name:
        return None
    for key, profile in _PROCESSES.items():
        if key in name:
            return profile
    return None


def known_ports() -> dict[int, ServiceProfile]:
    """The whole port table. Exposed for the tests and the documentation."""
    return dict(_PORTS)
