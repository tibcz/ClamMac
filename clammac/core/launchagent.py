"""launchd integration: login item, scheduled scans, scheduled updates.

Scheduling lives in launchd rather than in a timer inside the application, so
a weekly scan still happens on a machine where ClamMac is not left running.
launchd starts ClamMac with a command-line flag, it does the one job it was
asked to do, and it exits.

Agents are written to ``~/Library/LaunchAgents`` and loaded into the user's own
GUI domain. Nothing here needs root, and nothing is installed system-wide.
"""

from __future__ import annotations

import plistlib
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..version import APP_ID
from . import paths
from .config import Frequency, ScheduleSettings, Settings
from .log import get_logger

log = get_logger(__name__)

__all__ = ["AgentKind", "LaunchAgentError", "agent_path", "install", "is_installed", "sync_all", "uninstall"]


class AgentKind(str, Enum):
    LOGIN = "login"
    SCAN = "scan"
    UPDATE = "update"

    @property
    def label(self) -> str:
        return self.value

    @property
    def identifier(self) -> str:
        return f"{APP_ID}.{self.value}"


class LaunchAgentError(Exception):
    """A launchd agent could not be written or loaded."""


def agents_dir() -> Path:
    return paths.home() / "Library" / "LaunchAgents"


def agent_path(kind: AgentKind) -> Path:
    return agents_dir() / f"{kind.identifier}.plist"


def _executable() -> list[str]:
    """The command that re-launches ClamMac.

    From a built bundle this is the bundle's own executable. From a source
    checkout it is the current interpreter running the package, which keeps
    scheduling testable during development.
    """
    if paths.running_frozen():
        return [sys.executable]
    return [sys.executable, "-m", "clammac"]


def _calendar_interval(schedule: ScheduleSettings) -> dict | list[dict]:
    """Translate the user's schedule into launchd's StartCalendarInterval."""
    base = {"Hour": max(0, min(23, schedule.hour)), "Minute": max(0, min(59, schedule.minute))}
    if schedule.frequency is Frequency.HOURLY:
        return {"Minute": base["Minute"]}
    if schedule.frequency is Frequency.DAILY:
        return base
    if schedule.frequency is Frequency.WEEKLY:
        # launchd uses Sunday=0; Python's weekday() uses Monday=0.
        return {**base, "Weekday": (schedule.weekday + 1) % 7}
    return {**base, "Day": max(1, min(28, schedule.day_of_month))}


def _plist(kind: AgentKind, settings: Settings) -> dict:
    label = kind.identifier
    program = _executable()
    common = {
        "Label": label,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 5,
        "EnvironmentVariables": {"CLAMMAC_LAUNCHED_BY": "launchd"},
        "StandardOutPath": str(paths.logs_dir() / f"agent-{kind.value}.log"),
        "StandardErrorPath": str(paths.logs_dir() / f"agent-{kind.value}.log"),
    }

    if kind is AgentKind.LOGIN:
        return {
            **common,
            "ProgramArguments": [*program, "--background"],
            "RunAtLoad": True,
            "KeepAlive": False,
        }

    if kind is AgentKind.SCAN:
        return {
            **common,
            "ProgramArguments": [*program, "--scheduled-scan", settings.schedule.target],
            "StartCalendarInterval": _calendar_interval(settings.schedule),
            "RunAtLoad": False,
        }

    interval = settings.updates.frequency.seconds
    return {
        **common,
        "ProgramArguments": [*program, "--update-definitions"],
        "StartInterval": interval,
        "RunAtLoad": False,
    }


# --------------------------------------------------------------------------
# launchctl
# --------------------------------------------------------------------------


def _domain() -> str:
    import os

    return f"gui/{os.getuid()}"


def _launchctl(*arguments: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/bin/launchctl", *arguments],
        capture_output=True,
        text=True,
        timeout=30,
        check=check,
    )


def install(kind: AgentKind, settings: Settings) -> Path:
    """Write and load an agent, replacing any earlier version of it."""
    if not paths.is_macos():
        raise LaunchAgentError("launchd agents are only available on macOS")

    target = agent_path(kind)
    target.parent.mkdir(parents=True, exist_ok=True)
    paths.logs_dir().mkdir(parents=True, exist_ok=True)

    try:
        with target.open("wb") as handle:
            plistlib.dump(_plist(kind, settings), handle)
        target.chmod(0o644)
    except OSError as exc:
        raise LaunchAgentError(f"could not write {target.name}: {exc}") from exc

    # Unload any previous incarnation first; bootstrap refuses a label that is
    # already loaded, and the old one may have a stale schedule.
    _launchctl("bootout", f"{_domain()}/{kind.identifier}")
    result = _launchctl("bootstrap", _domain(), str(target))
    if result.returncode != 0:
        # Older systems, and some sandboxed contexts, still want load -w.
        fallback = _launchctl("load", "-w", str(target))
        if fallback.returncode != 0:
            raise LaunchAgentError(
                f"could not load {kind.value} agent: "
                f"{(result.stderr or fallback.stderr).strip()}"
            )
    log.info("installed launch agent %s", kind.identifier)
    return target


def uninstall(kind: AgentKind) -> None:
    """Unload and delete an agent, if it is there."""
    if not paths.is_macos():
        return
    target = agent_path(kind)
    _launchctl("bootout", f"{_domain()}/{kind.identifier}")
    if target.exists():
        _launchctl("unload", "-w", str(target))
        try:
            target.unlink()
        except OSError as exc:
            log.warning("could not remove %s: %s", target, exc)
    log.info("removed launch agent %s", kind.identifier)


def is_installed(kind: AgentKind) -> bool:
    return agent_path(kind).is_file()


def is_loaded(kind: AgentKind) -> bool:
    if not paths.is_macos():
        return False
    result = _launchctl("print", f"{_domain()}/{kind.identifier}")
    return result.returncode == 0


def sync_all(settings: Settings) -> dict[AgentKind, str]:
    """Make the installed agents match the current settings.

    Returns any problems keyed by agent, so the interface can report them
    without a failure in one agent preventing the others from being set up.
    """
    wanted = {
        AgentKind.LOGIN: settings.interface.launch_at_login,
        AgentKind.SCAN: settings.schedule.enabled,
        AgentKind.UPDATE: settings.updates.auto_update,
    }
    problems: dict[AgentKind, str] = {}
    for kind, enabled in wanted.items():
        try:
            if enabled:
                install(kind, settings)
            else:
                uninstall(kind)
        except LaunchAgentError as exc:
            problems[kind] = str(exc)
            log.warning("could not sync %s agent: %s", kind.value, exc)
    return problems


@dataclass(frozen=True)
class AgentStatus:
    kind: AgentKind
    installed: bool
    loaded: bool


def status(settings: Settings | None = None) -> list[AgentStatus]:
    return [AgentStatus(kind, is_installed(kind), is_loaded(kind)) for kind in AgentKind]
