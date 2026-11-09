"""Managing ``clamd`` and speaking its protocol.

``clamscan`` loads the whole signature database -- a few hundred megabytes --
every time it starts, which costs ten to thirty seconds before it looks at a
single byte. That is fine for a scheduled full scan and useless for real-time
protection, where a file needs a verdict in milliseconds.

``clamd`` solves that by holding the database in memory and answering over a
local socket. ClamMac runs its own copy as the logged-in user, with its own
config and its own socket inside the support directory: no system daemon, no
root, and nothing shared with other accounts on the machine.

The protocol is text over a Unix socket. Commands are sent with a ``z`` prefix
and NUL-terminated, which is the framing ClamAV documents as preferred.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import engine as engine_module
from . import paths
from .log import get_logger

log = get_logger(__name__)

__all__ = ["ClamdClient", "ClamdDaemon", "ClamdError", "ScanVerdict"]

_TERMINATOR = b"\x00"
_INSTREAM_CHUNK = 1 << 16
_MAX_REPLY = 1 << 20


class ClamdError(Exception):
    """The daemon could not be reached, or refused a command."""


@dataclass(frozen=True)
class ScanVerdict:
    """What clamd said about one path."""

    path: str
    infected: bool
    signature: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.infected and not self.error


class ClamdClient:
    """A thin, synchronous client for a local clamd socket."""

    def __init__(self, socket_path: Path | None = None, *, timeout: float = 120.0) -> None:
        self.socket_path = Path(socket_path) if socket_path else paths.runtime_dir() / "clamd.sock"
        self.timeout = timeout

    # -- plumbing ---------------------------------------------------------

    @contextlib.contextmanager
    def _connection(self):
        if not self.socket_path.exists():
            raise ClamdError("clamd is not running (its socket does not exist)")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            yield connection
        except (TimeoutError, OSError) as exc:
            raise ClamdError(f"could not talk to clamd: {exc}") from exc
        finally:
            with contextlib.suppress(OSError):
                connection.close()

    @staticmethod
    def _send(connection: socket.socket, command: str) -> None:
        connection.sendall(b"z" + command.encode("utf-8") + _TERMINATOR)

    @staticmethod
    def _read(connection: socket.socket) -> str:
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = connection.recv(4096)
            except TimeoutError as exc:
                raise ClamdError("clamd stopped responding") from exc
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_REPLY:
                break
        return b"".join(chunks).replace(_TERMINATOR, b"\n").decode("utf-8", "replace").strip()

    def _command(self, command: str) -> str:
        with self._connection() as connection:
            self._send(connection, command)
            return self._read(connection)

    # -- commands ---------------------------------------------------------

    def ping(self) -> bool:
        try:
            return self._command("PING").strip() == "PONG"
        except ClamdError:
            return False

    def version(self) -> str:
        return self._command("VERSION")

    def stats(self) -> str:
        return self._command("STATS")

    def reload(self) -> bool:
        """Ask clamd to re-read the databases after an update."""
        try:
            return "RELOADING" in self._command("RELOAD")
        except ClamdError:
            return False

    def shutdown(self) -> None:
        with contextlib.suppress(ClamdError):
            self._command("SHUTDOWN")

    def scan_path(self, path: Path, *, multiscan: bool = False) -> list[ScanVerdict]:
        """Scan a file or directory that clamd can read directly."""
        command = "MULTISCAN" if multiscan else "CONTSCAN"
        reply = self._command(f"{command} {path}")
        return _parse_verdicts(reply, str(path))

    def scan_file(self, path: str) -> ScanVerdict:
        """Scan exactly one regular file and return clamd's verdict on it.

        The reply is matched against the path that was sent rather than split
        on line breaks, so a file whose name contains a newline or ``": "``
        still gets the right verdict.
        """
        return _parse_single_verdict(self._command(f"SCAN {path}"), path)

    def scan_stream(self, path: Path) -> ScanVerdict:
        """Send a file's contents to clamd over the socket.

        Used when clamd may not be able to read the file itself -- anything
        under a folder macOS gates behind a privacy prompt, for instance.
        """
        try:
            size = path.stat().st_size
        except OSError as exc:
            return ScanVerdict(str(path), False, error=str(exc))

        with self._connection() as connection:
            self._send(connection, "INSTREAM")
            try:
                with path.open("rb") as handle:
                    while True:
                        chunk = handle.read(_INSTREAM_CHUNK)
                        if not chunk:
                            break
                        connection.sendall(struct.pack("!L", len(chunk)) + chunk)
                connection.sendall(struct.pack("!L", 0))
            except OSError as exc:
                return ScanVerdict(str(path), False, error=f"could not read the file: {exc}")
            reply = self._read(connection)

        verdicts = _parse_verdicts(reply.replace("stream:", f"{path}:"), str(path))
        if verdicts:
            return verdicts[0]
        return ScanVerdict(str(path), False, error=f"clamd gave no verdict for {size} bytes")


def _parse_single_verdict(reply: str, path: str) -> ScanVerdict:
    """Read clamd's answer to ``SCAN`` on one file."""
    text = reply.strip()
    prefix = f"{path}: "
    body = text[len(prefix) :] if text.startswith(prefix) else text.rpartition(": ")[2] or text
    if body.endswith(" FOUND"):
        signature = body[: -len(" FOUND")].strip()
        if signature.endswith("(Multiple)"):
            signature = signature[: -len("(Multiple)")].strip()
        return ScanVerdict(path, True, signature=signature)
    if body == "OK":
        return ScanVerdict(path, False)
    if body.endswith(" ERROR"):
        return ScanVerdict(path, False, error=body[: -len(" ERROR")].strip())
    return ScanVerdict(path, False, error=body or "clamd gave no verdict")


def _parse_verdicts(reply: str, fallback_path: str) -> list[ScanVerdict]:
    verdicts: list[ScanVerdict] = []
    for line in reply.splitlines():
        text = line.strip()
        if not text:
            continue
        if text.endswith(" FOUND"):
            head, _, _ = text.rpartition(" FOUND")
            path, _, signature = head.rpartition(": ")
            verdicts.append(
                ScanVerdict(path or fallback_path, True, signature=signature.strip())
            )
        elif text.endswith(" ERROR"):
            head, _, _ = text.rpartition(" ERROR")
            path, _, detail = head.rpartition(": ")
            verdicts.append(ScanVerdict(path or fallback_path, False, error=detail.strip()))
        elif text.endswith(": OK"):
            path = text[: -len(": OK")]
            verdicts.append(ScanVerdict(path or fallback_path, False))
    return verdicts


class ClamdDaemon:
    """Starts, stops and supervises ClamMac's private clamd process."""

    def __init__(
        self,
        tools: engine_module.EngineTools,
        *,
        name: str = "clamd",
        max_threads: int = 4,
        low_priority: bool = False,
    ) -> None:
        self.tools = tools
        self.name = name
        self.max_threads = max_threads
        self.low_priority = low_priority
        self.socket_path = paths.runtime_dir() / f"{name}.sock"
        self.client = ClamdClient(self.socket_path)
        self._process: subprocess.Popen[bytes] | None = None
        self._lock = threading.RLock()

    @property
    def available(self) -> bool:
        return self.tools.clamd is not None

    def is_running(self) -> bool:
        """True when something is listening and answering on the socket."""
        return self.client.ping()

    def start(self, *, settings=None, timeout: float = 180.0) -> bool:
        """Start clamd and wait until it answers.

        Loading the database takes a while on first start; the timeout is
        generous because failing early here would silently disable real-time
        protection on a slower machine.
        """
        with self._lock:
            if self.is_running():
                return True
            if self.tools.clamd is None:
                raise ClamdError("this ClamAV installation does not include clamd")

            config = engine_module.write_clamd_conf(
                settings=settings, name=self.name, max_threads=self.max_threads
            )
            self._clear_stale_socket()

            prefix = ["/usr/bin/nice", "-n", "10"] if self.low_priority else []
            log.info("starting %s with %s", self.name, config)
            self._process = subprocess.Popen(
                [*prefix, str(self.tools.clamd), f"--config-file={config}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                env=engine_module._clean_env(),
            )

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    raise ClamdError(
                        f"clamd exited immediately with status {self._process.returncode}. "
                        f"See {paths.logs_dir() / (self.name + '.log')} for details."
                    )
                if self.client.ping():
                    log.info("%s is ready", self.name)
                    return True
                time.sleep(0.5)

            self.stop()
            raise ClamdError("clamd did not become ready in time")

    def stop(self) -> None:
        """Ask clamd to shut down, then make sure it did."""
        with self._lock:
            with contextlib.suppress(Exception):
                self.client.shutdown()

            process = self._process
            if process is not None and process.poll() is None:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(OSError, ProcessLookupError):
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        process.wait(timeout=5)
            self._process = None
            self._clear_stale_socket()

    def kill(self) -> None:
        """Stop the daemon at once, abandoning whatever it is scanning.

        ``stop`` lets clamd finish its current files, which is right for
        real-time protection and far too slow for a cancelled full scan, where
        a single large archive can keep it busy for minutes.
        """
        # Deliberately signalled outside the lock: ``start`` holds it for as
        # long as the database takes to load, and a cancel must not wait for
        # that. Killing the process is also what makes ``start`` give up.
        process = self._process
        if process is not None and process.poll() is None:
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(OSError, ProcessLookupError):
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
        with self._lock:
            if self._process is process:
                self._process = None
            self._clear_stale_socket()

    def restart(self, *, settings=None) -> bool:
        self.stop()
        return self.start(settings=settings)

    def _clear_stale_socket(self) -> None:
        """Remove a socket file left behind by a daemon that did not exit cleanly."""
        if self.socket_path.exists() and not self.client.ping():
            with contextlib.suppress(OSError):
                self.socket_path.unlink()
