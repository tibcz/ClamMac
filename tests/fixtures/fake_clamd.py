#!/usr/bin/env python3
"""A stand-in for clamd, used by the multi-core scan tests.

It reads the config ClamMac generated, listens on the socket named there, and
answers the handful of commands ClamMac sends, in the shapes ClamAV 1.5's
clamd uses: ``PONG``, a version banner, and ``<path>: OK``,
``<path>: <Signature> FOUND`` or ``<path>: <reason> ERROR`` for ``SCAN``.

File names drive the verdict, as with the fake clamscan: "infected" is a
detection, "unreadable" an error. It also records how many files it was
scanning at the same moment, which is the whole point of a multi-core scan and
so the one thing the tests most need to see.

Environment:
    FAKE_CLAMD_DELAY      seconds to spend on each file
    FAKE_CLAMD_REPORT     file to write {"max_concurrent": n, "scanned": [...]} to
    FAKE_CLAMD_FAIL       exit at once with status 2, like a broken install
    FAKE_CLAMD_LOAD       seconds to "load the database" before answering

Written for whatever ``python3`` is first on PATH, which on a stock Mac is
still 3.9, so nothing newer than that is used here.
"""
import json
import os
import socket
import sys
import threading
import time


def read_config(path):
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(" ")
            values[key] = value.strip()
    return values


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = 0
        self.max_concurrent = 0
        self.scanned = []
        self.stopping = threading.Event()


def verdict(path, delay, state):
    with state.lock:
        state.active += 1
        state.max_concurrent = max(state.max_concurrent, state.active)
    try:
        if delay:
            time.sleep(delay)
        name = os.path.basename(path)
        if not os.path.exists(path):
            return f"{path}: lstat() failed: No such file or directory. ERROR"
        if "infected" in name:
            return f"{path}: Test.Fake.Signature-1 FOUND"
        if "unreadable" in name:
            return f"{path}: Access denied. ERROR"
        return f"{path}: OK"
    finally:
        with state.lock:
            state.active -= 1
            state.scanned.append(path)


def handle(connection, delay, state, server):
    with connection:
        data = b""
        while not data.endswith(b"\x00"):
            chunk = connection.recv(4096)
            if not chunk:
                return
            data += chunk
        command = data[:-1].decode("utf-8")
        if command.startswith("z"):
            command = command[1:]
        name, _, argument = command.partition(" ")
        if name == "PING":
            reply = "PONG"
        elif name == "VERSION":
            reply = "ClamAV 1.5.4/27820/Sun Nov  8 09:00:00 2026"
        elif name == "SCAN":
            reply = verdict(argument, delay, state)
        elif name == "SHUTDOWN":
            reply = ""
            state.stopping.set()
            try:
                server.close()
            except OSError:
                pass
        else:
            reply = "UNKNOWN COMMAND"
        try:
            connection.sendall(reply.encode("utf-8") + b"\x00")
        except OSError:
            pass


def main():
    if os.environ.get("FAKE_CLAMD_FAIL"):
        return 2
    config_path = next(a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--config-file="))
    config = read_config(config_path)
    socket_path = config["LocalSocket"]
    delay = float(os.environ.get("FAKE_CLAMD_DELAY", "0"))
    report = os.environ.get("FAKE_CLAMD_REPORT", "")
    state = State()

    time.sleep(float(os.environ.get("FAKE_CLAMD_LOAD", "0")))
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(64)

    def write_report():
        if report:
            with state.lock:
                body = {"max_concurrent": state.max_concurrent, "scanned": list(state.scanned)}
            with open(report, "w", encoding="utf-8") as handle:
                json.dump(body, handle)

    import signal

    def on_term(_signum, _frame):
        write_report()
        os._exit(0)

    signal.signal(signal.SIGTERM, on_term)

    while not state.stopping.is_set():
        try:
            connection, _ = server.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(connection, delay, state, server), daemon=True).start()

    write_report()
    try:
        os.unlink(socket_path)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
