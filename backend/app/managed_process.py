"""Generic Linux process inventory and approved remediation program.

Rendered into a fixed catalog command. No incident text or model output is
evaluated. Process identity is the exact absolute argv token, owner and start
ticks. This file can also be tested directly with a temporary /proc fixture.
"""
from __future__ import annotations

import errno
import json
import os
import select
import shlex
import signal
import sys
import time
from pathlib import Path


def inventory(config, proc_root="/proc"):
    import pwd
    rows = []
    root = Path(proc_root)
    if not root.is_dir():
        raise RuntimeError("Linux /proc is required for process actions")
    for directory in root.iterdir():
        if not directory.name.isdigit() or int(directory.name) <= 1:
            continue
        try:
            argv = [value.decode("utf-8", "surrogateescape")
                    for value in (directory / "cmdline").read_bytes().split(b"\0") if value]
            if config["process_path"] not in argv:
                continue
            stat = (directory / "stat").read_text()
            fields = stat[stat.rfind(")") + 2:].split()
            if fields[0] == "Z":
                continue
            uid = directory.stat().st_uid
            owner = pwd.getpwuid(uid).pw_name
            if config.get("owner") and owner != config["owner"]:
                continue
            rows.append({"pid": int(directory.name), "start": int(fields[19]),
                         "owner": owner, "argv": argv, "ppid": int(fields[1])})
        except (FileNotFoundError, ProcessLookupError):
            continue  # Exited while being inspected.
        except (PermissionError, KeyError, IndexError, ValueError) as exc:
            raise RuntimeError("Unable to establish a matching process identity") from exc
    return sorted(rows, key=lambda row: (row["start"], row["pid"]))


def _ancestors():
    result = {os.getpid(), os.getppid()}
    pid = os.getppid()
    while pid > 1:
        try:
            text = Path("/proc", str(pid), "stat").read_text()
            pid = int(text[text.rfind(")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            break
        result.add(pid)
    return result


def terminate(config, selected, timeout):
    forbidden = _ancestors()
    if any(row["pid"] in forbidden for row in selected):
        raise RuntimeError("Refusing to signal the executor or its parent process")
    opened = []
    try:
        # Open stable PID handles where the host supports them. Validate all
        # selected identities before sending the first signal.
        for row in selected:
            fd = None
            if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                try:
                    fd = os.pidfd_open(row["pid"])
                except OSError as exc:
                    if exc.errno not in (errno.ENOSYS, errno.EINVAL):
                        raise
            opened.append((row, fd))
        current = {row["pid"]: row for row in inventory(config)}
        if any(current.get(row["pid"]) != row for row, _ in opened):
            raise RuntimeError("Process identity changed; no signal sent")
        selected_signal = getattr(signal, "SIG" + config["signal"])
        print(json.dumps({"event": "process_selection", "pids": [row["pid"] for row, _ in opened],
                          "signal": config["signal"]}), flush=True)
        for row, fd in opened:
            if fd is not None:
                signal.pidfd_send_signal(fd, selected_signal)
            else:
                # Older Linux kernels lack pidfd support. Recheck immediately
                # before each signal; this reduces but cannot eliminate races.
                current = {item["pid"]: item for item in inventory(config)}
                if current.get(row["pid"]) != row:
                    raise RuntimeError("Process identity changed before signal")
                os.kill(row["pid"], selected_signal)
            print(json.dumps({"event": "signal_sent", "pid": row["pid"], "start_ticks": row["start"]}), flush=True)
        deadline = time.monotonic() + timeout
        while True:
            current = {row["pid"]: row for row in inventory(config)}
            alive = [row["pid"] for row, fd in opened
                     if (fd is not None and not select.select([fd], [], [], 0)[0])
                     or (fd is None and current.get(row["pid"]) == row)]
            if not alive:
                return [row["pid"] for row, _ in opened]
            if time.monotonic() >= deadline:
                raise RuntimeError("Selected processes did not exit; start command was not run")
            time.sleep(0.2)
    finally:
        for _, fd in opened:
            if fd is not None:
                os.close(fd)


def run(config):
    import subprocess
    rows = inventory(config)
    if len(rows) > config["max_matches"]:
        raise RuntimeError("Process count exceeds the reviewed maximum")
    if config["operation"] == "TRIM_PROCESSES":
        # Keep the oldest matching instances. This policy is visible to admin.
        selected = rows[config["expected_count"]:]
    else:
        selected = rows
    stopped = terminate(config, selected, config["stop_timeout_seconds"])
    if config["operation"] == "RESTART_SCRIPT":
        # Refresh after stop: do not start over a concurrent auto-restart.
        if inventory(config):
            raise RuntimeError("A matching process appeared; start command was not run")
        command = config["command"]
        completed = subprocess.run(command, shell=True,
                                   timeout=config["start_timeout_seconds"],
                                   stdin=subprocess.DEVNULL)
        if completed.returncode:
            raise RuntimeError("Reviewed start command failed with exit code " + str(completed.returncode))
    print(json.dumps({"signalled_pids": stopped, "signal": config["signal"],
                      "matching_after": len(inventory(config))}))


if __name__ == "__main__":
    try:
        run(json.loads(sys.argv[1]))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
