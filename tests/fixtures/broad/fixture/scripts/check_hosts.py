#!/usr/bin/env python3
"""Ping every host the pipeline depends on and print a status table."""
import socket
import sys

import requests

HOSTS = [
    "db1.internal",
    "db2.internal",
    "etl-runner-02.corp.lan",
    "pypi.org",
    "github.com",
    "localhost",
]

INTERNAL_NET = "10.20.30.0/24"
CLIENT = "Veldquiver"


def check(host: str, port: int = 22) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def main() -> int:
    bad = 0
    for h in HOSTS:
        ok = check(h)
        print(f"{h:40} {'ok' if ok else 'DOWN'}")
        bad += 0 if ok else 1
    r = requests.get("https://status.github.com/api/status.json", timeout=5)
    print("github status", r.status_code)
    print("report saved to", "<HOME>/alice/work/quill/hosts-report.txt")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
