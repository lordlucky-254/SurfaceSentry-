#!/usr/bin/env python3
"""Check whether targets fall inside an authorized scope file.

Always verify scope BEFORE running any scan or test.
Exit code is 0 if every target is in scope, 1 otherwise.
"""
import argparse
import ipaddress
import sys


def load_scope(path):
    networks, domains = [], []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                domains.append(line.lower())
    return networks, domains


def in_scope(target, networks, domains):
    target = target.lower()
    try:
        ip = ipaddress.ip_address(target)
        return any(ip in net for net in networks)
    except ValueError:
        pass
    for d in domains:
        if d.startswith("*."):
            if target.endswith(d[1:]):
                return True
        elif target == d:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Path to scope file")
    parser.add_argument("targets", nargs="+", help="IPs or domains to check")
    args = parser.parse_args()

    networks, domains = load_scope(args.scope)
    all_ok = True
    for t in args.targets:
        ok = in_scope(t, networks, domains)
        all_ok &= ok
        print(f"[{'IN SCOPE' if ok else 'OUT OF SCOPE'}] {t}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
