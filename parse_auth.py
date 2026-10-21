#!/usr/bin/env python3
"""
parse_auth.py - a small SSH auth log analyser.

Reads a Linux auth log and reports three things a SOC analyst cares about:
  1. Brute force    - a source IP with a lot of failed logins
  2. Breach         - a source IP that failed a lot AND then succeeded
  3. Known bad IP   - any source IP that appears on a threat intel list

It is the Python version of the detection I built in Splunk for Lab 03,
plus an IOC (indicator of compromise) check that Splunk lab did not do.

Usage:
  python3 parse_auth.py data/auth.log
  python3 parse_auth.py data/auth.log --iocs iocs.txt --threshold 20
  python3 parse_auth.py data/auth.log --json

Exit code is 0 if nothing is found, 1 if any finding is raised, so the
script can be dropped into an automated pipeline.
"""

import argparse
import json
import re
import sys
from collections import defaultdict

# One regex pulls the pieces out of an sshd line. Example line:
# Oct 20 11:18:06 webserver01 sshd[10829]: Accepted password for admin from 203.0.113.45 port 37702 ssh2
LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+"      # timestamp: Oct 20 11:18:06
    r"\S+\s+sshd\[\d+\]:\s+"                 # host and sshd[pid]:
    r"(?P<result>Accepted|Failed)\spassword\sfor\s"   # Accepted or Failed
    r"(?:invalid user\s)?(?P<user>\S+)\s"    # username (optional 'invalid user')
    r"from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})" # source IP
)


def parse(path):
    """Walk the log once and tally failures and successes per IP."""
    stats = defaultdict(lambda: {"failures": 0, "successes": 0, "users": set()})
    parsed, skipped = 0, 0
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = LINE.search(line)
            if not m:
                skipped += 1
                continue
            parsed += 1
            ip = m.group("ip")
            rec = stats[ip]
            rec["users"].add(m.group("user"))
            if m.group("result") == "Failed":
                rec["failures"] += 1
            else:
                rec["successes"] += 1
    return stats, parsed, skipped


def load_iocs(path):
    """Load a list of known bad IPs, one per line, '#' comments allowed."""
    iocs = set()
    if not path:
        return iocs
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                iocs.add(line)
    return iocs


def analyse(stats, iocs, threshold):
    """Turn the tallies into findings."""
    findings = []
    for ip, rec in stats.items():
        if rec["failures"] >= threshold and rec["successes"] > 0:
            findings.append({
                "severity": "HIGH",
                "type": "brute_force_success",
                "ip": ip,
                "detail": f"{rec['failures']} failed then {rec['successes']} successful login(s). Likely compromise.",
                "users": sorted(rec["users"]),
            })
        elif rec["failures"] >= threshold:
            findings.append({
                "severity": "MEDIUM",
                "type": "brute_force",
                "ip": ip,
                "detail": f"{rec['failures']} failed logins, no success. Brute force attempt.",
                "users": sorted(rec["users"]),
            })
        if ip in iocs:
            findings.append({
                "severity": "HIGH",
                "type": "known_bad_ip",
                "ip": ip,
                "detail": "Source IP is on the known bad IP list (threat intel match).",
                "users": sorted(rec["users"]),
            })
    # Highest severity first
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings


def print_report(findings, parsed, skipped, ip_count):
    print("=" * 60)
    print("SSH AUTH LOG ANALYSIS")
    print("=" * 60)
    print(f"Lines parsed: {parsed}   skipped: {skipped}   unique IPs: {ip_count}")
    print("-" * 60)
    if not findings:
        print("No findings. Nothing crossed the thresholds.")
        return
    for f in findings:
        print(f"[{f['severity']}] {f['type']}  {f['ip']}")
        print(f"    {f['detail']}")
        print(f"    accounts touched: {', '.join(f['users'])}")
        print("-" * 60)
    print(f"{len(findings)} finding(s) raised.")


def main():
    ap = argparse.ArgumentParser(description="Analyse an SSH auth log for brute force and known bad IPs.")
    ap.add_argument("logfile", help="path to the auth log")
    ap.add_argument("--iocs", help="path to a known bad IP list (one per line)")
    ap.add_argument("--threshold", type=int, default=20, help="failed logins before an IP is flagged (default 20)")
    ap.add_argument("--json", action="store_true", help="output findings as JSON instead of a report")
    args = ap.parse_args()

    stats, parsed, skipped = parse(args.logfile)
    iocs = load_iocs(args.iocs)
    findings = analyse(stats, iocs, args.threshold)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print_report(findings, parsed, skipped, len(stats))

    # Non-zero exit if anything was found, so automation can react.
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
