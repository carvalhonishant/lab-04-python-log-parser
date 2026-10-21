# Python SSH Log Parser with IOC Matching

I wrote a Python tool that reads an SSH auth log and raises security findings: brute force attempts, likely breaches, and matches against a known bad IP list. It is the same detection I built in Splunk for Lab 03, rebuilt in code, with a threat intel check added on top. Run against the sample log it flags one external IP that brute forced its way in and also sits on the bad IP list.

I am an IT support engineer moving into security. I did this one to show I can write the detection logic myself, not only inside a SIEM, and to practice the Python that security automation relies on.

## What it does

The tool walks the log once and, for every source IP, counts failed and successful logins and the accounts touched. Then it raises three kinds of finding:

| Finding | Logic | Severity |
|---|---|---|
| Brute force | failures at or above the threshold, no success | MEDIUM |
| Brute force with success | failures at or above the threshold, then a success | HIGH |
| Known bad IP | the source IP is on the threat intel list | HIGH |

The first two are behavioural, they look at what the IP did. The third is intelligence, it checks who the IP is. A real SOC uses both, so the tool does both.

## Running it

```bash
python3 parse_auth.py data/auth.log --iocs iocs.txt
```

Output:

```
[HIGH] brute_force_success  203.0.113.45
    120 failed then 1 successful login(s). Likely compromise.
    accounts touched: admin, ftpuser, git, jenkins, mysql, oracle, postgres, root, test, ubuntu
[HIGH] known_bad_ip  203.0.113.45
    Source IP is on the known bad IP list (threat intel match).
```

Options:
- `--threshold N` sets how many failures before an IP is flagged (default 20)
- `--iocs FILE` points at the known bad IP list
- `--json` prints findings as JSON for piping into other tools

The script exits with code 1 when it finds something and 0 when it does not, so it can drop straight into an automated pipeline that reacts to a nonzero exit.

## How it works

- A single regular expression pulls the timestamp, result, username and source IP out of each `sshd` line. Lines that are not login attempts (session opened, disconnect, sftp) do not match and are counted as skipped rather than treated as errors.
- Results are tallied per IP in one pass, so the tool stays fast on large logs.
- The IOC list is a plain text file, one IP per line with `#` comments. In a real setup that file would be fed from a source like AbuseIPDB or an internal blocklist. It is static here to keep the lab self contained.

## Proving the two detections are independent

Raising the threshold above the attack volume drops the brute force finding but the IOC match still fires:

```bash
python3 parse_auth.py data/auth.log --iocs iocs.txt --threshold 200
```

```
[HIGH] known_bad_ip  203.0.113.45
1 finding(s) raised.
```

That is the point. Behaviour and threat intel are two separate ways to catch the same attacker, and either one on its own can be the thing that flags a host.

## What this maps to

- Brute force is **MITRE ATT&CK T1110**, and a successful login after it is **Valid Accounts (T1078)**
- The IOC match is basic threat intelligence enrichment, the same idea as a SIEM checking events against a blocklist
- Writing the parser shows the Python, regex and data handling that security automation and tooling roles ask for

## What I would do next

- Pull the IOC list live from a real feed instead of a static file
- Support more log types (web server logs, Windows event logs) behind the same finding format
- Add a detection for a successful login from an IP never seen before for that account
- Output findings in a format a SIEM can ingest, so this becomes a feeder rather than a standalone script

## Skills this shows

Python (argparse, regex, file handling, JSON output), log parsing, writing detection logic from scratch, threat intel matching, and building a tool that fits into automation through exit codes and machine readable output.

---

*Sample log is generated and the IOC list is dummy data. No real systems or live threat feeds involved.*
