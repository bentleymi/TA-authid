"""Shared collection logic for TA-authid scripted inputs (nsswitch, SSSD, Kerberos)."""
import json
import os
import re
import subprocess
import sys

NSSWITCH = "/etc/nsswitch.conf"
SSSD_MAIN = "/etc/sssd/sssd.conf"
SSSD_CONF_D = "/etc/sssd/conf.d"

DOMAIN_RE = re.compile(r"^\s*domains\s*=\s*([^\s#]+)", re.MULTILINE)
VALID_UNTIL_RE = re.compile(r"Valid until")


def read_file(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return None


def run_cmd(cmd, timeout=25):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _service_active(name):
    p = run_cmd(["systemctl", "is-active", name])
    return 1 if p is not None and p.stdout.strip() == "active" else 0


def _parse_nsswitch(text):
    rec = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in ("#", ";") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key in ("passwd", "group"):
            rec[key] = [s for s in re.split(r"[\s,]+", value.strip()) if s]
    return rec


def _sssd_domains():
    last = None
    paths = [SSSD_MAIN]
    try:
        for name in sorted(os.listdir(SSSD_CONF_D)):
            if name.endswith(".conf"):
                paths.append(os.path.join(SSSD_CONF_D, name))
    except OSError:
        pass
    for path in paths:
        text = read_file(path)
        if text is None:
            continue
        for m in DOMAIN_RE.finditer(text):
            last = m.group(1)
    if last is None:
        return []
    return [d for d in re.split(r"[\s,]+", last) if d]


def _krb_tickets():
    p = run_cmd(["klist", "-S"])
    if p is not None and p.returncode == 0 and p.stdout:
        count = 0
        for line in p.stdout.splitlines():
            if "Ticket cache" in line or "krb5cc" in line:
                count += 1
        if count:
            return count
    p = run_cmd(["klist"])
    if p is not None and p.returncode == 0 and p.stdout:
        return sum(1 for line in p.stdout.splitlines() if VALID_UNTIL_RE.search(line))
    return 0


def discover():
    rec = {"status": "ok"}
    text = read_file(NSSWITCH)
    if text is None:
        rec["status"] = "absent"
        rec["sssd_active"] = 0
        rec["sssd_domains"] = []
        rec["krb_tickets"] = 0
        rec["nscd_active"] = 0
        return rec
    ns = _parse_nsswitch(text)
    if "passwd" in ns:
        rec["nsswitch_passwd"] = ns["passwd"]
    if "group" in ns:
        rec["nsswitch_group"] = ns["group"]
    rec["sssd_active"] = _service_active("sssd")
    rec["sssd_domains"] = _sssd_domains()
    rec["krb_tickets"] = _krb_tickets()
    rec["nscd_active"] = _service_active("nscd")
    return rec


def metrics_payload(data):
    payload = {}
    for key in ("sssd_active", "krb_tickets", "nscd_active"):
        v = data.get(key)
        if v is not None:
            payload[key] = int(v)
    sources = data.get("nsswitch_passwd") or []
    payload["nsswitch_files_first"] = 1 if sources and sources[0] == "files" else 0
    return payload


def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


def fail(message):
    sys.stderr.write("TA-authid collection error: %s\n" % message)
    return 1
