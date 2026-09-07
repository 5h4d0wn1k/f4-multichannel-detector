#!/usr/bin/env python3
"""
F4 — Multichannel threat detector (web + net + host).

Merges evidence flows from three log channels (web, network, host), runs a
cross-channel correlation engine that links noisy individual events into one
timeline, and raises alerts when correlated severity crosses a threshold.

Feeds are synthetic fixture JSONL (RFC 5737 addresses, doc domains). Everything
runs offline and deterministically; no sockets, no third-party packages.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# --------------------------------------------------------------------------- #
# Fixture channels (JSONL). One synthetic log line per flow record.
# --------------------------------------------------------------------------- #
WEB_FIXTURE = [
    {"ts": "2026-09-01T08:01:00Z", "channel": "web", "src": "198.51.100.7",
     "verb": "GET", "path": "/admin/config.php.bak", "status": 200, "ua": "curl/8.0"},
    {"ts": "2026-09-01T08:01:02Z", "channel": "web", "src": "198.51.100.7",
     "verb": "POST", "path": "/login", "status": 401, "ua": "curl/8.0"},
    {"ts": "2026-09-01T08:01:04Z", "channel": "web", "src": "198.51.100.7",
     "verb": "GET", "path": "/wp-login.php", "status": 200, "ua": "curl/8.0"},
    {"ts": "2026-09-01T08:02:00Z", "channel": "web", "src": "203.0.113.9",
     "verb": "GET", "path": "/index.html", "status": 200, "ua": "Mozilla/5.0"},
]

NET_FIXTURE = [
    {"ts": "2026-09-01T08:01:10Z", "channel": "net", "src": "198.51.100.7",
     "dst": "10.20.30.40", "proto": "tcp", "dport": 3306, "bytes": 4000,
     "flags": "SYN"},
    {"ts": "2026-09-01T08:01:11Z", "channel": "net", "src": "198.51.100.7",
     "dst": "10.20.30.40", "proto": "tcp", "dport": 23, "bytes": 1200,
     "flags": "SYN"},
    {"ts": "2026-09-01T08:01:30Z", "channel": "net", "src": "198.51.100.7",
     "dst": "10.20.30.41", "proto": "tcp", "dport": 443, "bytes": 500,
     "flags": "SYN"},
    {"ts": "2026-09-01T08:03:00Z", "channel": "net", "src": "203.0.113.9",
     "dst": "10.20.30.40", "proto": "tcp", "dport": 80, "bytes": 800,
     "flags": "ACK"},
]

HOST_FIXTURE = [
    {"ts": "2026-09-01T08:01:05Z", "channel": "host", "host": "websrv-01",
     "event": "susp_kernel_module", "detail": "module 'kmod_evil' loaded"},
    {"ts": "2026-09-01T08:01:06Z", "channel": "host", "host": "websrv-01",
     "event": "new_sshd_config", "detail": "/etc/ssh/sshd_config modified"},
    {"ts": "2026-09-01T08:02:30Z", "channel": "host", "host": "db-01",
     "event": "auth_fail", "detail": "user root 3 failures"},
    {"ts": "2026-09-01T08:04:00Z", "channel": "host", "host": "db-01",
     "event": "auth_success", "detail": "user root from 198.51.100.7"},
]


# --------------------------------------------------------------------------- #
# Parsers / loaders.
# --------------------------------------------------------------------------- #
def load_channel(text_or_path):
    """Parse fixture JSONL text (or a file path). Returns list of records."""
    raw = None
    if len(text_or_path) < 512 and "\n" not in text_or_path:
        try:
            if Path(text_or_path).exists():
                raw = Path(text_or_path).read_text()
        except OSError:
            raw = None
    if raw is None:
        raw = text_or_path
    recs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        recs.append(json.loads(line))
    return recs


def default_fixtures():
    return (load_channel("\n".join(json.dumps(r) for r in WEB_FIXTURE)),
            load_channel("\n".join(json.dumps(r) for r in NET_FIXTURE)),
            load_channel("\n".join(json.dumps(r) for r in HOST_FIXTURE)))


# --------------------------------------------------------------------------- #
# Per-channel indicators.
# --------------------------------------------------------------------------- #
def web_indicators(recs):
    """Score web records. Returns list of (rec, tag, severity)."""
    out = []
    sensitive = re.compile(r"/(config|wp-login|admin|\.bak|\.sql|\.env)", re.I)
    for r in recs:
        sev = 0
        if sensitive.search(r.get("path", "")):
            sev += 2
        if (r.get("verb") == "GET" and r.get("status") in (500, 401)):
            sev += 1
        if "curl" in (r.get("ua", "")).lower() or "python-requests" in r.get("ua", "").lower():
            sev += 1
        if sev:
            out.append((r, "web:%s" % r.get("path", "?"), min(sev, 5)))
    return out


def net_indicators(recs):
    """Score netflow-ish records."""
    out = []
    hot_ports = {23, 3306, 3389, 22, 445}
    for r in recs:
        sev = 0
        if r.get("proto") == "tcp" and r.get("dport") in hot_ports:
            sev += 2
        if r.get("flags") == "SYN":
            sev += 1
        if r.get("bytes", 0) == 0 and r.get("flags") == "SYN":
            sev += 1
        if sev:
            out.append((r, "net:%s:%s" % (r.get("proto"), r.get("dport")), min(sev, 5)))
    return out


def host_indicators(recs):
    out = []
    risky = ["susp_kernel_module", "new_sshd_config", "auth_success",
             "auth_fail", "new_user", "chmod_setuid", "iptables_flush"]
    for r in recs:
        ev = r.get("event", "")
        if ev in risky:
            sev = 4 if ev in ("susp_kernel_module", "new_sshd_config") else 3
            out.append((r, "host:%s" % ev, min(sev, 5)))
    return out


# --------------------------------------------------------------------------- #
# Cross-channel correlation engine.
# --------------------------------------------------------------------------- #
def correlate(channel_sets, window_sec=120, threshold=6):
    """Merge channel indicator lists; link records sharing an src host within
    a time window; raise an alert when accumulated severity passes threshold."""
    all_in = channel_sets[0] + channel_sets[1] + channel_sets[2]
    recs = sorted(all_in, key=lambda x: x[0].get("ts", ""))

    buckets = defaultdict(list)  # src -> list of records
    for rec, tag, sev in recs:
        src = rec.get("src") or rec.get("host") or "?weird"
        buckets[src].append((rec, tag, sev))

    timeline = []
    alerts = []
    for src, items in buckets.items():
        items = sorted(items, key=lambda x: x[0].get("ts", ""))
        # cluster by time window
        clusters = []
        cur, cur_t = [], None
        for rec, tag, sev in items:
            t = rec.get("ts", "")
            if cur_t is not None and _toks_diff(t, cur_t) > window_sec:
                clusters.append(cur)
                cur = []
            cur.append((rec, tag, sev))
            cur_t = t
        if cur:
            clusters.append(cur)

        for cl in clusters:
            total = sum(sev for _, _, sev in cl)
            channels = {tag.split(":")[0] for _, tag, _ in cl}
            key = src
            entry = {"src": src, "window": [cl[0][0].get("ts", ""), cl[-1][0].get("ts", "")],
                     "events": [tag for _, tag, _ in cl],
                     "severity": total, "channels": sorted(channels),
                     "cross_channel": len(channels) >= 2}
            timeline.append(entry)
            if total >= threshold:
                alerts.append({**entry,
                               "alert": "SEVERE: cross-channel compromise chain "
                                        "on %s (sev=%d, channels=%s)"
                                        % (key, total, sorted(channels))})
    timeline.sort(key=lambda e: e["window"][0])
    return timeline, alerts


def _toks_diff(ts_a, ts_b):
    """Seconds difference between two ISO-ish timestamps (fallback str)."""
    from datetime import datetime
    def as_dt(s):
        s = s.replace("Z", "+00:00")
        if "." in s:
            s = s[:s.index(".")] + s[s.index("."):][:1] + "000" + s[s.index("."):].lstrip(".")[3:]
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return 0
    da, db = as_dt(ts_a), as_dt(ts_b)
    if da == 0 or db == 0 or da == db:
        return 0
    return abs(int((da - db).total_seconds()))


# --------------------------------------------------------------------------- #
# CLI + report.
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="f4-multichannel-detector",
        description="Multichannel threat detector: merge web + net + host log "
                    "flows, correlate cross-channel, alert.",
    )
    ap.add_argument("--web", help="fixture JSONL channel (web)")
    ap.add_argument("--net", help="fixture JSONL channel (network)")
    ap.add_argument("--host", help="fixture JSONL channel (host)")
    ap.add_argument("--window", type=int, default=None,
                    help="correlation time window (seconds)")
    ap.add_argument("--threshold", type=int, default=None,
                    help="alert severity threshold")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when any alert fires (gate mode)")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--report", default="reports/report.md")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError:
            print("[config] parse error in %s" % cfg_path, file=sys.stderr)
            return 2
    window = args.window if args.window is not None else cfg.get("window", 120)
    threshold = (args.threshold if args.threshold is not None
                 else cfg.get("threshold", 6))

    if args.web and args.net and args.host:
        web = load_channel(args.web)
        net = load_channel(args.net)
        host = load_channel(args.host)
    else:
        web, net, host = default_fixtures()

    ws = web_indicators(web)
    ns = net_indicators(net)
    hs = host_indicators(host)
    timeline, alerts = correlate((ws, ns, hs),
                                 window_sec=window, threshold=threshold)

    banner = "=" * 62 + "\n  F4 - MULTICHANNEL THREAT DETECTOR\n" + "=" * 62
    lines = [banner,
             "  Channels   : web=%d net=%d host=%d records" %
             (len(web), len(net), len(host)),
             "  Indicators : web=%d net=%d host=%d" %
             (len(ws), len(ns), len(hs)),
             "  Correlated clusters : %d" % len(timeline),
             "  Alerts (sev>=%d)    : %d" % (threshold, len(alerts)),
             ""]
    lines.append("  cluster timeline (src | channels | sev | cross-channel)")
    for e in timeline:
        lines.append("    %-16s | %-10s | %4d | %s" %
                     (e["src"], ",".join(e["channels"]), e["severity"],
                      "CROSS" if e["cross_channel"] else "-"))
    lines.append("")
    lines.append("  alerts:")
    for a in alerts:
        lines.append("    !! %s" % a["alert"])
    text = "\n".join(lines)

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.report.endswith(".json"):
        out.write_text(json.dumps({"timeline": timeline, "alerts": alerts},
                                  indent=2))
    else:
        out.write_text(text)
    print(text)

    # 0 = successful run (report written), 1 = alerts (--strict only), 2 = error.
    return 1 if (alerts and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())