# F4 — Multichannel Threat Detector (web + net + host)

A deterministic, offline, standard-library-only detector that merges evidence
flows from three independent log channels, runs a **cross-channel correlation
engine**, and raises severity-threshold alerts.

## Overview

- **Three fixture channels** shipped as JSONL (`web`, `net`, `host`), all using
  RFC 5737 documentation addresses and doc domains. No real network data.
- **Per-channel indicators**:
  - web — sensitive-path regex, auth failures, automation UAs
  - net — hot ports (23/22/3306/3389/445), SYN sweeps, dead bytes
  - host — risky events (`susp_kernel_module`, `new_sshd_config`,
    `auth_success` after `auth_fail`, setuid, iptables flush)
- **Correlation engine** — buckets indicators by source, clusters within a time
  window, tracks severity and the set of contributing channels, and flags
  clusters touching **two or more channels** as `CROSS`.
- **Alerting** — a cluster whose severity ≥ threshold fires a human-readable
  alert naming the source, severity, and channels.
- **Reports** — Markdown or JSON into `reports/` (gitignored). CLI exit codes:
  `0` = successful run, `1` = alerts raised in `--strict` (gate) mode,
  `2` = config/usage error. The default demo run always exits `0`.

## CLI

```bash
python3 firmware/multichannel_detector.py --help
python3 firmware/multichannel_detector.py
python3 firmware/multichannel_detector.py --threshold 10 --report reports/quiet.md
python3 firmware/multichannel_detector.py --web web.jsonl --net net.jsonl --host host.jsonl
```

Config lives in `config.json` (`window`, `threshold`). Explicit CLI flags
override the config.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## IMPORTANT: Read before use.

Provided **exclusively** for authorized security research, academic study, and
defensive monitoring of infrastructure you own or are authorized to operate.
Use without explicit written authorization is illegal and unethical.

### Authorization Requirements

Feed this detector only logs you have a lawful right to analyze. Merging,
correlating, and alerting on third-party log flows without authorization may
constitute unauthorized access and interference.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the
**Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive
on Attacks Against Information Systems** (2013/40/EU), and equivalent
legislation in other jurisdictions. Penalties include imprisonment and
significant fines.

### Acceptable Use

- Correlating web/net/host logs from your own estate
- Authorized SOC detection-engineering and purple-team exercises
- Academic research on multi-channel correlation and log fusion
- CTF competitions and educational labs on immutable synthetic fixtures

### Prohibited Use

- Ingesting or correlating logs you have no right to access
- Using the correlation engine to surveil third parties without authorization
- Building detection bypasses from the channel model against other organizations
- Any use that violates applicable law or terms of service

### No Warranty

This software is provided "as is" without warranty of any kind. The authors
assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If the detector surfaces abuse on infrastructure you do not own, preserve the
timeline and report it through the owner's incident-response channel; allow
reasonable time for remediation before any public disclosure.

## Live Lab Test Plan

1. **Demo run** — `python3 firmware/multichannel_detector.py` prints the banner,
   merges 12 fixture records, writes the report, and exits `0`.
2. **Cross-channel claim** — confirm `198.51.100.7` appears with
   `CROSS` (channels `web`, `net`) in the timeline.
3. **Gate mode** — `--strict` exits `1` when alerts fire.
4. **Threshold control** — rerun with `--threshold 999`; expect `0` alerts and
   exit `0` even with `--strict`.
4. **Determinism** — `test_merge_is_deterministic` asserts identical timelines
   across runs.
5. **Config vs CLI precedence** — `--threshold` overrides `config.json`.
6. **Offline guarantee** — no sockets, no third-party packages, RFC 5737/doc
   names only.

## Metrics

| Metric | Definition |
|--------|-----------|
| Records ingested | fixture records per channel (web/net/host) |
| Indicators | per-channel events that clear the scoring bar |
| Correlated clusters | groups of indicators sharing a source + time window |
| Cross-channel clusters | clusters touching ≥2 channels |
| Alerts | clusters with severity ≥ threshold |
| Exit codes | 0 successful demo, 1 alerts in --strict mode, 2 config error |

Verified offline: 12 records → 10 indicators → 3 clusters → 3 alerts, with one
cross-channel compromise chain detected on `198.51.100.7`.

## License

MIT License