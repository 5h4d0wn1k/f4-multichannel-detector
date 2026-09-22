> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F4 — Multichannel Intrusion Detector

A deterministic **intrusion detection** correlator that fuses **web, network,
and host** log evidence into a single timeline, clusters related indicators,
and raises severity-threshold alerts — offline, standard-library only.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/f4-multichannel-detector)](https://github.com/5h4d0wn1k/f4-multichannel-detector)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f4-multichannel-detector)](https://github.com/5h4d0wn1k/f4-multichannel-detector)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/f4-multichannel-detector)](https://github.com/5h4d0wn1k/f4-multichannel-detector)

## Why F4

Single-channel detections miss the attack chains that span systems: a stolen
session (web), a suspicious scan (net), and a kernel module load (host) are
individually noisy but jointly alarming. F4 ships a **cross-channel
correlation engine** that buckets indicators by source, clusters them inside a
time window, tracks severity and contributing channels, and flags clusters
touching two or more channels as `CROSS`. It's a **blue team** teaching tool
for SOC detection engineering on immutable synthetic fixtures — feed it only
logs you own or are authorized to analyze.

## Features

- **Three fixture channels** — `web`, `net`, `host` JSONL (RFC 5737/documentation addresses only)
- **Per-channel indicators** — sensitive-path regex, auth failures, hot-port scans, risky host events
- **Correlation engine** — time-window clustering with source grouping and channel tracking
- **CROSS alerts** — clusters spanning ≥2 channels reported as cross-channel compromises
- **Gate mode** — `--strict` exits 1 when alerts fire; exit 2 on config errors
- **Config-driven** — `config.json` controls window/threshold; CLI flags override
- **Reports** — Markdown or JSON into `reports/` (gitignored)
- **Deterministic & offline** — no sockets, no third-party packages

## Quickstart

```bash
# Default demo run (exit 0)
python3 firmware/multichannel_detector.py

# Tune threshold
python3 firmware/multichannel_detector.py --threshold 10 --report reports/quiet.md

# Run against your own channel files
python3 firmware/multichannel_detector.py --web web.jsonl --net net.jsonl --host host.jsonl

# CI gate mode (exits 1 when alerts fire)
python3 firmware/multichannel_detector.py --strict

# Tests
python3 -m unittest discover -s tests -v
```

Config: `config.json` (`window`, `threshold`, `alert_on_cross_channel_only`).

## Project structure

- `firmware/multichannel_detector.py` — channel loaders, indicator rules, correlation engine, CLI
- `config.json` — default window/threshold
- `tests/` — determinism, severity, gate-mode, and precedence tests

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)