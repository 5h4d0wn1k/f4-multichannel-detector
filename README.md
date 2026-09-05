# F4 — Multi-Channel eBPF Rootkit Detector (Rust-style, SPiCa-class)

Pure-Python simulation of a multi-channel rootkit detector that observes kernel state through three independent channels and flags rootkits when channels disagree or heartbeats vanish.

## Overview

- Models a kernel rootkit hiding in /proc while running live processes, exactly as real rootkits behave
- Implements three simulated detection channels:
  - **A — eBPF-tracepoint-style sensors**: per-process syscall activity stream
  - **B — /proc cross-view reconciler**: parses a fake /proc view (with the rootkit's edits applied)
  - **C — hardware-timer heartbeat**: a periodic pulse that a stealthy rootkit fails to fully suppress
- Detects a rootkit when (1) the syscall stream and /proc disagree about which processes exist/are silent, or (2) heartbeat pulses vanish or drop below a health window
- Emits a **detection matrix** including channel-suppression cases: when the rootkit kills channel A, channels B/C still catch it
- Documents the **Rust + eBPF production integration point** (1:1 signal-flow mapping to `tracepoint:sys_enter_*`, `bpf_iter` process snapshots, and per-CPU hrtimer pulses)
- Fully offline, deterministic, standard-library only

## Features

- **SyscallSensor (channel A)**: per-process `{pid, comm, syscalls}` activity stream; supports rootkit-muted delivery
- **ProcView (channel B)**: dictionary-based /proc snapshot the attacker can edit (pid-dir removal)
- **TimerHeartbeat (channel C)**: per-epoch pulse generator with vanishing / weakened states
- **MultiChannelDetector**: fuses cross-view disagreement sets (A↔B), heartbeat gap-window logic (C), and produces a fused `CLEAN`/`SUSPECT` verdict per epoch
- **Detection Matrix**: baseline, proc-hide, and one-channel/three-channel suppression rows
- **Channel-Suppression Report**: attacker kills A, B, or C — the surviving channels still raise SUSPECT
- **Production Integration Note**: explicit Rust/eBPF mapping of every simulated channel
- **Zero Dependencies**: Python standard library only

## Installation

No external dependencies required — uses Python standard library only.

```bash
python3 firmware/multichannel_detector.py
```

## Usage

```python
from firmware.multichannel_detector import (SyscallSensor, ProcView,
                                            TimerHeartbeat,
                                            MultiChannelDetector,
                                            build_scenario)

procs, events, _, _, _ = build_scenario(17, hide_proc=True)  # rootkit hides
a = SyscallSensor(events)
b = ProcView(procs)
c = TimerHeartbeat(seed=3, base_pulse=6)

syscall_map = {s["pid"]: s["syscalls"] for s in a.stream()}
verdicts, evidence = MultiChannelDetector().fuse_epoch(
    syscall_map, b.list(), list(c.pulses(1)))
print(verdicts)     # -> includes VERDICT:SUSPECT
```

## Example Output

```
======================================================================
  F4 - MULTI-CHANNEL ROOTKIT DETECTOR (SPiCa-class)
======================================================================
Scenario                         | Fused channel verdicts
----------------------------------------------------------------------
baseline (no rootkit)            | A/B-AGREE; HEARTBEAT-OK; VERDICT:CLEAN
rk edits /proc (hide pid)        | A/B-CROSS-A (syscalls see pid, /proc does not); HEARTBEAT-OK; VERDICT:SUSPECT
rk kills channel A (tracepoints) | A/B-CROSS-B (/proc lists pid, syscalls silent); HEARTBEAT-OK; VERDICT:SUSPECT
rk kills channel B (/proc view)  | A/B-CROSS-A (syscalls see pid, /proc does not); HEARTBEAT-OK; VERDICT:SUSPECT
rk kills channel C (heartbeat)   | A/B-AGREE; HEARTBEAT-VANISHED; VERDICT:SUSPECT
rk suppresses A+B, C fails       | A/B-CROSS-B; HEARTBEAT-WEAK; VERDICT:SUSPECT
----------------------------------------------------------------------
  CHANNEL-SUPPRESSION CASES (attacker disables a channel)
----------------------------------------------------------------------
  Dead channel A          | A/B-CROSS-B; HEARTBEAT-OK; VERDICT:SUSPECT
  Dead channel B          | A/B-CROSS-A; HEARTBEAT-OK; VERDICT:SUSPECT
  Dead channel C          | A/B-CROSS-A; HEARTBEAT-VANISHED; VERDICT:SUSPECT
```

## IMPORTANT: Read before use.

This tool is provided **exclusively** for authorized security research, academic study, and defensive hardening. Use without explicit written authorization is illegal and unethical.

### Authorization Requirements

Run this detector only on systems you own or are explicitly authorized to monitor. Deploying rootkit-detector probes, low-level process walking, or heartbeat instrumentation against third-party hosts without authorization may violate applicable law and host policies. Do not use the channel/rootkit models to build hiding techniques against systems you do not own.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the **Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive on Attacks Against Information Systems** (2013/40/EU), and equivalent legislation in other jurisdictions. Penalties include imprisonment and significant fines.

### Acceptable Use

- Authorized forensic analysis of your own hosts for rootkit presence
- Defensive monitoring of your own infrastructure with multi-channel probes
- Academic research on kernel-level detection and eBPF-based observability
- CTF competitions and controlled lab environments
- Building production defense tooling in Rust + eBPF from the signal-flow model

### Prohibited Use

- Deploying detection probes on third-party hosts without authorization
- Using the suppression/rootkit models to develop or deploy hiding techniques
- Tampering with /proc, syscall streams, or timers on systems you do not own
- Weaponizing channel-suppression techniques against another organization's monitoring

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If you discover rootkit techniques, kernel hiding methods, or detector blind spots in third-party products using this tool, follow coordinated disclosure practices. Report to the vendor directly and allow reasonable time for remediation before public disclosure.

## License

MIT License