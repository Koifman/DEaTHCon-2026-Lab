# DEATHCon 2026 Lab — Adversarial Detection Engineering

Companion lab for the DEATHCon 2026 workshop *"I See Your Rule, and I Raise You a Bypass"* by **Daniel Koifman** ([@KoifSec](https://koifsec.me)) and **Vadim Volkov**.

This repo contains 8 hands-on demos illustrating concrete bypass techniques from the field. Each demo includes a vulnerable detection rule, an explanation of why it fails, a hardened replacement, and exercises designed to build adversarial intuition.


---

## How to use this repo

1. **Read the [Workshop Overview](#workshop-overview) below** for context on Adversarial Detection Engineering and the ADE Framework.
2. **Pick a demo** from the table below — they're independent and can be done in any order.
3. **Try the exercises before peeking at solutions.** The whole point is to develop bypass intuition; reading the answer first defeats it.
4. **Stress-test the rule you wrote** with the [telemetry generator](#stress-test-your-rules--telemetry-generator) — it ships up to 100 varied, unique events per demo into your SIEM so you can measure your detection rate.
5. **Compare your reasoning** to the writeup in `solutions/`.

---

## Workshop Overview

**Adversarial Detection Engineering (ADE)** is the offensive practice of enumerating, reverse-engineering, and systematically bypassing detection-in-depth capabilities. The thesis: detection engineering is a non-cooperative, repeated, imperfect-information game. No single rule survives contact with a motivated adversary. Layered, behavior-focused detection is the only winning posture.

The **ADE Framework** (Bielski & Koifman) is an open taxonomy of detection logic bugs. Every demo in this repo cites which ADE category it exploits:

| Category | Name | Failure mode |
|----------|------|--------------|
| **ADE1** | Reformatting in Actions | Substring manipulation, encoding, case, character tricks. *Same outcome, different string.* |
| **ADE2** | Omit Alternatives | API alternatives, version drift, path variants, file-type swaps. *The most common category.* |
| **ADE3** | Context Development | Process cloning, aggregation hijack, timing, event fragmentation. *Adversary games the correlation layer.* |
| **ADE4** | Logic Manipulation | Gate inversion, conjunction inversion, incorrect expression. *The rule's own logical structure is wrong — wrong AND/OR composition, an inverted negation, a malformed expression.* |

---

## The Demos

| # | Demo |
|---|------|
| 1 | [Parameter Variation](demos/01-parameter-variation/) |
| 2 | [Fragmentation & Chaining](demos/02-fragmentation-chaining/) |
| 3 | [Whitespace Manipulation](demos/03-spaces/) |
| 4 | [Boolean Replacement](demos/04-boolean-replacement/) |
| 5 | [Quote Manipulation](demos/05-quote-manipulation/) |
| 6 | [Delimiter Manipulation](demos/06-delimiter-manipulation/) |
| 7 | [WSL for PowerShell](demos/07-wsl-for-powershell/) |
| 8 | [Obfuscation](demos/08-obfuscation/) |

---

## Stress-test your rules — telemetry generator

You wrote a hardened rule. Does it actually hold? [`telemetry-generator/Invoke-LabTelemetry.ps1`](telemetry-generator/Invoke-LabTelemetry.ps1) generates **synthetic telemetry** for any demo you pick, so you can run your rule against realistic data and measure how well it does.

For each lab you select it emits up to **100 varied, unique events** — a deliberate mix of:

- **evasive true-positives** — should fire your *hardened* rule while slipping the *naive* one
- **FP-trap near-misses** — look close, but a good rule fires on *neither* (e.g. `-ExecutionPolicy`, `reagentc /enable`, `/allcompartments`, `-Force` without `-Recurse`)
- **benign baseline noise** — ordinary host activity

Output is **ndjson** (one JSON event per line) using Sysmon (EID 1/11/13/23/26) and PowerShell Script Block (4104) field names. It's SIEM-agnostic — point a file monitor / uploader at the file, or one-shot import it into whatever you run.

> The script **generates log records only**. It never runs `reagentc`, `certutil`, `powershell -enc`, `wsl`, `Remove-Item`, or any other command shown in the data — the attack-looking strings exist only as fields inside the emitted events.

### Run it

```powershell
# Interactive menu (PowerShell 7 / pwsh):
./telemetry-generator/Invoke-LabTelemetry.ps1

# Windows PowerShell 5.1:
powershell -ExecutionPolicy Bypass -File .\telemetry-generator\Invoke-LabTelemetry.ps1

# Non-interactive:
./telemetry-generator/Invoke-LabTelemetry.ps1 -Labs all -OutFile all.ndjson
./telemetry-generator/Invoke-LabTelemetry.ps1 -Labs 1,5,8 -PerLab 100
```

| Flag | Meaning |
|------|---------|
| `-Labs 1,3,8` \| `all` | which demos to generate (omit for the interactive menu) |
| `-OutFile <path>` | ndjson output path (default `.\deathcon-telemetry.ndjson`) |
| `-PerLab <1-100>` | hard cap on events per lab (default 100) |
| `-IncludeGroundTruth` | tag each event with a `deathcon` answer-key object for self-grading |
| `-Seed <int>` | reproducible batch |
| `-ScriptBlockLogging On`\|`Off`\|`Mixed` | (Demo 08) whether 4104 auditing is enabled — see below. Default `Mixed` |

### Grade yourself

Run with `-IncludeGroundTruth` and each event gains a `deathcon` object:

```json
{ "demo": 5, "technique": "quote-spliced disable '/disa\"b\"le'",
  "expectation": "hardened_fires", "evades_naive": true }
```

`expectation` is one of `hardened_fires`, `fp_trap`, `baseline`, `bypass_static` (a bypass no *static* rule catches — only behavioral/AMSI, e.g. the superscript-folded `certutil` cradle), or `blind_no_sbl` (see below). Your rule should fire on **every** `hardened_fires` event and stay silent on **every** `fp_trap` and `baseline`. Leave the flag off for a blind run.

### Demo 08 and Script Block Logging (4104)

Demo 08's Layer-1 rule reads `ScriptBlockText` (Event 4104) — which only exists if **PowerShell Script Block Logging is enabled**. The generator models that precondition with `-ScriptBlockLogging`:

- **`On`** — every obfuscated script emits a 4104 event; your script-content rule can match it.
- **`Off`** — **no 4104 is emitted at all**. The only trace of each obfuscated exec is the `powershell.exe` **process-creation (EID 1)** event, with the payload either on the command line (`-Command`) or hidden inside `-EncodedCommand`. A 4104-based rule fires on *nothing* — the "obfuscation wins without SBL" lesson, made literal. These events are tagged `blind_no_sbl`.
- **`Mixed`** (default) — SBL state is decided per host, so some obfuscated execs log 4104 and some don't, like a real estate with inconsistent GPO coverage.

The takeaway for participants: if your only Demo-08 detection is a 4104 `ScriptBlockText` rule, measure your detection rate under `-ScriptBlockLogging Off` — the gap you see is your dependence on an audit setting the attacker may have disabled (or that was never turned on). That's exactly why the solution pairs the 4104 rule with process-creation and behavioral layers.

### What each lab emits

| # | Demo | Telemetry generated |
|---|------|---------------------|
| 1 | Parameter Variation | process_creation (EID 1) — `EncodedCommand` flag equivalence class |
| 2 | Fragmentation & Chaining | FileCreate (EID 11) → ProcessCreate (EID 1) of the freshly-written script, correlated ≤30s |
| 3 | Whitespace Manipulation | process_creation (EID 1) — multi-space / tab / zero-space recon |
| 4 | Boolean Replacement | ScriptBlock (4104) `-Force`/`-Recurse` forms + mass FileDeleteDetected (EID 26) burst |
| 5 | Quote Manipulation | process_creation (EID 1) `reagentc`/`bcdedit` + side-effect EID 11 (`ReAgent.xml`) / EID 13 (BCD hive) |
| 6 | Delimiter Manipulation | process_creation (EID 1) — recon chains sharing one parent within 60s |
| 7 | WSL for PowerShell | process_creation (EID 1) `wsl.exe` + FileCreate (EID 11) drop in `C:\Users\Public\`, ≤5m, same host |
| 8 | Obfuscation | ScriptBlock (4104) construction primitives + obfuscated `certutil` process_creation — honours the `-ScriptBlockLogging` state (4104 present vs EID 1 only) |


---

## Solutions

[`solutions/README.md`](solutions/README.md) contains worked answers for every exercise. **Read it last.**


<img width="1542" height="575" alt="image" src="https://github.com/user-attachments/assets/5e6231bf-21d2-4800-bb3a-f989ad0c7965" />
