# sigmatch

`sigmatch` matches [SigmaHQ](https://github.com/SigmaHQ/sigma) rules against
Microsoft Sysmon events in real time.  It consumes the Sysmon ETW provider
(`Microsoft-Windows-Sysmon`) through its own real-time trace session, decodes
each event with TDH, and evaluates the applicable Sigma detections locally.

It is a matching engine, not a converter: rules are evaluated directly and
alerts are emitted as text or JSONL.

## Features

* Live Sysmon ETW consumption (`live`) with ~10-25 ms reaction time.
* Loads `sigma/rules` (and optionally the emerging-threats, threat-hunting,
  compliance and DFIR collections).
* Maps Sigma Windows logsource categories to Sysmon event IDs.
* Implements the Sigma condition language used by SigmaHQ:
  `and`, `or`, `not`, parentheses, `1 of ...`, `any of ...`, `all of ...`,
  `them`, and wildcard selection patterns.
* Implements Sigma value modifiers used by the Windows rules: `contains`,
  `startswith`, `endswith`, `all`, `re`, `i`, `cased`, `windash`, `cidr`,
  `base64`, `base64offset`, `fieldref`, `exists`, `lt`/`lte`/`gt`/`gte`,
  `utf16*`, and `expand`.
* Case-insensitive string matching by default; Sigma `*`/`?` wildcards and
  backslash escaping.
* ETW events are normalised to the EventLog XML field form
  (`GrantedAccess`/`LogonId` as `0x...` hex, braced GUIDs) so Sigma rules see
  the values they expect.
* Optional PyQt6 desktop UI that follows the live feed, shows rule matches,
  and lets you inspect every event.

## Requirements

* Windows 10/11 or Windows Server.
* Python 3.9+ (tested with Python 3.14).
* `PyYAML`:

```powershell
python -m pip install -r requirements.txt
# or install the package (adds a `sigmatch` command)
python -m pip install -e .
```

Live reading needs `pyetwkit` (Sysmon ETW provider; prebuilt wheels for 64-bit
CPython 3.10-3.14). If it is missing, sigmatch installs it automatically with
pip. If Sysmon is not installed, sigmatch downloads it from
Microsoft Sysinternals, installs it with `config/sysmon-sigmatch.xml`, and
starts the service. Those steps need administrator rights, and failures are
reported with manual installation instructions.

Reading the Sysmon channel normally requires an elevated shell.  Sysmon must be
configured to log the event types you want to match.  See
`config/sysmon-sigmatch.xml` for a test-friendly configuration, or set
`SIGMATCH_SYSMON_CONFIG` to use a different configuration file. Set
`SIGMATCH_SYSMON_PATH` to use an existing `Sysmon64.exe`/`Sysmon.exe`.

## Desktop UI

The UI follows the live Sysmon channel from launch until you close the window.
It shows every event, highlights Sigma matches, and opens event fields, matched
rule details, and the raw XML when you click a row.  Rules are loaded in the
background with a progress bar.

Two checkboxes above the event list control the live view.  "Only events with
Sigma matches" is off by default and filters the table to matching events.
"Notify for high/critical matches" is on by default and sends a Windows
notification when a high or critical Sigma rule matches.  Clicking a
notification brings the window forward and selects the matching event.

```powershell
python -m pip install PyQt6
python sigmatch_gui.py --rules Z:\sigma
```

Or install the optional GUI entry point:

```powershell
python -m pip install -e ".[gui]"
sigmatch-gui --rules Z:\sigma
```

The UI requests administrator rights automatically through User Account Control,
because starting a Sysmon ETW trace session requires elevation.  Use
`--no-elevate` only for development; live reading will normally fail without
administrator rights.  If the rules cannot be found or the Sysmon channel is
unavailable, the window shows an inline message with a Retry button.

## Getting the rules

```powershell
git clone --depth 1 https://github.com/SigmaHQ/sigma.git Z:\sigma
```

The default rule location is `./sigma/rules`, then
`<tool dir>/sigma/rules`, then `<tool dir>/../sigma/rules`.  Use `--rules` to
point anywhere explicitly:

```powershell
python -m sigmatch live --rules Z:\sigma --duration 60
```

Passing a Sigma repository root loads `rules` by default.  Add
`--all-rule-sets` to also load `rules-emerging-threats`,
`rules-threat-hunting`, `rules-compliance` and `rules-dfir`.

## Usage

### Live Sysmon

```powershell
# Follow live events for 5 minutes, print human-readable alerts and stats
python -m sigmatch live --rules Z:\sigma --duration 300 --stats

# Write JSONL alerts while following live events
python -m sigmatch live --rules Z:\sigma --format json `
    --json-out Z:\alerts.jsonl

# Only medium and above, stable/test rules
python -m sigmatch live --min-level medium --status stable --status test
```

### Validate the rule set

```powershell
python -m sigmatch validate --rules Z:\sigma --verbose
```

This reports how many rules compiled, how many files were scanned, exceptions,
and the number of rules per Sysmon event ID.  It exits nonzero on compile
errors.

## How logsource mapping works

| Sigma category | Sysmon event IDs |
| --- | --- |
| `process_creation` | 1 |
| `file_change` | 2 |
| `network_connection` | 3 |
| `sysmon_status` | 4 |
| `process_termination` | 5 |
| `driver_load` | 6 |
| `image_load` | 7 |
| `create_remote_thread` | 8 |
| `raw_access_thread`, `raw_access_read` | 9 |
| `process_access` | 10 |
| `file_event` | 11 |
| `registry_add`, `registry_delete` | 12 |
| `registry_set` | 13 |
| `registry_rename` | 14 |
| `registry_event` | 12, 13, 14 |
| `create_stream_hash` | 15 |
| `pipe_created` | 17 |
| `pipe_connected` | 18 |
| `wmi_event` | 19, 20, 21 |
| `dns_query` | 22 |
| `file_delete` | 23, 26 |
| `clipboard_capture` | 24 |
| `process_tampering` | 25 |
| `file_block` | 27, 28 |
| `file_executable_detected` | 29 |
| `sysmon_error` | 255 |

Rules with `service: sysmon` use the `EventID` field in their detection to
choose the Sysmon event type.  Rules for other services (`security`, `system`,
PowerShell, etc.) are skipped because they do not describe Sysmon telemetry.
A small number of generic Windows rules (no category/service) are evaluated
against all Sysmon events.

## Notes and limitations

* Sigma processing pipelines, backend field mappings, and aggregation
  conditions (`| count() > N`) are not applied.  The rules are evaluated as
  written against Sysmon field names.
* Event 3 (network), 7 (image load), 10 (process access), etc. do not contain
  process command lines by default.  Rules that require those context fields
  only match events that carry them.
* Rule coverage depends on the Sysmon configuration.  If a Sysmon event type
  is not enabled, no matching alert can be generated.
* Sigma string matching is case-insensitive by default; use `|cased` for the
  rare case-sensitive value.  `|re` follows Sigma's case-sensitive default
  unless `|i` is present.
* Rules are found with `os.scandir` (no per-file `Path.resolve()`), read in
  parallel, parsed with PyYAML's libyaml loader when available, and compiled
  with literal fast paths instead of one regex per value.  That keeps a cold
  load of the full SigmaHQ tree to roughly a second on a local disk and a
  couple of seconds on a network share.
* Compiled rules are cached under `%LOCALAPPDATA%\sigmatch\rule-cache`
  (or `$XDG_CACHE_HOME/sigmatch/rule-cache`).  The cache is validated against
  every rule file's size and nanosecond modification time, so edits and new
  files invalidate it automatically.  A warm start takes well under a second.
  Set `SIGMATCH_RULE_CACHE=0` to bypass the cache, or
  `SIGMATCH_RULE_CACHE_DIR` to put it somewhere else.
* `live` starts its ETW session before rules are compiled, so events written
  during loading are queued and matched instead of being dropped.
* ETW has no `EventRecordID` (the EventLog service assigns it), so JSON alerts
  from `live` carry `"EventRecordID": null` and text alerts omit `record=`.
  No shipped SigmaHQ rule references that field.
* `Security_UserID` comes from the EventLog XML header and is not part of the
  Sysmon ETW payload; no shipped rule references it either.
* The desktop UI reconstructs EventLog-style XML for ETW events in the raw
  view, because ETW events have no source XML document.

## Why ETW (measured)

The EventLog service publishes channel records in batches: a subscription sees
an event ~250-485 ms (p50) after it is written, with a tail beyond 1 s.  ETW
delivers each event as Sysmon writes it.  Measured on the same triggers
(`cmd.exe /cwhoami`, Sysmon 15.x, Windows 11 VM):

| Path | transport (write -> consumer) | process create -> alert |
| --- | --- | --- |
| EventLog `EvtSubscribe` | p50 250-485 ms, max >1 s | p50 ~484 ms |
| Sysmon ETW | p50 13 ms (min 4, max 17) | p50 ~25 ms, max ~32 ms |

A burst of 300 triggers (561 events/s delivered) matched every event with
`lost=0`.  Rule matching itself is ~8 ms per process-create event (1,194 rules
apply to event ID 1), so it is now a comparable share of the total.

`pyetwkit.next_event_timeout()` holds the GIL for the whole timeout, which
starves other Python threads (a 5 ms sleeper became a 203 ms sleeper with a
200 ms timeout).  `sigmatch` therefore polls with `try_next_event()` and sleeps
in Python, which releases the GIL.

## Development

```powershell
python -m pip install -r requirements.txt
python -m pytest -q
```

The test suite includes unit tests for matchers, condition parsing, the ETW
normaliser, the rule loader, and integration tests that validate rule sets.
`tests/live_rules` contains a rule set used for manual end-to-end checks
against a real Sysmon installation.

Validation performed during development:

* 3,164 SigmaHQ rule files scanned, 1,881 Sysmon-applicable rules compiled,
  0 compile errors.
* Extended collections (`rules-emerging-threats`, `rules-threat-hunting`,
  `rules-compliance`, `rules-dfir`): 2,256 rules, 0 compile errors.
* Sysmon 15.22 live end-to-end tests matched event IDs 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 13, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 27 and 29.
* Event-ID mapping also covers 6 (driver load), 12, 14, 26, 28 and 255; those
  paths are exercised by unit tests and category mapping validation.
