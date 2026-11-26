"""Tests for the Sysmon ETW path (no Windows ETW session required)."""

from __future__ import annotations

from datetime import datetime, timezone

from sigmatch.events import (
    event_from_etw,
    normalize_etw_value,
    render_event_xml,
)
from sigmatch.rules import RuleSet, load_rules

TS = datetime(2026, 11, 26, 14, 2, 56, 563292, tzinfo=timezone.utc)

# TDH hands these over as native types; the EventLog XML has strings.
PROCESS_ACCESS_PROPS = {
    "RuleName": "-",
    "UtcTime": "2026-11-26 14:02:56.560",
    "ProcessGuid": "b75a7b4b-437b-6b08-bb0c-000000003f00",
    "ProcessId": 5496,
    "Image": "C:\\Windows\\System32\\taskmgr.exe",
    "TargetProcessGuid": "b75a7b4b-437b-6b08-1f0c-000000003f00",
    "TargetProcessId": 1121,
    "GrantedAccess": 5136,
    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9dab4|C:\\Windows\\SYSTEM32\\KERNELBASE.dll+28d3e",
    "SourceThreadId": 4264,
}

def test_normalize_etw_value_hex_fields():
    assert normalize_etw_value("GrantedAccess", 5136) == "0x1410"
    assert normalize_etw_value("GrantedAccess", 0x1FFFFF) == "0x1fffff"
    assert normalize_etw_value("LogonId", 0x586E7) == "0x586e7"


def test_normalize_etw_value_plain_ints_and_bools():
    assert normalize_etw_value("ProcessId", 5496) == "5496"
    assert normalize_etw_value("Signed", True) == "true"
    assert normalize_etw_value("IsExecutable", False) == "false"


def test_normalize_etw_value_braces_guids():
    guid = "b75a7b4b-437b-6b08-bb0c-000000003f00"
    assert normalize_etw_value("ProcessGuid", guid) == "{" + guid + "}"
    # Already-braced values are left alone.
    assert normalize_etw_value("ProcessGuid", "{" + guid + "}") == "{" + guid + "}"
    # A GUID embedded in a larger string is not a GUID field.
    assert normalize_etw_value("CallTrace", "x|" + guid) == "x|" + guid


def test_event_from_etw_synthesises_metadata():
    event = event_from_etw(10, PROCESS_ACCESS_PROPS, TS, computer="TESTHOST")
    assert event.event_id == 10
    assert event.record_id is None  # ETW has no EventRecordID
    assert event.timestamp == TS
    assert event.channel == "Microsoft-Windows-Sysmon/Operational"
    assert event.provider == "Microsoft-Windows-Sysmon"
    assert event.get("EventID") == "10"
    assert event.get("Provider_Name") == "Microsoft-Windows-Sysmon"
    assert event.get("ProviderName") == "Microsoft-Windows-Sysmon"
    assert event.get("Computer") == "TESTHOST"
    assert event.get("TimeCreated") == TS.isoformat()
    # The ETW payload's own UtcTime wins over the trace timestamp.
    assert event.get("UtcTime") == "2026-11-26 14:02:56.560"


def test_etw_normalisation_matches_eventlog_values():
    event = event_from_etw(10, PROCESS_ACCESS_PROPS, TS, computer="TESTHOST")
    assert event.get("ProcessGuid") == "{b75a7b4b-437b-6b08-bb0c-000000003f00}"
    assert event.get("TargetProcessGuid") == "{b75a7b4b-437b-6b08-1f0c-000000003f00}"
    assert event.get("GrantedAccess") == "0x1410"
    assert event.get("ProcessId") == "5496"
    assert event.get("TargetProcessId") == "1121"
    assert event.get("CallTrace") == PROCESS_ACCESS_PROPS["CallTrace"]


RULE = r"""title: ETW parity rule
id: 99999999-9999-9999-9999-999999999999
status: test
level: high
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1410'
  condition: selection
"""


def test_etw_event_matches_rule(tmp_path):
    """A rule using GrantedAccess matches the normalised ETW encoding."""

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.yml").write_text(RULE, encoding="utf-8")
    ruleset = RuleSet(load_rules([rules_dir]).rules)

    props = dict(PROCESS_ACCESS_PROPS, TargetImage=r"C:\Windows\System32\lsass.exe")
    etw_event = event_from_etw(10, props, TS)
    assert [r.title for r in ruleset.match(10, etw_event.lookup)] == ["ETW parity rule"]


def test_render_event_xml():
    etw_event = event_from_etw(10, PROCESS_ACCESS_PROPS, TS, computer="TESTHOST")
    rendered = render_event_xml(etw_event)
    assert rendered.startswith("<Event ")
    assert "EventRecordID" not in rendered  # ETW has none
    assert "<EventID>10</EventID>" in rendered
    assert 'Name="CommandLine"' not in rendered
    assert 'Name="GrantedAccess"' in rendered and ">0x1410</Data>" in rendered


def test_event_from_etw_skips_empty_properties():
    event = event_from_etw(1, {"Image": None, "CommandLine": "cmd.exe /cwhoami"}, TS)
    assert event.get("CommandLine") == "cmd.exe /cwhoami"
    assert event.get("Image") is None
