"""Tests for the Sysmon ETW path (no Windows ETW session required)."""

from __future__ import annotations

from datetime import datetime, timezone

from sigmatch.events import (
    event_from_etw,
    normalize_etw_value,
    parse_event_xml,
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

# The same event as written to Microsoft-Windows-Sysmon/Operational.
PROCESS_ACCESS_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Sysmon'/><EventID>10</EventID><EventRecordID>281957</EventRecordID>
<TimeCreated SystemTime='2026-11-26T14:02:56.5632926Z'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>TESTHOST</Computer></System><EventData>
<Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-11-26 14:02:56.560</Data>
<Data Name='ProcessGuid'>{b75a7b4b-437b-6b08-bb0c-000000003f00}</Data>
<Data Name='ProcessId'>5496</Data><Data Name='Image'>C:\\Windows\\System32\\taskmgr.exe</Data>
<Data Name='TargetProcessGuid'>{b75a7b4b-437b-6b08-1f0c-000000003f00}</Data>
<Data Name='TargetProcessId'>1121</Data><Data Name='GrantedAccess'>0x1410</Data>
<Data Name='CallTrace'>C:\\Windows\\SYSTEM32\\ntdll.dll+9dab4|C:\\Windows\\SYSTEM32\\KERNELBASE.dll+28d3e</Data>
<Data Name='SourceThreadId'>4264</Data></EventData></Event>"""


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
    # Already-braced values (e.g. from a JSON replay) are left alone.
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


def test_etw_and_xml_agree_on_rule_fields():
    """The ETW event must look exactly like the XML one to Sigma selectors."""

    xml_event = parse_event_xml(PROCESS_ACCESS_XML)
    etw_event = event_from_etw(10, PROCESS_ACCESS_PROPS, TS, computer="TESTHOST")
    # EventRecordID is assigned by the EventLog service, not ETW.
    assert set(xml_event.lookup) - set(etw_event.lookup) == {"eventrecordid"}
    assert set(etw_event.lookup) - set(xml_event.lookup) == set()
    for name, value in etw_event.lookup.items():
        assert xml_event.lookup[name] == value, name


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


def test_etw_event_matches_like_xml_event(tmp_path):
    """A rule using GrantedAccess matches the ETW and XML encodings alike."""

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.yml").write_text(RULE, encoding="utf-8")
    ruleset = RuleSet(load_rules([rules_dir]).rules)

    props = dict(PROCESS_ACCESS_PROPS, TargetImage=r"C:\Windows\System32\lsass.exe")
    etw_event = event_from_etw(10, props, TS)
    assert [r.title for r in ruleset.match(10, etw_event.lookup)] == ["ETW parity rule"]

    xml = PROCESS_ACCESS_XML.replace(
        "<Data Name='TargetProcessGuid'>",
        r"<Data Name='TargetImage'>C:\Windows\System32\lsass.exe</Data>"
        "<Data Name='TargetProcessGuid'>",
    )
    assert [r.title for r in ruleset.match(10, parse_event_xml(xml).lookup)] == [
        "ETW parity rule"
    ]


def test_render_event_xml_round_trips():
    etw_event = event_from_etw(10, PROCESS_ACCESS_PROPS, TS, computer="TESTHOST")
    rendered = render_event_xml(etw_event)
    assert rendered.startswith("<Event ")
    assert "EventRecordID" not in rendered  # ETW has none
    reparsed = parse_event_xml(rendered)
    assert reparsed.event_id == 10
    assert reparsed.data == etw_event.data
    assert 'Name="GrantedAccess"' in rendered and ">0x1410</Data>" in rendered


def test_event_from_etw_skips_empty_properties():
    event = event_from_etw(1, {"Image": None, "CommandLine": "cmd.exe /cwhoami"}, TS)
    assert event.get("CommandLine") == "cmd.exe /cwhoami"
    assert event.get("Image") is None
