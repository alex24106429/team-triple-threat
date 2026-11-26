from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import sigmatch.rules as rules_module
from sigmatch.events import event_from_etw
from sigmatch.rules import (
    ALL_SYSMON_EVENT_IDS,
    CATEGORY_TO_SYSMON,
    RuleSet,
    expand_rule_paths,
    load_rules,
)


RULE_HEADER = """title: {title}
id: {id}
status: {status}
level: {level}
logsource:
  product: windows
{logsource}
detection:
{detection}
"""


def write_rule(directory: Path, name: str, *, title="Test Rule", rule_id="11111111-1111-1111-1111-111111111111",
               status="test", level="high", logsource="  category: process_creation",
               detection="  selection:\n    Image|endswith: '\\\\cmd.exe'\n  condition: selection"):
    path = directory / f"{name}.yml"
    path.write_text(
        RULE_HEADER.format(
            title=title,
            id=rule_id,
            status=status,
            level=level,
            logsource=logsource,
            detection=detection,
        ),
        encoding="utf-8",
    )
    return path


def test_category_mapping_and_matching(tmp_path):
    write_rule(tmp_path, "rule")
    result = load_rules([tmp_path])
    assert not result.errors
    assert len(result.rules) == 1
    rule = result.rules[0]
    assert rule.event_ids == frozenset({1})
    assert rule.matches({"image": r"C:\Windows\System32\cmd.exe"})
    assert not rule.matches({"image": r"C:\Windows\System32\powershell.exe"})


def test_service_sysmon_event_id_mapping(tmp_path):
    write_rule(
        tmp_path,
        "sysmon",
        logsource="  service: sysmon",
        detection=(
            "  selection:\n"
            "    EventID: 7\n"
            "    ImageLoaded|endswith: '\\\\sigma_test.dll'\n"
            "  condition: selection\n"
        ),
    )
    result = load_rules([tmp_path])
    assert not result.errors
    rule = result.rules[0]
    assert rule.event_ids == frozenset({7})
    assert rule.matches({"eventid": "7", "imageloaded": r"C:\test\sigma_test.dll"})
    assert not rule.matches({"eventid": "1", "imageloaded": r"C:\test\sigma_test.dll"})


def test_service_sysmon_event_id_list(tmp_path):
    write_rule(
        tmp_path,
        "sysmon-list",
        logsource="  service: sysmon",
        detection=(
            "  selection:\n"
            "    EventID:\n"
            "      - 3\n"
            "      - 22\n"
            "    Image|endswith: '\\\\cmd.exe'\n"
            "  condition: selection\n"
        ),
    )
    result = load_rules([tmp_path])
    assert not result.errors
    assert result.rules[0].event_ids == frozenset({3, 22})


def test_non_sysmon_rules_are_skipped(tmp_path):
    write_rule(tmp_path, "security", logsource="  service: security")
    write_rule(tmp_path, "ps", logsource="  category: ps_script")
    result = load_rules([tmp_path])
    assert not result.errors
    assert result.rules == []
    assert result.skipped["non_sysmon_service:security"] == 1
    assert result.skipped["unsupported_category:ps_script"] == 1


def test_eventid_outside_category_is_skipped(tmp_path):
    write_rule(
        tmp_path,
        "security-process",
        detection=(
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|endswith: '\\\\cmd.exe'\n"
            "  condition: selection\n"
        ),
    )
    result = load_rules([tmp_path])
    assert result.rules == []
    assert result.skipped["eventid_not_in_sysmon_category"] == 1


def test_level_and_status_filters(tmp_path):
    write_rule(tmp_path, "low", level="low", rule_id="22222222-2222-2222-2222-222222222222")
    write_rule(tmp_path, "high", level="high", rule_id="33333333-3333-3333-3333-333333333333")
    write_rule(tmp_path, "stable", status="stable", rule_id="44444444-4444-4444-4444-444444444444")

    high = load_rules([tmp_path], min_level="high")
    assert {rule.title for rule in high.rules} == {"Test Rule"}
    assert len(high.rules) == 2

    stable = load_rules([tmp_path], statuses=["stable"])
    assert len(stable.rules) == 1
    assert stable.rules[0].status == "stable"


def test_duplicate_ids_are_skipped(tmp_path):
    write_rule(tmp_path, "one", rule_id="55555555-5555-5555-5555-555555555555")
    write_rule(tmp_path, "two", rule_id="55555555-5555-5555-5555-555555555555")
    result = load_rules([tmp_path])
    assert len(result.rules) == 1
    assert result.duplicates == 1
    assert result.skipped["duplicate_id"] == 1


def test_multi_document_global_defaults(tmp_path):
    path = tmp_path / "multi.yml"
    path.write_text(
        """action: global
logsource:
  product: windows
  category: process_creation
---
title: Global Rule
id: 66666666-6666-6666-6666-666666666666
status: test
level: medium
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
""",
        encoding="utf-8",
    )
    result = load_rules([tmp_path])
    assert not result.errors
    assert len(result.rules) == 1
    assert result.rules[0].event_ids == frozenset({1})


def test_invalid_condition_reports_error(tmp_path):
    write_rule(
        tmp_path,
        "bad",
        detection=(
            "  selection:\n"
            "    Image|endswith: '\\\\cmd.exe'\n"
            "  condition: selection and missing\n"
        ),
    )
    result = load_rules([tmp_path])
    assert len(result.rules) == 0
    assert len(result.errors) == 1
    assert "unknown selection" in result.errors[0].message


def test_rule_set_indexes_by_event_id(tmp_path):
    write_rule(tmp_path, "one")
    result = load_rules([tmp_path])
    ruleset = RuleSet(result.rules)
    assert len(ruleset.by_event[1]) == 1
    assert list(ruleset.match(1, {"image": r"C:\Windows\System32\cmd.exe"}))
    assert not list(ruleset.match(2, {"image": r"C:\Windows\System32\cmd.exe"}))


def test_expand_rule_paths_repository_root(tmp_path, monkeypatch):
    repo = tmp_path / "sigma"
    (repo / "rules").mkdir(parents=True)
    (repo / "rules-emerging-threats").mkdir()
    assert expand_rule_paths([repo]) == [repo / "rules"]
    assert expand_rule_paths([repo], all_rule_sets=True) == [
        repo / "rules",
        repo / "rules-emerging-threats",
    ]


def test_real_sigma_rules_load_without_errors(real_sigma_result):
    result = real_sigma_result
    assert not result.errors, [f"{e.path}: {e.message}" for e in result.errors[:10]]
    assert len(result.rules) > 1800
    assert len(result.rules) == len({rule.id for rule in result.rules})

    by_title = {rule.title: rule for rule in result.rules}
    assert "Renamed Whoami Execution" in by_title
    assert "Add DisallowRun Execution to Registry" in by_title
    assert "Sysmon Blocked Executable" in by_title


def test_real_sigma_rule_matches_crafted_events(real_sigma_result):
    result = real_sigma_result
    by_title = {rule.title: rule for rule in result.rules}

    whoami = by_title["Renamed Whoami Execution"]
    assert whoami.matches(
        {
            "originalfilename": "whoami.exe",
            "image": r"C:\Users\Public\notwhoami.exe",
        }
    )
    assert not whoami.matches(
        {
            "originalfilename": "whoami.exe",
            "image": r"C:\Windows\System32\whoami.exe",
        }
    )

    disallow = by_title["Add DisallowRun Execution to Registry"]
    assert disallow.matches(
        {
            "targetobject": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun",
            "details": "DWORD (0x00000001)",
        }
    )

    blocked = by_title["Sysmon Blocked Executable"]
    assert blocked.matches({"eventid": "27"})

    from sigmatch.matchers import _base64offset_values

    iex = by_title["PowerShell Base64 Encoded IEX Cmdlet"]
    for encoded in _base64offset_values("IEX (["):
        assert iex.matches({"commandline": f"powershell -EncodedCommand {encoded}"})


def test_real_sigma_matches_process_event_object(real_sigma_result):
    result = real_sigma_result
    event = event_from_etw(
        1,
        {
            "Image": r"C:\Users\Public\notwhoami.exe",
            "OriginalFileName": "whoami.exe",
            "CommandLine": "notwhoami.exe /all",
        },
        datetime(2026, 11, 16, 13, 45, 12, 123456, tzinfo=timezone.utc),
        computer="TESTHOST",
    )
    ruleset = RuleSet(result.rules)
    matches = list(ruleset.match(event.event_id, event.lookup))
    assert any(rule.title == "Renamed Whoami Execution" for rule in matches)


def test_category_mapping_covers_all_sysmon_event_types():
    assert CATEGORY_TO_SYSMON["process_creation"] == frozenset({1})
    assert CATEGORY_TO_SYSMON["network_connection"] == frozenset({3})
    assert CATEGORY_TO_SYSMON["registry_event"] == frozenset({12, 13, 14})
    assert CATEGORY_TO_SYSMON["pipe_connected"] == frozenset({18})
    assert CATEGORY_TO_SYSMON["file_delete"] == frozenset({23, 26})
    assert CATEGORY_TO_SYSMON["file_block"] == frozenset({27, 28})
    assert CATEGORY_TO_SYSMON["clipboard_capture"] == frozenset({24})
    assert CATEGORY_TO_SYSMON["sysmon_error"] == frozenset({255})
    assert ALL_SYSMON_EVENT_IDS == frozenset(range(1, 30)) | frozenset({255})


def test_rule_cache_hit_and_invalidation(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    monkeypatch.setenv("SIGMATCH_RULE_CACHE_DIR", str(tmp_path / "cache"))
    path = write_rule(rules_dir, "cached", title="Cached Rule")

    first = load_rules([rules_dir])
    assert [rule.title for rule in first.rules] == ["Cached Rule"]
    assert list((tmp_path / "cache").glob("*.pkl"))

    # A second identical load must come from the cache, not parse YAML again.
    original_parser = rules_module._yaml_documents_from_text

    def fail_parse(text):
        raise AssertionError("the cache should have been used")

    monkeypatch.setattr(rules_module, "_yaml_documents_from_text", fail_parse)
    second = load_rules([rules_dir])
    assert [rule.title for rule in second.rules] == ["Cached Rule"]

    # Changing a rule invalidates the cache entry.
    monkeypatch.setattr(rules_module, "_yaml_documents_from_text", original_parser)
    write_rule(
        rules_dir,
        "cached",
        title="Changed Rule",
        rule_id="99999999-9999-9999-9999-999999999999",
    )
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000))
    third = load_rules([rules_dir])
    assert [rule.title for rule in third.rules] == ["Changed Rule"]


def test_rule_cache_respects_filters(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    monkeypatch.setenv("SIGMATCH_RULE_CACHE_DIR", str(tmp_path / "cache"))
    write_rule(rules_dir, "low", level="low")
    write_rule(
        rules_dir,
        "high",
        level="high",
        rule_id="77777777-7777-7777-7777-777777777777",
    )

    assert len(load_rules([rules_dir]).rules) == 2
    high = load_rules([rules_dir], min_level="high")
    assert [rule.level for rule in high.rules] == ["high"]
