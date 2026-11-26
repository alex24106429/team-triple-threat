"""Command-line interface for sigmatch."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Iterable, Sequence

from . import __version__
from .events import (
    EventParseError,
    ProcessCache,
    SYSMON_CHANNEL,
    SysmonEvent,
    parse_event_any,
)
from .rules import (
    LoadResult,
    Rule,
    RuleSet,
    default_rule_paths,
    expand_rule_paths,
    load_rules,
)
from .sources import (
    EtwSource,
    SourceError,
    evtx_events,
    replay_events,
)

TEXT_FIELDS = (
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "TargetFilename",
    "TargetObject",
    "Details",
    "NewName",
    "DestinationIp",
    "DestinationPort",
    "DestinationHostname",
    "QueryName",
    "PipeName",
    "SourceImage",
    "TargetImage",
    "GrantedAccess",
    "User",
    "State",
)


def _default_rule_paths() -> list[Path]:
    return default_rule_paths()


def _flatten_rule_args(values: Sequence[Sequence[str]] | None) -> list[str]:
    if not values:
        return []
    return [item for group in values for item in group]


def _build_common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "-r",
        "--rules",
        action="append",
        nargs="+",
        metavar="PATH",
        help="Sigma rule file/directory (repeatable). Defaults to sigma/rules.",
    )
    parser.add_argument(
        "--all-rule-sets",
        action="store_true",
        help="When PATH is a Sigma repository root, also load the extra rule collections.",
    )
    parser.add_argument(
        "--min-level",
        choices=["informational", "low", "medium", "high", "critical"],
        default=None,
        help="Only load rules at or above this level.",
    )
    parser.add_argument(
        "--status",
        action="append",
        metavar="STATUS",
        help="Only load rules with this status (repeatable, e.g. stable, test).",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Add CommandLine/Parent* fields from recent process-create events.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Alert format on stdout (default: text).",
    )
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        help="Append JSONL alerts to this file.",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        metavar="N",
        help="Stop after processing N events (useful for tests).",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print processing statistics to stderr on exit.",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress the startup banner.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed rule-loading errors.")
    return parser


def _build_parser() -> argparse.ArgumentParser:
    common = _build_common_parser()
    parser = argparse.ArgumentParser(
        prog="sigmatch",
        description="Match SigmaHQ rules against Microsoft Sysmon events in real time.",
    )
    parser.add_argument("--version", action="version", version=f"sigmatch {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    live = subparsers.add_parser(
        "live",
        parents=[common],
        help="Follow the live Sysmon ETW provider.",
    )
    live.add_argument(
        "--channel",
        default=SYSMON_CHANNEL,
        help="Sysmon channel (ETW consumption is fixed to the Sysmon provider).",
    )
    live.add_argument(
        "--query",
        default="*",
        help="Event Log XPath filter applied to --backfill only (default: *).",
    )
    live.add_argument(
        "--backfill",
        type=int,
        default=0,
        metavar="N",
        help="Process the last N events from the Sysmon log before following live "
        "ETW events (needs pywin32 and admin rights).",
    )
    live.add_argument(
        "--duration",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Stop after this many seconds.",
    )

    evtx = subparsers.add_parser(
        "evtx",
        parents=[common],
        help="Process events from an .evtx file.",
    )
    evtx.add_argument("path", help="Path to .evtx file.")
    evtx.add_argument("--query", default="*", help="Windows Event Log XPath query.")

    replay = subparsers.add_parser(
        "replay",
        parents=[common],
        help="Replay XML or JSON Sysmon events from a file or stdin.",
    )
    replay.add_argument("path", nargs="?", default="-", help="Input file (default: stdin).")
    replay.add_argument(
        "--input-format",
        choices=["auto", "xml", "json", "ndjson"],
        default="auto",
        help="Replay input format (default: auto).",
    )

    subparsers.add_parser(
        "validate",
        parents=[common],
        help="Load and compile rules, then report statistics and errors.",
    )
    return parser


def _load(
    args: argparse.Namespace, *, require_rules: bool = True
) -> tuple[LoadResult, RuleSet, list[str]]:
    paths = _flatten_rule_args(args.rules)
    if not paths:
        paths = [str(p) for p in _default_rule_paths()]
    expanded = expand_rule_paths(paths, all_rule_sets=args.all_rule_sets)
    expanded_strings = [str(path) for path in expanded]

    try:
        result = load_rules(
            expanded_strings,
            min_level=args.min_level,
            statuses=args.status,
        )
    except (FileNotFoundError, OSError) as exc:
        raise SystemExit(f"[sigmatch] {exc}") from exc

    if not args.quiet:
        print(
            f"[sigmatch] loaded {len(result.rules)} Sysmon rules from "
            f"{len(expanded_strings)} path(s), scanned {result.files_scanned} files",
            file=sys.stderr,
        )
        skipped = {key: value for key, value in result.skipped.items() if not key.startswith("loaded:")}
        if skipped:
            detail = ", ".join(f"{key}={value}" for key, value in sorted(skipped.items()))
            print(f"[sigmatch] skipped: {detail}", file=sys.stderr)
        if result.duplicates:
            print(f"[sigmatch] duplicate rule ids: {result.duplicates}", file=sys.stderr)
        if result.errors:
            print(f"[sigmatch] {len(result.errors)} rule(s) failed to load:", file=sys.stderr)
            errors = result.errors if args.verbose else result.errors[:10]
            for error in errors:
                print(f"  - {error.path}: {error.message}", file=sys.stderr)
            if not args.verbose and len(result.errors) > len(errors):
                print("  ... use --verbose for all errors", file=sys.stderr)

    if require_rules and not result.rules:
        raise SystemExit("No Sysmon-compatible rules were loaded.")

    return result, RuleSet(result.rules), expanded_strings


def _format_text(rule: Rule, event: SysmonEvent) -> str:
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "-"
    parts = [
        f"[{timestamp}]",
        f"{rule.level.upper():<13}",
        f"{rule.title}",
        f"(event={event.event_id}",
    ]
    if event.record_id is not None:
        parts[-1] += f" record={event.record_id}"
    parts[-1] += ")"
    extras: list[str] = []
    for name in TEXT_FIELDS:
        value = event.get(name)
        if value:
            extras.append(f"{name}={value}")
    if extras:
        parts.append(" ".join(extras))
    parts.append(f"[rule={rule.id}]")
    return " ".join(parts)


def _alert_json(rule: Rule, event: SysmonEvent) -> str:
    payload = {
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "event": event.to_output(),
        "rule": {
            "title": rule.title,
            "id": rule.id,
            "level": rule.level,
            "status": rule.status,
            "path": rule.path,
            "tags": list(rule.tags),
        },
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _emit(rule: Rule, event: SysmonEvent, args: argparse.Namespace, json_file) -> None:
    if args.format == "json":
        line = _alert_json(rule, event)
        print(line, flush=True)
        if json_file is not None:
            json_file.write(line + "\n")
            json_file.flush()
    else:
        print(_format_text(rule, event), flush=True)
        if json_file is not None:
            json_file.write(_alert_json(rule, event) + "\n")
            json_file.flush()


def _print_stats(
    stats: Counter[str],
    event_ids: Counter[int],
    rule_counts: Counter[str],
    elapsed: float,
) -> None:
    print("[sigmatch] stats:", file=sys.stderr)
    print(
        f"  events={stats['events']} matches={stats['matches']} "
        f"parse_errors={stats['parse_errors']} elapsed={elapsed:.2f}s",
        file=sys.stderr,
    )
    if event_ids:
        top_events = ", ".join(f"{eid}:{count}" for eid, count in event_ids.most_common(8))
        print(f"  events by id: {top_events}", file=sys.stderr)
    if rule_counts:
        top_rules = ", ".join(f"{count}x {title}" for title, count in rule_counts.most_common(8))
        print(f"  top rules: {top_rules}", file=sys.stderr)


def _run(
    events: Iterable[str],
    ruleset: RuleSet,
    args: argparse.Namespace,
    *,
    duration: float | None = None,
) -> int:
    stats: Counter[str] = Counter()
    event_ids: Counter[int] = Counter()
    rule_counts: Counter[str] = Counter()
    seen_records: OrderedDict[int, None] = OrderedDict()
    process_cache = ProcessCache() if args.enrich else None
    started = time.monotonic()
    try:
        json_file = open(args.json_out, "a", encoding="utf-8") if args.json_out else None
    except OSError as exc:
        print(f"[sigmatch] cannot open --json-out file: {exc}", file=sys.stderr)
        return 2

    try:
        for raw in events:
            if duration is not None and time.monotonic() - started >= duration:
                break
            try:
                event = raw if isinstance(raw, SysmonEvent) else parse_event_any(raw)
            except EventParseError as exc:
                stats["parse_errors"] += 1
                print(f"[sigmatch] parse error: {exc}", file=sys.stderr)
                continue

            if event.record_id is not None:
                if event.record_id in seen_records:
                    continue
                seen_records[event.record_id] = None
                if len(seen_records) > 100_000:
                    seen_records.popitem(last=False)

            if process_cache is not None:
                process_cache.observe(event)
                process_cache.enrich(event)

            stats["events"] += 1
            event_ids[event.event_id] += 1
            for rule in ruleset.match(event.event_id, event.lookup):
                stats["matches"] += 1
                rule_counts[rule.title] += 1
                _emit(rule, event, args, json_file)

            if args.max_events is not None and stats["events"] >= args.max_events:
                break
    finally:
        close = getattr(events, "close", None)
        if close is not None:
            try:
                close()
            except Exception:
                pass
        if json_file is not None:
            json_file.close()

    if args.stats:
        _print_stats(stats, event_ids, rule_counts, time.monotonic() - started)
    return 0


def _cmd_live(args: argparse.Namespace) -> int:
    source = EtwSource(
        args.channel,
        backfill=args.backfill,
        query=args.query,
        duration=args.duration,
    )
    try:
        # Start the trace session first: the ETW consumer drains buffers on its
        # own thread, so events written while rules are compiled are queued
        # instead of being missed (the old EventLog subscription dropped them).
        source.start()
        _, ruleset, _ = _load(args)
        return _run(source, ruleset, args, duration=args.duration)
    except SourceError as exc:
        print(f"[sigmatch] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        source.close()


def _cmd_evtx(args: argparse.Namespace) -> int:
    _, ruleset, _ = _load(args)
    try:
        return _run(evtx_events(args.path, query=args.query), ruleset, args)
    except SourceError as exc:
        print(f"[sigmatch] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


def _cmd_replay(args: argparse.Namespace) -> int:
    _, ruleset, _ = _load(args)
    try:
        return _run(
            replay_events(args.path, input_format=args.input_format),
            ruleset,
            args,
        )
    except (SourceError, OSError) as exc:
        print(f"[sigmatch] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


def _cmd_validate(args: argparse.Namespace) -> int:
    result, ruleset, paths = _load(args, require_rules=False)
    print(f"Paths: {', '.join(paths)}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Rules loaded: {len(result.rules)}")
    print(f"Rule errors: {len(result.errors)}")
    print(f"Duplicate ids: {result.duplicates}")
    print("Skipped:")
    for key, value in sorted(result.skipped.items()):
        print(f"  {key}: {value}")
    print("Rules by event id:")
    for event_id, count in sorted(result.event_id_counts.items()):
        print(f"  {event_id}: {count}")
    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"  {error.path}: {error.message}")
        return 1
    print("Validation OK")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    # Windows consoles/files default to the ANSI code page; Sysmon fields can
    # contain characters from vendor descriptions that are not representable
    # there.  Use UTF-8 with replacement so an alert can never kill the loop.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0].startswith("-") and argv[0] not in {"-h", "--help", "--version"}):
        argv = ["live", *argv]

    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "live":
        return _cmd_live(args)
    if args.command == "evtx":
        return _cmd_evtx(args)
    if args.command == "replay":
        return _cmd_replay(args)
    if args.command == "validate":
        return _cmd_validate(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
