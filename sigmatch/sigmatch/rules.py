"""Load and compile SigmaHQ rules for Sysmon events."""

from __future__ import annotations

import copy
import hashlib
import os
import pickle
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

import yaml

from . import __version__
from .condition import ConditionNode, compile_condition
from .matchers import (
    RuleCompileError,
    SelectionGroup,
    compile_detection_item,
)

# Sigma logsource category -> Sysmon event IDs.
CATEGORY_TO_SYSMON: dict[str, frozenset[int]] = {
    "process_creation": frozenset({1}),
    "file_change": frozenset({2}),
    "network_connection": frozenset({3}),
    "sysmon_status": frozenset({4}),
    "process_termination": frozenset({5}),
    "driver_load": frozenset({6}),
    "image_load": frozenset({7}),
    "create_remote_thread": frozenset({8}),
    "raw_access_thread": frozenset({9}),
    "raw_access_read": frozenset({9}),
    "process_access": frozenset({10}),
    "file_event": frozenset({11}),
    "registry_add": frozenset({12}),
    "registry_delete": frozenset({12}),
    "registry_event": frozenset({12, 13, 14}),
    "registry_set": frozenset({13}),
    "registry_rename": frozenset({14}),
    "create_stream_hash": frozenset({15}),
    "pipe_created": frozenset({17}),
    "pipe_connected": frozenset({18}),
    "wmi_event": frozenset({19, 20, 21}),
    "dns_query": frozenset({22}),
    "file_delete": frozenset({23, 26}),
    "clipboard_capture": frozenset({24}),
    "process_tampering": frozenset({25}),
    "file_block": frozenset({27, 28}),
    "file_executable_detected": frozenset({29}),
    "sysmon_error": frozenset({255}),
}

ALL_SYSMON_EVENT_IDS = frozenset(range(1, 30)) | frozenset({255})


def default_rule_paths() -> list[Path]:
    """Return the conventional SigmaHQ rule location for this installation."""

    tool_root = Path(__file__).resolve().parent.parent
    candidates = [
        Path.cwd() / "sigma" / "rules",
        tool_root / "sigma" / "rules",
        tool_root.parent / "sigma" / "rules",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return [candidate]
    return [candidates[0]]


LEVELS = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Rule:
    title: str
    id: str
    level: str
    status: str
    description: str
    author: str
    tags: tuple[str, ...]
    references: tuple[str, ...]
    path: str
    event_ids: frozenset[int]
    selections: Mapping[str, SelectionGroup]
    condition: ConditionNode
    raw: Mapping[str, Any]

    def matches(self, fields: Mapping[str, str]) -> bool:
        cache: dict[str, bool] = {}
        return self.condition.evaluate(fields, self.selections, cache)


@dataclass
class RuleError:
    path: str
    message: str


@dataclass
class LoadResult:
    rules: list[Rule] = field(default_factory=list)
    errors: list[RuleError] = field(default_factory=list)
    skipped: Counter[str] = field(default_factory=Counter)
    files_scanned: int = 0
    duplicates: int = 0

    @property
    def event_id_counts(self) -> Counter[int]:
        counts: Counter[int] = Counter()
        for rule in self.rules:
            for event_id in rule.event_ids:
                counts[event_id] += 1
        return counts


class RuleSet:
    """Rules indexed by Sysmon event ID for fast per-event evaluation."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = list(rules)
        self.by_event: dict[int, list[Rule]] = {}
        for rule in self.rules:
            for event_id in rule.event_ids:
                self.by_event.setdefault(event_id, []).append(rule)

    def match(self, event_id: int, fields: Mapping[str, str]) -> Iterator[Rule]:
        for rule in self.by_event.get(event_id, ()):
            if rule.matches(fields):
                yield rule

    def __len__(self) -> int:
        return len(self.rules)


def _deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


# PyYAML ships a libyaml-backed loader whenever its C extension is available.
# It is roughly ten times faster than the pure-Python SafeLoader and produces
# the same basic Python objects for Sigma rule files.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _yaml_documents_from_text(text: str) -> list[Mapping[str, Any]]:
    try:
        documents = list(yaml.load_all(text, Loader=_YAML_LOADER))
    except yaml.YAMLError as exc:
        raise RuleCompileError(f"invalid YAML: {exc}") from exc

    defaults: dict[str, Any] = {}
    merged_documents: list[Mapping[str, Any]] = []
    for document in documents:
        if not isinstance(document, Mapping):
            continue
        action = document.get("action")
        if action == "global":
            defaults = _deep_merge(defaults, {k: v for k, v in document.items() if k != "action"})
            continue
        merged = _deep_merge(defaults, document)
        if merged.get("detection"):
            merged_documents.append(merged)
    return merged_documents


def _read_rule_text(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8"), None
    except (OSError, UnicodeError) as exc:
        return None, f"cannot read rule file: {exc}"


def _iter_yaml_documents(path: Path) -> Iterator[Mapping[str, Any]]:
    text, error = _read_rule_text(path)
    if error is not None or text is None:
        raise RuleCompileError(error or "cannot read rule file")
    yield from _yaml_documents_from_text(text)


def _base_field(key: str) -> str:
    return key.split("|", 1)[0].strip().lower()


def _positive_selection_names(detection: Mapping[str, Any]) -> list[str]:
    return [
        name
        for name in detection
        if name != "condition" and not name.lower().startswith(("filter", "optional"))
    ]


def _event_ids_from_value(value: Any) -> set[int] | None:
    """Return EventID values, empty set if none, None if not statically usable."""

    if value is None:
        return None
    if isinstance(value, (int, str)) and not isinstance(value, bool):
        try:
            return {int(str(value), 10)}
        except ValueError:
            return None
    if isinstance(value, list):
        result: set[int] = set()
        for item in value:
            parsed = _event_ids_from_value(item)
            if parsed is None:
                return None
            result.update(parsed)
        return result
    return None


def _extract_event_ids(value: Any) -> set[int] | None:
    """Collect statically usable EventID fields from a selection tree."""

    if isinstance(value, Mapping):
        result: set[int] = set()
        found = False
        for key, item in value.items():
            parts = key.split("|")
            if _base_field(key) == "eventid":
                if len(parts) > 1:
                    return None
                parsed = _event_ids_from_value(item)
                if parsed is None:
                    return None
                result.update(parsed)
                found = True
            else:
                nested = _extract_event_ids(item)
                if nested is None:
                    return None
                if nested:
                    result.update(nested)
                    found = True
        return result if found else set()
    if isinstance(value, list):
        result = set()
        found = False
        for item in value:
            nested = _extract_event_ids(item)
            if nested is None:
                return None
            if nested:
                result.update(nested)
                found = True
        return result if found else set()
    return set()


def _event_ids_for_rule(
    logsource: Mapping[str, Any], detection: Mapping[str, Any]
) -> tuple[frozenset[int] | None, str]:
    product = str(logsource.get("product") or "").lower()
    service = str(logsource.get("service") or "").lower()
    category = str(logsource.get("category") or "").lower()

    if product and product != "windows":
        return None, "non_windows_product"
    if service and service != "sysmon":
        return None, f"non_sysmon_service:{service}"

    positive_ids: set[int] = set()
    extraction_usable = True
    for name in _positive_selection_names(detection):
        if name == "condition":
            continue
        parsed = _extract_event_ids(detection[name])
        if parsed is None:
            extraction_usable = False
            break
        positive_ids.update(parsed)

    if category:
        mapped = CATEGORY_TO_SYSMON.get(category)
        if mapped is None:
            return None, f"unsupported_category:{category}"
        if extraction_usable and positive_ids:
            intersection = mapped & frozenset(positive_ids)
            if not intersection:
                return None, "eventid_not_in_sysmon_category"
            return frozenset(intersection), "category+eventid"
        return mapped, "category"

    if service == "sysmon":
        if extraction_usable and positive_ids:
            return frozenset(positive_ids), "sysmon_eventid"
        return ALL_SYSMON_EVENT_IDS, "sysmon_all"

    # A generic Windows rule (for example the built-in Mimikatz keyword rule)
    # may apply to any event log, including Sysmon.
    if extraction_usable and positive_ids:
        return frozenset(positive_ids), "generic_eventid"
    return ALL_SYSMON_EVENT_IDS, "generic_all"


def _rule_level_allowed(level: Any, min_level: str | None) -> bool:
    if not min_level:
        return True
    threshold = LEVELS.get(str(min_level).lower())
    if threshold is None:
        raise ValueError(f"unknown minimum level: {min_level}")
    actual = LEVELS.get(str(level or "informational").lower(), 0)
    return actual >= threshold


@dataclass(frozen=True)
class _RuleFile:
    path: Path
    mtime_ns: int
    size: int


def _rule_file(path: Path) -> _RuleFile:
    info = path.stat()
    return _RuleFile(path, info.st_mtime_ns, info.st_size)


def _scan_rule_directory(root: Path, progress: callable | None = None) -> list[_RuleFile]:
    """Walk *root* with ``scandir`` and collect YAML files plus their stamps.

    ``Path.rglob`` is slower and, more importantly, the old loader called
    ``Path.resolve()`` for every candidate.  On a network share that one call
    is several milliseconds per file; ``DirEntry.stat()`` is cached by Windows
    for entries returned by ``scandir`` and costs almost nothing.
    """

    files: list[_RuleFile] = []
    stack = [str(root)]
    root_string = str(root)
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.name.lower().endswith((".yml", ".yaml")):
                            info = entry.stat()
                            record = _RuleFile(
                                Path(entry.path), info.st_mtime_ns, info.st_size
                            )
                            files.append(record)
                            if progress is not None:
                                progress(len(files), record.path)
                    except OSError:
                        # An unreadable/broken entry should not abort the scan.
                        continue
        except OSError:
            if directory == root_string:
                raise
            # Match the old rglob behaviour for unreadable subdirectories.
            continue
    files.sort(key=lambda item: str(item.path).lower())
    return files


def _iter_rule_file_records(
    paths: Sequence[str | Path], progress: callable | None = None
) -> Iterator[_RuleFile]:
    seen: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        base = len(seen)
        if path.is_file():
            records = [_rule_file(path)]
            if progress is not None:
                progress(base + 1, path)
        elif path.is_dir():
            if progress is None:
                records = _scan_rule_directory(path)
            else:
                records = _scan_rule_directory(
                    path, lambda count, item: progress(base + count, item)
                )
        else:
            raise FileNotFoundError(f"rule path does not exist: {path}")
        for record in records:
            key = os.path.normcase(os.path.abspath(str(record.path)))
            if key in seen:
                continue
            seen.add(key)
            yield record


def discover_rule_records(
    paths: Sequence[str | Path], progress: callable | None = None
) -> list[_RuleFile]:
    """Discover rule files once, reporting each file through *progress*."""

    return list(_iter_rule_file_records(paths, progress))


def _read_rule_file_texts(
    records: Sequence[_RuleFile],
    progress: callable | None,
) -> Iterator[tuple[_RuleFile, str | None, str | None]]:
    """Read rule files concurrently, preserving discovery order.

    A network share has high per-file latency, so a handful of reader threads
    hide it almost completely (roughly 4x faster for a typical SigmaHQ tree).
    Parsing and compilation stay in the caller because they are CPU-bound and
    the GIL would serialise them anyway.
    """

    if len(records) <= 1:
        for index, record in enumerate(records, 1):
            text, error = _read_rule_text(record.path)
            if progress is not None:
                progress(index, record.path)
            yield record, text, error
        return

    workers = min(8, len(records))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for index, (record, (text, error)) in enumerate(
            zip(records, executor.map(lambda item: _read_rule_text(item.path), records)), 1
        ):
            if progress is not None:
                progress(index, record.path)
            yield record, text, error


# ---------------------------------------------------------------------------
# Compiled rule cache
# ---------------------------------------------------------------------------

_CACHE_FORMAT = "sigmatch-rule-cache-v2"
_CACHE_MODULES = ("rules.py", "matchers.py", "condition.py")
_CACHE_KEEP = 16

# Only the classes/functions that appear in a cached LoadResult may be
# unpickled.  This keeps a cache file from becoming an arbitrary-code-execution
# vector if another process can write to the user's cache directory.
_ALLOWED_CACHE_GLOBALS = {
    ("collections", "Counter"),
    ("datetime", "date"),
    ("datetime", "datetime"),
    ("ipaddress", "IPv4Network"),
    ("ipaddress", "IPv6Network"),
    ("re", "_compile"),
}
_ALLOWED_CACHE_MODULES = {
    "sigmatch.rules",
    "sigmatch.matchers",
    "sigmatch.condition",
}


class _RuleCacheUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> Any:
        if module in _ALLOWED_CACHE_MODULES or (module, name) in _ALLOWED_CACHE_GLOBALS:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"unexpected object in rule cache: {module}.{name}")


def _rule_cache_enabled(requested: bool) -> bool:
    if not requested:
        return False
    value = os.environ.get("SIGMATCH_RULE_CACHE", "").strip().lower()
    return value not in {"0", "false", "no", "off", "disabled"}


def _rule_cache_dir() -> Path:
    override = os.environ.get("SIGMATCH_RULE_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "sigmatch" / "rule-cache"
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "sigmatch" / "rule-cache"
    return Path.home() / ".cache" / "sigmatch" / "rule-cache"


def _rule_cache_key(
    records: Sequence["_RuleFile"],
    min_level: str | None,
    statuses: Sequence[str] | None,
) -> str:
    digest = hashlib.blake2b(digest_size=20)
    digest.update(_CACHE_FORMAT.encode("ascii"))
    digest.update(__version__.encode("ascii", "replace"))
    digest.update(sys.version.encode("utf-8", "replace"))

    source_dir = Path(__file__).resolve().parent
    for name in _CACHE_MODULES:
        source = source_dir / name
        try:
            info = source.stat()
            digest.update(f"{name}:{info.st_mtime_ns}:{info.st_size}".encode("ascii"))
        except OSError:
            digest.update(name.encode("ascii"))

    filters = repr((min_level, tuple(sorted(statuses)) if statuses else None))
    digest.update(filters.encode("utf-8", "replace"))
    for record in sorted(
        records, key=lambda item: os.path.normcase(os.path.abspath(str(item.path)))
    ):
        key = os.path.normcase(os.path.abspath(str(record.path)))
        digest.update(key.encode("utf-8", "surrogatepass"))
        digest.update(f"\0{record.mtime_ns}:{record.size}\0".encode("ascii"))
    return digest.hexdigest()


def _load_cached_result(cache_path: Path) -> LoadResult | None:
    try:
        with cache_path.open("rb") as handle:
            payload = _RuleCacheUnpickler(handle).load()
    except (
        OSError,
        EOFError,
        pickle.UnpicklingError,
        AttributeError,
        ImportError,
        TypeError,
        ValueError,
    ):
        return None
    if not isinstance(payload, dict) or payload.get("format") != _CACHE_FORMAT:
        return None
    result = payload.get("result")
    return result if isinstance(result, LoadResult) else None


def _prune_rule_cache(directory: Path) -> None:
    try:
        files = sorted(
            directory.glob("*.pkl"),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )
    except OSError:
        return
    for stale in files[_CACHE_KEEP:]:
        try:
            stale.unlink()
        except OSError:
            pass


def _store_cached_result(cache_path: Path, result: LoadResult) -> None:
    directory = cache_path.parent
    temporary = cache_path.with_name(
        f".{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with temporary.open("wb") as handle:
            pickle.dump(
                {"format": _CACHE_FORMAT, "result": result},
                handle,
                protocol=5,
            )
        os.replace(temporary, cache_path)
    except (OSError, pickle.PicklingError, AttributeError, TypeError, ValueError):
        # The cache is a best-effort optimisation; never fail a rule load
        # because the cache directory is read-only or an object is unpicklable.
        try:
            temporary.unlink()
        except OSError:
            pass
        return
    _prune_rule_cache(directory)


def load_rules(
    paths: Sequence[str | Path],
    *,
    min_level: str | None = None,
    statuses: Sequence[str] | None = None,
    progress: callable | None = None,
    use_cache: bool = True,
) -> LoadResult:
    """Discover and load every Sysmon-applicable rule under *paths*.

    Compiled results are cached under the user's cache directory and validated
    with the rule files' size and nanosecond modification time.  Set
    ``use_cache=False`` (or ``SIGMATCH_RULE_CACHE=0``) to bypass the cache.
    """

    return load_rule_records(
        discover_rule_records(paths),
        min_level=min_level,
        statuses=statuses,
        progress=progress,
        use_cache=use_cache,
    )


def load_rule_records(
    records: Sequence[_RuleFile],
    *,
    min_level: str | None = None,
    statuses: Sequence[str] | None = None,
    progress: callable | None = None,
    use_cache: bool = True,
) -> LoadResult:
    """Compile already-discovered rule *records* (see :func:`discover_rule_records`)."""

    result = LoadResult()
    seen_ids: set[str] = set()
    allowed_statuses = {s.lower() for s in statuses} if statuses else None

    cache_path: Path | None = None
    if records and _rule_cache_enabled(use_cache):
        cache_path = _rule_cache_dir() / (
            _rule_cache_key(records, min_level, statuses) + ".pkl"
        )
        cached = _load_cached_result(cache_path)
        if cached is not None:
            if progress is not None:
                progress(len(records), records[-1].path)
            return cached

    for record, text, read_error in _read_rule_file_texts(records, progress):
        path = record.path
        result.files_scanned += 1
        if read_error is not None or text is None:
            result.errors.append(RuleError(str(path), read_error or "cannot read rule file"))
            continue
        try:
            documents = _yaml_documents_from_text(text)
        except RuleCompileError as exc:
            result.errors.append(RuleError(str(path), str(exc)))
            continue

        for document in documents:
            detection = document.get("detection")
            logsource = document.get("logsource")
            if not isinstance(detection, Mapping):
                result.errors.append(RuleError(str(path), "missing or invalid detection block"))
                continue
            if not isinstance(logsource, Mapping):
                result.errors.append(RuleError(str(path), "missing or invalid logsource block"))
                continue

            status = str(document.get("status") or "").lower()
            if allowed_statuses is not None and status not in allowed_statuses:
                result.skipped["status_filter"] += 1
                continue
            if not _rule_level_allowed(document.get("level"), min_level):
                result.skipped["level_filter"] += 1
                continue

            event_ids, mapping_reason = _event_ids_for_rule(logsource, detection)
            if event_ids is None:
                result.skipped[mapping_reason] += 1
                continue

            condition = detection.get("condition")
            selection_names = [name for name in detection if name != "condition"]
            if not selection_names:
                result.errors.append(RuleError(str(path), "detection has no selections"))
                continue

            try:
                selections: dict[str, SelectionGroup] = {}
                for name in selection_names:
                    selections[name] = compile_detection_item(name, detection[name])
                compiled_condition = compile_condition(condition, selection_names)
            except RuleCompileError as exc:
                result.errors.append(RuleError(str(path), str(exc)))
                continue
            except Exception as exc:  # defensive: a malformed rule must not kill the loader
                result.errors.append(
                    RuleError(str(path), f"{type(exc).__name__}: {exc}")
                )
                continue

            rule_id = str(document.get("id") or "").strip()
            if rule_id:
                if rule_id in seen_ids:
                    result.duplicates += 1
                    result.skipped["duplicate_id"] += 1
                    continue
                seen_ids.add(rule_id)

            rule = Rule(
                title=str(document.get("title") or path.stem),
                id=rule_id or str(path),
                level=str(document.get("level") or "informational"),
                status=status,
                description=str(document.get("description") or ""),
                author=str(document.get("author") or ""),
                tags=tuple(str(tag) for tag in (document.get("tags") or [])),
                references=tuple(str(ref) for ref in (document.get("references") or [])),
                path=str(path),
                event_ids=event_ids,
                selections=selections,
                condition=compiled_condition,
                raw=document,
            )
            result.rules.append(rule)
            result.skipped[f"loaded:{mapping_reason}"] += 1

    if cache_path is not None and result.rules:
        _store_cached_result(cache_path, result)
    return result


def expand_rule_paths(paths: Sequence[str | Path], *, all_rule_sets: bool = False) -> list[Path]:
    """Resolve a Sigma repository root to its rule directories.

    Passing ``.../sigma`` loads ``sigma/rules`` by default.  ``--all-rule-sets``
    additionally loads the emerging-threats, threat-hunting, compliance and
    DFIR collections.  Passing a rule directory directly is always respected.
    """

    expanded: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.is_dir():
            expanded.append(path)
            continue
        if path.name.lower() in {"rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance", "rules-dfir"}:
            expanded.append(path)
            continue
        if (path / "rules").is_dir():
            expanded.append(path / "rules")
            if all_rule_sets:
                for name in (
                    "rules-emerging-threats",
                    "rules-threat-hunting",
                    "rules-compliance",
                    "rules-dfir",
                ):
                    candidate = path / name
                    if candidate.is_dir():
                        expanded.append(candidate)
        else:
            expanded.append(path)
    return expanded


def rule_category(rule: Rule) -> str:
    logsource = rule.raw.get("logsource") or {}
    return str(logsource.get("category") or logsource.get("service") or "generic")


