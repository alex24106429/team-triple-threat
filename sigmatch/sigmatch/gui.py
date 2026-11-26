"""PyQt6 desktop UI for sigmatch.

The window follows the live Sysmon event log, shows every event plus the Sigma
rules it matched, and lets the user inspect the full event and rule details.
"""

from __future__ import annotations

import argparse
import ctypes
import html
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    from PyQt6.QtCore import (
        QAbstractTableModel,
        QModelIndex,
        QObject,
        QSortFilterProxyModel,
        Qt,
        QThread,
        QTimer,
        pyqtSignal,
        pyqtSlot,
    )
    from PyQt6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPalette
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QCheckBox,
        QDialog,
        QDialogButtonBox,
        QFrame,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QMainWindow,
        QMenu,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QSizePolicy,
        QSplitter,
        QStackedWidget,
        QStyle,
        QStyleFactory,
        QSystemTrayIcon,
        QTabWidget,
        QTableView,
        QTableWidget,
        QTableWidgetItem,
        QTextBrowser,
        QToolButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - depends on the installation
    _pyqt_message = "The sigmatch GUI requires PyQt6." + chr(10) * 2
    _pyqt_message += "Install it with:" + chr(10)
    _pyqt_message += "    python -m pip install PyQt6"
    if sys.stderr is not None:
        print(_pyqt_message, file=sys.stderr)
    try:
        ctypes.windll.user32.MessageBoxW(
            None, _pyqt_message, "sigmatch", 0x10 | 0x00040000 | 0x00010000
        )
    except Exception:
        pass
    raise SystemExit(2) from exc


from . import __version__
from .events import (
    SYSMON_CHANNEL,
    SysmonEvent,
    render_event_xml,
)
from .rules import (
    LEVELS,
    LoadResult,
    Rule,
    RuleSet,
    default_rule_paths,
    discover_rule_records,
    expand_rule_paths,
    load_rule_records,
    rule_category,
)
from .sources import EtwSource, SourceError


# Rolling window of events that matched no rule.  Matched events are kept
# separately (see MAX_MATCHED_ROWS) because they are the reason the window is
# open in the first place.
MAX_ROWS = 10_000
# Safety valve on matched events so a long run cannot grow without bound.  The
# oldest matched rows are dropped only once this many are held.
MAX_MATCHED_ROWS = 50_000
BATCH_INTERVAL_MS = 80
MAX_PENDING_EVENTS = 10_000

EVENT_NAMES = {
    1: "Process Create",
    2: "File Creation Time Changed",
    3: "Network Connection",
    4: "Sysmon Service State Changed",
    5: "Process Terminated",
    6: "Driver Loaded",
    7: "Image Loaded",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "Process Access",
    11: "File Create",
    12: "Registry Object Added or Deleted",
    13: "Registry Value Set",
    14: "Registry Key or Value Renamed",
    15: "FileCreateStreamHash",
    16: "Sysmon Config Change",
    17: "Pipe Created",
    18: "Pipe Connected",
    19: "WMI Event Filter",
    20: "WMI Event Consumer",
    21: "WMI Consumer Filter",
    22: "DNS Query",
    23: "File Delete (Archived)",
    24: "Clipboard Change",
    25: "Process Tampering",
    26: "File Delete Detected",
    27: "File Block Executable",
    28: "File Block Shredding",
    29: "File Executable Detected",
    255: "Sysmon Error",
}

LEVEL_BACKGROUND = {
    "critical": QColor("#c50f1f"),
    "high": QColor("#d83b01"),
    "medium": QColor("#f2c811"),
    "low": QColor("#0f6cbd"),
}
LEVEL_FOREGROUND = {
    "critical": QColor("#ffffff"),
    "high": QColor("#ffffff"),
    "medium": QColor("#1b1b1b"),
    "low": QColor("#ffffff"),
}
LEVEL_HTML_COLOR = {
    "critical": "#c50f1f",
    "high": "#d83b01",
    "medium": "#8a6d00",
    "low": "#0f6cbd",
    "informational": "#6b6b6b",
}


# ---------------------------------------------------------------------------
# Small data objects and formatting helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Problem:
    """A user-facing error or warning."""

    title: str
    message: str
    details: str = ""


class _RuleLoadFailure(Exception):
    """Carries a user-facing Problem out of the loader."""

    def __init__(self, problem: Problem) -> None:
        super().__init__(problem.title)
        self.problem = problem


@dataclass(frozen=True)
class LoaderProgress:
    stage: str  # "discovering" or "loading"
    current: int
    total: int
    path: str = ""


@dataclass(frozen=True)
class LoaderOutcome:
    result: LoadResult
    ruleset: RuleSet
    files: tuple[Path, ...]
    search_paths: tuple[Path, ...]
    missing_paths: tuple[Path, ...]
    scan_errors: tuple[str, ...]


@dataclass(frozen=True)
class LiveEventRow:
    event: SysmonEvent
    rules: tuple[Rule, ...]
    summary: str

    @property
    def match_count(self) -> int:
        return len(self.rules)

    @property
    def max_level(self) -> str | None:
        if not self.rules:
            return None
        return max(
            (rule.level.lower() for rule in self.rules),
            key=lambda level: LEVELS.get(level, 0),
        )


class _Cancelled(Exception):
    """Internal cancellation marker used while the window is closing."""


def event_type_name(event_id: int) -> str:
    return EVENT_NAMES.get(event_id, f"Event {event_id}")


def _field(event: SysmonEvent, name: str) -> str:
    value = event.get(name)
    return value.strip() if value else ""


def _join(*parts: str) -> str:
    return "  ".join(part for part in parts if part)


def event_summary(event: SysmonEvent) -> str:
    """Return a compact, human-readable summary of a Sysmon event."""

    eid = event.event_id
    image = _field(event, "Image")
    target = _field(event, "TargetFilename")
    target_object = _field(event, "TargetObject")

    if eid == 1:
        summary = _join(image, _field(event, "CommandLine"))
    elif eid == 2:
        summary = target
    elif eid == 3:
        destination = _field(event, "DestinationHostname") or _field(
            event, "DestinationIp"
        )
        port = _field(event, "DestinationPort")
        if destination and port:
            destination = f"{destination}:{port}"
        if destination:
            summary = _join(image, "->", destination) if image else destination
        else:
            summary = image
    elif eid == 4:
        summary = _field(event, "State") or "Sysmon service state changed"
    elif eid == 5:
        summary = image
    elif eid == 6:
        summary = _join(_field(event, "ImageLoaded"), "driver loaded")
    elif eid == 7:
        summary = _field(event, "ImageLoaded")
    elif eid == 8:
        source = _field(event, "SourceImage")
        target_image = _field(event, "TargetImage")
        summary = " -> ".join(part for part in (source, target_image) if part)
    elif eid == 9:
        summary = _join(image, _field(event, "Device"))
    elif eid == 10:
        source = _field(event, "SourceImage")
        target_image = _field(event, "TargetImage")
        access = _field(event, "GrantedAccess")
        summary = " -> ".join(part for part in (source, target_image) if part)
        if access:
            summary = _join(summary, f"access={access}")
    elif eid in {12, 13, 14}:
        summary = _join(
            target_object, _field(event, "Details"), _field(event, "NewName")
        )
    elif eid == 15:
        summary = target
    elif eid == 16:
        summary = "Sysmon configuration changed"
    elif eid in {17, 18}:
        summary = _join(_field(event, "PipeName"), image)
    elif eid in {19, 20, 21}:
        summary = _join(
            _field(event, "EventType"),
            _field(event, "Operation"),
            _field(event, "Query"),
            _field(event, "Consumer"),
            _field(event, "Destination"),
        )
    elif eid == 22:
        summary = _join(_field(event, "QueryName"), _field(event, "QueryResults"))
    elif eid in {23, 26, 27, 28}:
        summary = target
    elif eid == 24:
        summary = _join(image, _field(event, "ClientInfo"))
    elif eid == 25:
        summary = _join(image, _field(event, "Type"))
    elif eid == 29:
        summary = _field(event, "Image") or target
    else:
        summary = _join(
            image,
            target,
            target_object,
            _field(event, "QueryName"),
            _field(event, "PipeName"),
            _field(event, "DestinationIp"),
        )

    if not summary:
        summary = _join(
            image,
            target,
            target_object,
            _field(event, "CommandLine"),
            _field(event, "Details"),
        )
    return summary or "(no event data)"


def _local_timestamp(event: SysmonEvent) -> str:
    timestamp = event.timestamp
    if timestamp is None:
        return ""
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _format_count(value: int) -> str:
    return f"{value:,}"


def _overflow_indices(
    rows: list[LiveEventRow], max_rows: int, max_matched_rows: int
) -> set[int]:
    """Return the indices of rows to drop, oldest unmatched rows first."""
    unmatched = [index for index, row in enumerate(rows) if not row.match_count]
    matched = [index for index, row in enumerate(rows) if row.match_count]
    drop = set(unmatched[: max(0, len(unmatched) - max_rows)])
    drop.update(matched[: max(0, len(matched) - max_matched_rows)])
    return drop


def _removal_ranges(indices: list[int]) -> list[tuple[int, int]]:
    """Group sorted row indices into inclusive ``(start, end)`` runs.

    The highest run comes first so callers can delete rows from the bottom up
    without invalidating the indices below.
    """
    ranges: list[tuple[int, int]] = []
    for index in indices:
        if ranges and index == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], index)
        else:
            ranges.append((index, index))
    ranges.reverse()
    return ranges


def _windows_build_number() -> int | None:
    """Return the Windows build number, or None when not running on Windows."""

    if sys.platform != "win32":
        return None
    try:
        return sys.getwindowsversion().build
    except (AttributeError, OSError):
        return None


def choose_style_name() -> str | None:
    """Return the preferred available Qt style on this machine."""

    keys = {key.lower(): key for key in QStyleFactory.keys()}
    build = _windows_build_number()
    if build is not None and build >= 22000:
        names = ("windows11", "windowsvista")
    else:
        names = ("windowsvista", "windows11")
    for name in names:
        if name in keys:
            return keys[name]
    return None


def load_application_icon() -> QIcon:
    """Load the custom sigmatch icon from source or installed package data."""

    package_dir = Path(__file__).resolve().parent
    icon = QIcon()
    candidates = (
        package_dir / "assets" / "icon.ico",
        package_dir / "assets" / "icon.png",
    )
    for path in candidates:
        if path.is_file():
            icon.addFile(str(path))
    return icon


def _rules_by_severity(rules: Iterable[Rule]) -> list[Rule]:
    return sorted(
        rules,
        key=lambda rule: (-LEVELS.get(rule.level.lower(), 0), rule.title.casefold()),
    )


# ---------------------------------------------------------------------------
# Worker: discover and compile Sigma rules
# ---------------------------------------------------------------------------


def _paths_block(paths: Sequence[Path]) -> str:
    return "\n".join(f"  - {path}" for path in paths)


def _rule_problems_for_empty_result(
    search_paths: Sequence[Path], files: Sequence[Path]
) -> Problem:
    details = (
        "Searched paths:\n"
        f"{_paths_block(search_paths)}\n\n"
        f"Rule files found: {len(files)}\n\n"
        "Point sigmatch at a SigmaHQ repository or its rules directory, for example:\n"
        "  python sigmatch_gui.py --rules Z:\\sigma\n"
        "  python sigmatch_gui.py --rules Z:\\sigma\\rules"
    )
    return Problem(
        "No usable Sigma rules were found.",
        "The selected paths did not contain any Sysmon-compatible Sigma rules. "
        "Check that --rules points at the SigmaHQ rules directory.",
        details,
    )


def _rule_discovery_problem(
    search_paths: Sequence[Path],
    missing_paths: Sequence[Path],
    scan_errors: Sequence[str],
) -> Problem:
    errors_block = (
        os.linesep.join("  - " + item for item in scan_errors)
        if scan_errors
        else "  (none)"
    )
    details = (
        "Searched paths:\n"
        f"{_paths_block(search_paths)}\n\n"
        "Missing paths:\n"
        f"{_paths_block(missing_paths) if missing_paths else '  (none)'}\n\n"
        "Access errors:\n"
        f"{errors_block}"
    )
    return Problem(
        "No Sigma rule files could be read.",
        "sigmatch could not find any .yml/.yaml rule files. "
        "Check the --rules path and make sure it is accessible.",
        details,
    )


def _rule_warning(outcome: LoaderOutcome) -> Problem | None:
    notes: list[str] = []
    if outcome.missing_paths:
        notes.append(f"{len(outcome.missing_paths)} rule path(s) were not found")
    if outcome.scan_errors:
        notes.append(f"{len(outcome.scan_errors)} path(s) could not be scanned")
    if outcome.result.errors:
        notes.append(f"{len(outcome.result.errors)} rule file(s) could not be compiled")
    if outcome.result.duplicates:
        notes.append(
            f"{outcome.result.duplicates} duplicate rule id(s) were skipped"
        )
    if not notes:
        return None

    details: list[str] = []
    details.append(f"Active rules: {len(outcome.result.rules):,}")
    details.append(f"Files scanned: {outcome.result.files_scanned:,}")
    details.append(f"Duplicate rule ids skipped: {outcome.result.duplicates:,}")
    details.append(f"Search paths:\n{_paths_block(outcome.search_paths)}")
    if outcome.missing_paths:
        details.append(f"Missing paths:\n{_paths_block(outcome.missing_paths)}")
    if outcome.scan_errors:
        details.append("Path scan errors:")
        details.extend(f"  - {item}" for item in outcome.scan_errors)
    if outcome.result.errors:
        details.append("Rule compile errors:")
        for error in outcome.result.errors[:20]:
            details.append(f"  - {error.path}: {error.message}")
        if len(outcome.result.errors) > 20:
            details.append(f"  ... and {len(outcome.result.errors) - 20} more")
    return Problem(
        "Rules loaded with warnings.",
        f"{len(outcome.result.rules):,} Sysmon rules are active, but "
        + "; ".join(notes)
        + ". The matcher will continue with the rules that loaded successfully.",
        "\n".join(details),
    )


def _live_problem(exc: BaseException) -> Problem:
    text = str(exc)
    lowered = text.lower()
    if "pyetwkit" in lowered:
        return Problem(
            "ETW support is missing.",
            "Live Sysmon reading requires pyetwkit, and sigmatch could not install "
            "it automatically. Install it manually and restart sigmatch.",
            "Technical details:" + chr(10) + text + chr(10) * 2
            + "Install with: python -m pip install pyetwkit",
        )
    if "sysmon" in lowered and (
        "automatic" in lowered or "automatically" in lowered
    ):
        return Problem(
            "Sysmon could not be installed automatically.",
            "sigmatch tried to install and start Sysmon, but Windows did not allow "
            "it. Run sigmatch as administrator and make sure the Sysmon service can "
            "start, then click Retry.",
            "Technical details:" + chr(10) + text,
        )
    if (
        "access is denied" in lowered
        or "access denied" in lowered
        or "privilege" in lowered
        or ("elevat" in lowered and "denied" in lowered)
    ):
        return Problem(
            "Access to the Sysmon ETW provider was denied.",
            "Consuming the Sysmon ETW provider requires administrator rights. "
            "Restart sigmatch without --no-elevate and accept the elevation prompt. "
            "If this keeps happening, verify that the Sysmon service is running.",
            f"Technical details:\n{text}",
        )
    if (
        "not found" in lowered
        or "cannot find" in lowered
        or "does not exist" in lowered
        or "channel" in lowered
        or "could not be opened" in lowered
    ):
        return Problem(
            "The Sysmon ETW provider is not available.",
            "sigmatch could not open Microsoft-Windows-Sysmon/Operational. "
            "Install Sysmon, make sure its service (Sysmon64) is running, and check "
            "that Sysmon is configured to write to that event channel.",
            f"Technical details:\n{text}",
        )
    return Problem(
        "The live Sysmon event feed stopped.",
        "sigmatch could not continue reading the Sysmon event log. "
        "Check that Sysmon is running and that this app is elevated, then click Retry.",
        f"Technical details:\n{text}",
    )


class RuleLoader(QObject):
    """Discover and compile rules off the UI thread."""

    progress = pyqtSignal(object)
    loaded = pyqtSignal(object)
    failed = pyqtSignal(object)
    finished = pyqtSignal()

    def __init__(
        self,
        rule_paths: Sequence[str],
        *,
        all_rule_sets: bool = False,
        stop_event: threading.Event,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._rule_paths = list(rule_paths)
        self._all_rule_sets = all_rule_sets
        self._stop_event = stop_event

    def _check_cancelled(self) -> None:
        if self._stop_event.is_set():
            raise _Cancelled()

    @pyqtSlot()
    def run(self) -> None:
        try:
            outcome = self._load()
            if outcome is not None and not self._stop_event.is_set():
                self.loaded.emit(outcome)
        except _Cancelled:
            pass
        except _RuleLoadFailure as exc:
            if not self._stop_event.is_set():
                self.failed.emit(exc.problem)
        except Exception as exc:  # defensive: never kill the Qt thread silently
            if not self._stop_event.is_set():
                self.failed.emit(
                    Problem(
                        "Sigma rules could not be loaded.",
                        "An unexpected problem occurred while reading the rule set. "
                        "Check that the rules directory is accessible and try again.",
                        f"Technical details:\n{type(exc).__name__}: {exc}",
                    )
                )
        finally:
            self.finished.emit()

    def _load(self) -> LoaderOutcome | None:
        search_paths = tuple(Path(item).expanduser() for item in self._rule_paths)
        self.progress.emit(LoaderProgress("discovering", 0, 0, ""))
        expanded = tuple(
            expand_rule_paths(
                [str(path) for path in search_paths],
                all_rule_sets=self._all_rule_sets,
            )
        )
        if not expanded:
            raise _RuleLoadFailure(_rule_discovery_problem(search_paths, [], []))

        load_paths: list[Path] = []
        missing: list[Path] = []
        scan_errors: list[str] = []
        for path in expanded:
            self._check_cancelled()
            try:
                exists = path.exists()
            except OSError as exc:
                scan_errors.append(f"{path}: {exc}")
                continue
            if not exists:
                missing.append(path)
                continue
            if path.is_file() or path.is_dir():
                load_paths.append(path)
            else:
                scan_errors.append(f"{path}: not a file or directory")

        last_progress = 0.0

        def on_discover(count: int, path: Path) -> None:
            nonlocal last_progress
            self._check_cancelled()
            now = time.monotonic()
            if now - last_progress >= 0.10:
                self.progress.emit(
                    LoaderProgress("discovering", count, 0, str(path))
                )
                last_progress = now

        records = []
        if load_paths:
            try:
                records = discover_rule_records(
                    [str(item) for item in load_paths], progress=on_discover
                )
            except (FileNotFoundError, OSError) as exc:
                scan_errors.append(str(exc))

        files = [record.path for record in records]
        if not files:
            if missing and not scan_errors:
                details = (
                    "Searched paths:" + chr(10)
                    + _paths_block(search_paths) + chr(10) * 2
                    + "Those paths do not exist. Put the SigmaHQ repository at "
                    + "Z:" + chr(92) + "sigma (or another location) and pass its path with --rules."
                    + chr(10) * 2
                    + "Typical locations:" + chr(10)
                    + "  - <tool>" + chr(92) + "sigma" + chr(92) + "rules" + chr(10)
                    + "  - <tool>" + chr(92) + ".." + chr(92) + "sigma" + chr(92) + "rules"
                )
                raise _RuleLoadFailure(
                    Problem(
                        "The Sigma rules directory was not found.",
                        "sigmatch looked for Sigma rules but none of the configured paths exist. "
                        "Use --rules to point at your SigmaHQ repository.",
                        details,
                    )
                )
            raise _RuleLoadFailure(
                _rule_discovery_problem(search_paths, missing, scan_errors)
            )

        total = len(files)
        self.progress.emit(LoaderProgress("loading", 0, total, ""))
        last_progress = 0.0

        def on_progress(scanned: int, path: Path) -> None:
            nonlocal last_progress
            self._check_cancelled()
            now = time.monotonic()
            if scanned == total or scanned == 1 or now - last_progress >= 0.05:
                self.progress.emit(
                    LoaderProgress("loading", scanned, total, str(path))
                )
                last_progress = now

        try:
            result = load_rule_records(records, progress=on_progress)
        except (FileNotFoundError, OSError) as exc:
            raise _RuleLoadFailure(
                Problem(
                    "The Sigma rules could not be read.",
                    "sigmatch found rule files but could not open them. "
                    "Check file permissions and make sure the rules directory is accessible.",
                    "Technical details:" + chr(10) + f"{type(exc).__name__}: {exc}",
                )
            ) from exc
        self._check_cancelled()

        if not result.rules:
            problem = _rule_problems_for_empty_result(search_paths, files)
            if result.errors:
                details = (
                    problem.details + chr(10) * 2
                    + "Rule errors:" + chr(10)
                    + chr(10).join(
                        f"  - {error.path}: {error.message}"
                        for error in result.errors[:20]
                    )
                )
                problem = Problem(problem.title, problem.message, details)
            raise _RuleLoadFailure(problem)

        return LoaderOutcome(
            result=result,
            ruleset=RuleSet(result.rules),
            files=tuple(files),
            search_paths=search_paths,
            missing_paths=tuple(missing),
            scan_errors=tuple(scan_errors),
        )


# ---------------------------------------------------------------------------
# Worker: follow the live Sysmon feed
# ---------------------------------------------------------------------------


class LiveMonitor(QObject):
    """Read live Sysmon events and match them against a compiled RuleSet."""

    started = pyqtSignal()
    event_found = pyqtSignal(object)
    failed = pyqtSignal(object)
    finished = pyqtSignal()

    def __init__(
        self,
        ruleset: RuleSet,
        stop_event: threading.Event,
        *,
        channel: str = SYSMON_CHANNEL,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._ruleset = ruleset
        self._stop_event = stop_event
        self._channel = channel

    @pyqtSlot()
    def run(self) -> None:
        events = None
        try:
            events = EtwSource(self._channel, stop_event=self._stop_event)
            events.start(on_subscribe=self.started.emit)
            for event in events:
                if self._stop_event.is_set():
                    break

                matched = tuple(self._ruleset.match(event.event_id, event.lookup))
                self.event_found.emit(
                    LiveEventRow(
                        event=event,
                        rules=matched,
                        summary=event_summary(event),
                    )
                )
        except SourceError as exc:
            if not self._stop_event.is_set():
                self.failed.emit(_live_problem(exc))
        except Exception as exc:  # defensive: keep the rest of the window alive
            if not self._stop_event.is_set():
                self.failed.emit(
                    Problem(
                        "The live Sysmon event feed stopped unexpectedly.",
                        "sigmatch hit an internal error while reading events. "
                        "Check that Sysmon and this app are still running, then click Retry.",
                        f"Technical details:\n{type(exc).__name__}: {exc}",
                    )
                )
        finally:
            if events is not None:
                close = getattr(events, "close", None)
                if close is not None:
                    try:
                        close()
                    except Exception:
                        pass
            self.finished.emit()


# ---------------------------------------------------------------------------
# Table model
# ---------------------------------------------------------------------------


class EventTableModel(QAbstractTableModel):
    HEADERS = ("Time", "Event", "Summary", "Matches", "Level", "Record")

    def __init__(
        self,
        parent: QObject | None = None,
        *,
        max_rows: int = MAX_ROWS,
        max_matched_rows: int = MAX_MATCHED_ROWS,
    ) -> None:
        super().__init__(parent)
        self._rows: list[LiveEventRow] = []
        self._max_rows = max(1, max_rows)
        self._max_matched_rows = max(1, max_matched_rows)
        self._bold_font = QFont(QApplication.font())
        self._bold_font.setBold(True)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.HEADERS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = 0
    ):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
        ):
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = 0):
        if not index.isValid() or not (0 <= index.row() < len(self._rows)):
            return None
        row = self._rows[index.row()]
        column = index.column()
        event = row.event

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return _local_timestamp(event)
            if column == 1:
                return f"{event.event_id}  {event_type_name(event.event_id)}"
            if column == 2:
                return " ".join(row.summary.splitlines())
            if column == 3:
                return str(row.match_count) if row.match_count else "-"
            if column == 4:
                level = row.max_level
                return level.title() if level else ""
            if column == 5:
                return (
                    str(event.record_id) if event.record_id is not None else "-"
                )
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            tooltip = [
                f"{_local_timestamp(event) or '(no timestamp)'}",
                f"Event {event.event_id}: {event_type_name(event.event_id)}",
                row.summary,
            ]
            if event.record_id is not None:
                tooltip.append(f"Record ID: {event.record_id}")
            tooltip.append("")
            if row.rules:
                tooltip.append(f"Matched {len(row.rules)} rule(s):")
                tooltip.extend(
                    f"  [{rule.level.upper()}] {rule.title}"
                    for rule in _rules_by_severity(row.rules)[:12]
                )
                if len(row.rules) > 12:
                    tooltip.append(f"  ... and {len(row.rules) - 12} more")
            else:
                tooltip.append("No Sigma rule matched this event.")
            return "\n".join(tooltip)

        if role == Qt.ItemDataRole.UserRole:
            return row

        if role == Qt.ItemDataRole.TextAlignmentRole and column in {3, 5}:
            return int(
                Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter
            )

        if role == Qt.ItemDataRole.FontRole:
            if column == 3 and row.rules:
                return self._bold_font
            if column == 4 and row.max_level in LEVEL_BACKGROUND:
                return self._bold_font
            return None

        if role == Qt.ItemDataRole.ForegroundRole and column == 4:
            return LEVEL_FOREGROUND.get(row.max_level or "")

        if role == Qt.ItemDataRole.BackgroundRole and column == 4:
            return LEVEL_BACKGROUND.get(row.max_level or "")

        return None

    def append_rows(self, rows: Iterable[LiveEventRow]) -> None:
        incoming = list(rows)
        if not incoming:
            return
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(incoming) - 1)
        self._rows.extend(incoming)
        self.endInsertRows()
        self._trim()

    def _trim(self) -> None:
        """Drop old rows, but keep rows that matched a rule.

        The oldest unmatched events are removed first, so the table always
        holds ``max_rows`` events of recent context no matter how many matches
        pour in.  Matched rows only go away once ``max_matched_rows`` are held.
        """
        drop = _overflow_indices(self._rows, self._max_rows, self._max_matched_rows)
        if not drop:
            return
        # Remove from the highest index down so the remaining indices stay valid.
        for start, end in _removal_ranges(sorted(drop)):
            self.beginRemoveRows(QModelIndex(), start, end)
            del self._rows[start : end + 1]
            self.endRemoveRows()

    def row_at(self, row: int) -> LiveEventRow | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def clear(self) -> None:
        if not self._rows:
            return
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    @property
    def max_rows(self) -> int:
        return self._max_rows

    @property
    def max_matched_rows(self) -> int:
        return self._max_matched_rows


class EventFilterProxyModel(QSortFilterProxyModel):
    """Hide events that did not match any Sigma rule, without touching the source."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._matched_only = False
        self.setDynamicSortFilter(True)

    @property
    def matched_only(self) -> bool:
        return self._matched_only

    def set_matched_only(self, enabled: bool) -> None:
        enabled = bool(enabled)
        if enabled == self._matched_only:
            return
        self._matched_only = enabled
        self.invalidateFilter()

    def filterAcceptsRow(
        self, source_row: int, _source_parent: QModelIndex
    ) -> bool:
        if not self._matched_only:
            return True
        model = self.sourceModel()
        if not isinstance(model, EventTableModel):
            return True
        row = model.row_at(source_row)
        return bool(row is not None and row.match_count)


# ---------------------------------------------------------------------------
# Small UI pieces
# ---------------------------------------------------------------------------


class ProblemDetailsDialog(QDialog):
    def __init__(self, problem: Problem, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Problem details")
        self.resize(780, 500)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 12)
        layout.setSpacing(10)

        title = QLabel(problem.title)
        title_font = QFont(self.font())
        title_font.setBold(True)
        title.setFont(title_font)
        title.setWordWrap(True)
        layout.addWidget(title)

        message = QLabel(problem.message)
        message.setWordWrap(True)
        message.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(message)

        details = QPlainTextEdit(problem.details or "(no additional details)")
        details.setReadOnly(True)
        details.setFont(
            QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        )
        details.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(details, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.accept)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class Banner(QFrame):
    """Inline progress / warning / error banner above the event table."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("statusBanner")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)
        self.setBackgroundRole(QPalette.ColorRole.AlternateBase)
        self.setAutoFillBackground(True)
        self.setVisible(False)
        self.kind = ""
        self._details_text = ""
        self._retry: Callable[[], None] | None = None

        outer = QHBoxLayout(self)
        outer.setContentsMargins(12, 9, 10, 9)
        outer.setSpacing(10)

        self._icon = QLabel()
        self._icon.setFixedSize(24, 24)
        self._icon.setAlignment(Qt.AlignmentFlag.AlignTop)
        outer.addWidget(self._icon)

        content = QVBoxLayout()
        content.setSpacing(4)
        self._title = QLabel()
        title_font = QFont(self.font())
        title_font.setBold(True)
        self._title.setFont(title_font)
        self._title.setWordWrap(True)
        content.addWidget(self._title)

        self._detail = QLabel()
        self._detail.setWordWrap(True)
        self._detail.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._detail.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        content.addWidget(self._detail)

        self._progress = QProgressBar()
        self._progress.setFixedHeight(18)
        self._progress.setTextVisible(True)
        self._progress.setMinimumWidth(280)
        content.addWidget(self._progress)
        outer.addLayout(content, 1)

        actions = QVBoxLayout()
        actions.setSpacing(5)
        self._retry_button = QPushButton("Retry")
        self._retry_button.clicked.connect(self._retry_clicked)
        actions.addWidget(self._retry_button)

        self._details_button = QPushButton("Details...")
        self._details_button.clicked.connect(self._show_details)
        actions.addWidget(self._details_button)

        self._dismiss_button = QToolButton()
        self._dismiss_button.setAutoRaise(True)
        self._dismiss_button.setToolTip("Dismiss")
        self._dismiss_button.setIcon(
            self.style().standardIcon(
                QStyle.StandardPixmap.SP_TitleBarCloseButton
            )
        )
        self._dismiss_button.clicked.connect(self.hide_banner)
        actions.addWidget(self._dismiss_button)
        outer.addLayout(actions)

        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self.hide_banner)

    def _set_icon(self, standard_pixmap: QStyle.StandardPixmap) -> None:
        self._icon.setPixmap(
            self.style().standardIcon(standard_pixmap).pixmap(24, 24)
        )

    def _reset_buttons(self) -> None:
        self._retry_button.hide()
        self._details_button.hide()
        self._dismiss_button.hide()
        self._retry = None
        self._details_text = ""

    def show_loading(
        self,
        title: str,
        detail: str,
        current: int | None = None,
        total: int | None = None,
        *,
        tooltip: str = "",
    ) -> None:
        self._hide_timer.stop()
        self.kind = "loading"
        self._reset_buttons()
        self._set_icon(QStyle.StandardPixmap.SP_MessageBoxInformation)
        self._title.setText(title)
        self._detail.setText(detail)
        self._detail.setToolTip(tooltip)
        if current is None or total is None:
            self._progress.setRange(0, 0)
            self._progress.setTextVisible(False)
        else:
            self._progress.setRange(0, max(1, total))
            self._progress.setValue(max(0, min(current, total)))
            self._progress.setFormat("%v / %m files (%p%)")
            self._progress.setTextVisible(True)
        self._progress.show()
        self.show()

    def show_warning(
        self,
        problem: Problem,
        *,
        timeout_ms: int = 10_000,
    ) -> None:
        self._hide_timer.stop()
        self.kind = "warning"
        self._reset_buttons()
        self._set_icon(QStyle.StandardPixmap.SP_MessageBoxWarning)
        self._title.setText(problem.title)
        self._detail.setText(problem.message)
        self._detail.setToolTip(problem.details)
        self._details_text = problem.details
        self._progress.hide()
        self._details_button.setVisible(bool(problem.details))
        self._dismiss_button.show()
        self.show()
        if timeout_ms > 0:
            self._hide_timer.start(timeout_ms)

    def show_error(
        self,
        problem: Problem,
        *,
        retry: Callable[[], None] | None = None,
    ) -> None:
        self._hide_timer.stop()
        self.kind = "error"
        self._reset_buttons()
        self._set_icon(QStyle.StandardPixmap.SP_MessageBoxCritical)
        self._title.setText(problem.title)
        self._detail.setText(problem.message)
        self._detail.setToolTip(problem.details)
        self._details_text = problem.details
        self._retry = retry
        self._progress.hide()
        self._retry_button.setVisible(retry is not None)
        self._details_button.setVisible(bool(problem.details))
        self._dismiss_button.show()
        self.show()

    def hide_banner(self) -> None:
        self._hide_timer.stop()
        self.kind = ""
        self.hide()

    def _retry_clicked(self) -> None:
        callback = self._retry
        self.hide_banner()
        if callback is not None:
            callback()

    def _show_details(self) -> None:
        dialog = ProblemDetailsDialog(
            Problem(
                self._title.text(),
                self._detail.text(),
                self._details_text,
            ),
            self.window(),
        )
        dialog.exec()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(
        self,
        rule_paths: Sequence[str | Path] | None = None,
        *,
        all_rule_sets: bool = False,
        auto_start: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("sigmatch - Live Sysmon")
        self.resize(1320, 860)
        self.setMinimumSize(900, 560)
        self._application_icon = load_application_icon()
        if not self._application_icon.isNull():
            self.setWindowIcon(self._application_icon)

        self._rule_paths = [
            str(path) for path in (rule_paths or default_rule_paths())
        ]
        self._all_rule_sets = all_rule_sets
        self._stop_event = threading.Event()
        self._closing = False
        self._ruleset: RuleSet | None = None
        self._total_events = 0
        self._total_matches = 0
        self._pending: list[LiveEventRow] = []
        self._loader_thread: QThread | None = None
        self._loader_worker: RuleLoader | None = None
        self._monitor_thread: QThread | None = None
        self._monitor_worker: LiveMonitor | None = None
        self._first_event_seen = False
        self._retry_loader_pending = False
        self._retry_monitor_pending = False
        self._tray: QSystemTrayIcon | None = None
        self._tray_available = False
        self._last_notification_row: LiveEventRow | None = None

        self._build_ui()
        self._setup_notifications()
        self._matched_only_checkbox.toggled.connect(
            self._matched_only_changed
        )
        self._notify_checkbox.toggled.connect(self._notify_toggled)
        self._banner.show_loading(
            "Starting sigmatch...",
            "Preparing to discover and load Sigma rules.",
            None,
            None,
        )
        self._update_totals()

        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(BATCH_INTERVAL_MS)
        self._flush_timer.timeout.connect(self._flush_events)
        self._flush_timer.start()

        if auto_start:
            QTimer.singleShot(0, self._start_loading)

    # -- UI construction ---------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget(self)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 8, 10, 0)
        layout.setSpacing(8)
        self.setCentralWidget(central)

        self._banner = Banner(central)
        layout.addWidget(self._banner)

        filter_bar = QHBoxLayout()
        filter_bar.setContentsMargins(2, 0, 2, 0)
        filter_bar.setSpacing(20)
        self._matched_only_checkbox = QCheckBox(
            "Only events with Sigma matches"
        )
        self._matched_only_checkbox.setChecked(False)
        self._matched_only_checkbox.setToolTip(
            "Hide live events that did not match any Sigma rule."
        )
        self._notify_checkbox = QCheckBox(
            "Notify for high/critical matches"
        )
        self._notify_checkbox.setChecked(True)
        self._notify_checkbox.setToolTip(
            "Show a Windows notification when an event matches a high or "
            "critical Sigma rule."
        )
        filter_bar.addWidget(self._matched_only_checkbox)
        filter_bar.addWidget(self._notify_checkbox)
        filter_bar.addStretch(1)
        layout.addLayout(filter_bar)

        splitter = QSplitter(Qt.Orientation.Vertical, central)
        splitter.setChildrenCollapsible(False)

        self._model = EventTableModel(self)
        self._proxy = EventFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._table = QTableView(splitter)
        self._table.setModel(self._proxy)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._table.setWordWrap(False)
        self._table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._table.setShowGrid(False)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(24)
        self._table.setAccessibleName("Live Sysmon events")

        header = self._table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 142)
        self._table.setColumnWidth(1, 190)
        self._table.setColumnWidth(3, 72)
        self._table.setColumnWidth(4, 92)
        self._table.setColumnWidth(5, 78)
        self._table.selectionModel().currentRowChanged.connect(
            self._current_row_changed
        )
        splitter.addWidget(self._table)

        self._details_stack = QStackedWidget(splitter)

        placeholder = QLabel(
            "Click an event to inspect its fields and any matched Sigma rules."
        )
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setWordWrap(True)
        placeholder_palette = placeholder.palette()
        placeholder_palette.setColor(
            QPalette.ColorRole.WindowText,
            self.palette().color(QPalette.ColorRole.PlaceholderText),
        )
        placeholder.setPalette(placeholder_palette)
        self._details_stack.addWidget(placeholder)

        details = QWidget(self._details_stack)
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(2, 4, 2, 4)
        details_layout.setSpacing(3)

        self._detail_header = QLabel("Select an event")
        header_font = QFont(self.font())
        header_font.setBold(True)
        self._detail_header.setFont(header_font)
        self._detail_header.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details_layout.addWidget(self._detail_header)

        self._detail_meta = QLabel()
        self._detail_meta.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details_layout.addWidget(self._detail_meta)

        self._tabs = QTabWidget(details)
        self._rules_view = QTextBrowser()
        self._rules_view.setOpenExternalLinks(False)
        self._rules_view.setOpenLinks(False)
        self._fields_view = QTableWidget(0, 2)
        self._fields_view.setHorizontalHeaderLabels(["Field", "Value"])
        self._fields_view.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._fields_view.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._fields_view.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._fields_view.setAlternatingRowColors(True)
        self._fields_view.setShowGrid(False)
        self._fields_view.setWordWrap(False)
        self._fields_view.verticalHeader().setVisible(False)
        self._fields_view.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self._fields_view.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._raw_view = QPlainTextEdit()
        self._raw_view.setReadOnly(True)
        self._raw_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._raw_view.setFont(
            QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        )
        self._tabs.addTab(self._rules_view, "Matched rules")
        self._tabs.addTab(self._fields_view, "Event fields")
        self._tabs.addTab(self._raw_view, "Raw XML")
        details_layout.addWidget(self._tabs, 1)

        self._details_stack.addWidget(details)
        self._details_stack.setCurrentIndex(0)
        splitter.addWidget(self._details_stack)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([590, 280])
        layout.addWidget(splitter, 1)

        self._status_label = QLabel("Starting...")
        self._status_label.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        self._status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._totals_label = QLabel()
        self._totals_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.statusBar().addWidget(self._status_label, 1)
        self.statusBar().addPermanentWidget(self._totals_label)

    # -- display filter and notifications ---------------------------------

    def _matched_only_changed(self, enabled: bool) -> None:
        self._proxy.set_matched_only(enabled)
        self._table.clearSelection()
        self._table.setCurrentIndex(QModelIndex())
        self._clear_details()
        self._table.scrollToBottom()

    def _setup_notifications(self) -> None:
        try:
            self._tray_available = QSystemTrayIcon.isSystemTrayAvailable()
            icon = self.windowIcon()
            if icon.isNull():
                icon = load_application_icon()
            if icon.isNull():
                icon = self.style().standardIcon(
                    QStyle.StandardPixmap.SP_ComputerIcon
                )
                self.setWindowIcon(icon)
            tray = QSystemTrayIcon(icon, self)
            tray.setToolTip("sigmatch - Live Sysmon")
            menu = QMenu(self)
            menu.addAction("Open sigmatch", self._show_window)
            menu.addAction("Quit sigmatch", self.close)
            tray.setContextMenu(menu)
            tray.messageClicked.connect(self._notification_clicked)
            self._tray = tray
        except Exception:
            self._tray = None
            self._tray_available = False
        if not self._tray_available:
            self._notify_checkbox.setToolTip(
                "Windows notifications are not available in this session. "
                "Live monitoring still works."
            )
        self._update_tray_visibility()

    def _update_tray_visibility(self) -> None:
        if self._tray is None:
            return
        if self._notify_checkbox.isChecked() and self._tray_available:
            self._tray.show()
        else:
            self._tray.hide()

    def _notify_toggled(self, _enabled: bool) -> None:
        self._update_tray_visibility()

    def _show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _notification_clicked(self) -> None:
        self._show_window()
        row = self._last_notification_row
        if row is None:
            return
        if self._pending:
            self._flush_events()
        for source_row in range(self._model.rowCount() - 1, -1, -1):
            if self._model.row_at(source_row) is row:
                index = self._proxy.mapFromSource(
                    self._model.index(source_row, 0)
                )
                if index.isValid():
                    self._table.selectRow(index.row())
                    self._table.scrollTo(
                        index,
                        QAbstractItemView.ScrollHint.PositionAtCenter,
                    )
                return

    def _notify_high_critical(self, row: LiveEventRow) -> None:
        relevant = [
            rule
            for rule in row.rules
            if rule.level.lower() in {"high", "critical"}
        ]
        if not relevant:
            return
        relevant = _rules_by_severity(relevant)
        critical = relevant[0].level.lower() == "critical"
        title = (
            "Critical Sigma match"
            if critical
            else "High severity Sigma match"
        )
        rule_titles = [rule.title for rule in relevant[:2]]
        if len(relevant) > 2:
            rule_titles.append(f"+{len(relevant) - 2} more")
        summary = " ".join(row.summary.splitlines())
        message = (
            " | ".join(rule_titles)
            + chr(10)
            + f"Event {row.event.event_id} - "
            + f"{event_type_name(row.event.event_id)}: {summary}"
        )
        if len(message) > 350:
            message = message[:347] + "..."
        self._last_notification_row = row
        self._show_notification(title, message, critical)

    def _show_notification(
        self, title: str, message: str, critical: bool
    ) -> None:
        if not self._notify_checkbox.isChecked():
            return
        if not self._tray_available or self._tray is None:
            return
        icon = (
            QSystemTrayIcon.MessageIcon.Critical
            if critical
            else QSystemTrayIcon.MessageIcon.Warning
        )
        try:
            self._tray.showMessage(title, message, icon, 10_000)
        except Exception:
            pass

    # -- rule loading ------------------------------------------------------

    def _start_loading(self) -> None:
        if self._closing:
            return
        if self._loader_thread is not None and self._loader_thread.isRunning():
            self._retry_loader_pending = True
            return
        if self._monitor_thread is not None and self._monitor_thread.isRunning():
            return
        self._retry_loader_pending = False
        self._ruleset = None
        self._banner.show_loading(
            "Loading Sigma rules...",
            "Finding rule files. Large rule sets can take a while.",
            None,
            None,
        )
        self._status_label.setText("Discovering Sigma rule files...")
        self._status_label.setToolTip("")
        self._update_totals()

        thread = QThread(self)
        worker = RuleLoader(
            self._rule_paths,
            all_rule_sets=self._all_rule_sets,
            stop_event=self._stop_event,
        )
        worker.moveToThread(thread)
        self._loader_thread = thread
        self._loader_worker = worker

        thread.started.connect(worker.run)
        worker.progress.connect(self._loader_progress)
        worker.loaded.connect(self._rules_loaded)
        worker.failed.connect(self._loader_failed)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._loader_thread_finished)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    @pyqtSlot(object)
    def _loader_progress(self, progress: LoaderProgress) -> None:
        if self._closing:
            return
        name = Path(progress.path).name if progress.path else ""
        if progress.stage == "discovering":
            detail = f"{_format_count(progress.current)} rule file(s) found"
            if name:
                detail += f" - {name}"
            self._banner.show_loading(
                "Scanning for Sigma rules...",
                detail,
                None,
                None,
                tooltip=progress.path,
            )
            self._status_label.setText("Scanning for Sigma rule files...")
        else:
            detail = (
                f"{_format_count(progress.current)} of "
                f"{_format_count(progress.total)} files"
            )
            if name:
                detail += f" - {name}"
            self._banner.show_loading(
                "Loading Sigma rules...",
                detail,
                progress.current,
                progress.total,
                tooltip=progress.path,
            )
            self._status_label.setText(
                f"Loading Sigma rules: {_format_count(progress.current)} / "
                f"{_format_count(progress.total)} files"
            )
        self._status_label.setToolTip(progress.path)

    @pyqtSlot(object)
    def _rules_loaded(self, outcome: LoaderOutcome) -> None:
        if self._closing:
            return
        self._ruleset = outcome.ruleset
        self._banner.hide_banner()
        self._update_totals()
        warning = _rule_warning(outcome)
        if warning is not None:
            self._banner.show_warning(warning, timeout_ms=12_000)
            self._status_label.setToolTip(warning.details)
        else:
            self._status_label.setToolTip("")
        self._status_label.setText(
            f"Loaded {_format_count(len(outcome.ruleset))} Sigma rules from "
            f"{_format_count(len(outcome.files))} files. Starting live monitor..."
        )
        self._start_monitor()

    @pyqtSlot(object)
    def _loader_failed(self, problem: Problem) -> None:
        if self._closing:
            return
        self._ruleset = None
        self._banner.show_error(problem, retry=self._start_loading)
        self._status_label.setText("Sigma rules could not be loaded.")
        self._status_label.setToolTip(problem.details)
        self._update_totals()

    @pyqtSlot()
    def _loader_thread_finished(self) -> None:
        self._loader_worker = None
        self._loader_thread = None
        if self._retry_loader_pending and not self._closing:
            QTimer.singleShot(0, self._start_loading)

    # -- live monitoring ---------------------------------------------------

    def _start_monitor(self) -> None:
        if self._closing or self._ruleset is None or self._stop_event.is_set():
            return
        if self._monitor_thread is not None and self._monitor_thread.isRunning():
            self._retry_monitor_pending = True
            return
        self._retry_monitor_pending = False
        if self._banner.kind == "error":
            self._banner.hide_banner()
        self._status_label.setText(
            "Starting live monitor for Microsoft-Windows-Sysmon/Operational..."
        )

        thread = QThread(self)
        worker = LiveMonitor(self._ruleset, self._stop_event)
        worker.moveToThread(thread)
        self._monitor_thread = thread
        self._monitor_worker = worker

        thread.started.connect(worker.run)
        worker.started.connect(self._live_started)
        worker.event_found.connect(self._queue_event)
        worker.failed.connect(self._monitor_failed)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._monitor_thread_finished)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    @pyqtSlot()
    def _live_started(self) -> None:
        if self._closing:
            return
        if self._banner.kind == "loading":
            self._banner.hide_banner()
        self._status_label.setText(
            "Live - waiting for Sysmon events on Microsoft-Windows-Sysmon/Operational."
        )
        live_tooltip = (
            "sigmatch is consuming the Sysmon ETW provider. This window never "
            "stops on its own; close it to stop monitoring."
        )
        if self._banner.kind == "warning" and self._status_label.toolTip():
            live_tooltip = (
                self._status_label.toolTip() + chr(10) * 2 + live_tooltip
            )
        self._status_label.setToolTip(live_tooltip)

    @pyqtSlot(object)
    def _queue_event(self, row: LiveEventRow) -> None:
        if self._closing:
            return
        self._pending.append(row)
        self._total_events += 1
        self._total_matches += row.match_count
        if len(self._pending) > MAX_PENDING_EVENTS:
            self._trim_pending()
        if not self._first_event_seen:
            self._first_event_seen = True
            self._status_label.setText(
                "Live - following Microsoft-Windows-Sysmon/Operational."
            )
        if self._notify_checkbox.isChecked():
            self._notify_high_critical(row)

    def _trim_pending(self) -> None:
        """Cap the queue without throwing away events that matched a rule."""
        drop = _overflow_indices(
            self._pending, MAX_PENDING_EVENTS, MAX_PENDING_EVENTS
        )
        if drop:
            self._pending[:] = [
                row
                for index, row in enumerate(self._pending)
                if index not in drop
            ]

    def _flush_events(self) -> None:
        if self._closing:
            return
        if not self._pending:
            self._update_totals()
            return

        scrollbar = self._table.verticalScrollBar()
        at_bottom = scrollbar.value() >= scrollbar.maximum() - 2
        batch = self._pending[:1000]
        del self._pending[:1000]
        self._model.append_rows(batch)
        if at_bottom:
            self._table.scrollToBottom()
        self._update_totals()

    @pyqtSlot(object)
    def _monitor_failed(self, problem: Problem) -> None:
        if self._closing:
            return
        self._banner.show_error(problem, retry=self._start_monitor)
        self._status_label.setText("Live monitoring stopped. See the message above.")
        self._status_label.setToolTip(problem.details)

    @pyqtSlot()
    def _monitor_thread_finished(self) -> None:
        self._monitor_worker = None
        self._monitor_thread = None
        if self._retry_monitor_pending and not self._closing:
            QTimer.singleShot(0, self._start_monitor)

    def _update_totals(self) -> None:
        rules_text = (
            _format_count(len(self._ruleset)) if self._ruleset is not None else "-"
        )
        text = (
            f"Rules {rules_text}  |  Events {_format_count(self._total_events)}  |  "
            f"Matches {_format_count(self._total_matches)}"
        )
        if self._totals_label.text() != text:
            self._totals_label.setText(text)
        tooltip = (
            "Counts include every event seen since this window opened. "
            "The table keeps the most recent "
            f"{_format_count(self._model.max_rows)} events that matched no rule, "
            f"plus up to {_format_count(self._model.max_matched_rows)} matched events "
            "(oldest dropped first)."
        )
        if self._totals_label.toolTip() != tooltip:
            self._totals_label.setToolTip(tooltip)

    # -- details pane ------------------------------------------------------

    @pyqtSlot(QModelIndex, QModelIndex)
    def _current_row_changed(
        self, current: QModelIndex, _previous: QModelIndex
    ) -> None:
        if not current.isValid():
            self._clear_details()
            return
        source_index = self._proxy.mapToSource(current)
        row = self._model.row_at(source_index.row())
        if row is None:
            self._clear_details()
            return
        self._show_details(row)

    def _clear_details(self) -> None:
        self._details_stack.setCurrentIndex(0)
        self._tabs.setTabText(0, "Matched rules")
        self._fields_view.setRowCount(0)
        self._rules_view.clear()
        self._raw_view.clear()
        self._detail_header.setText("Select an event")
        self._detail_meta.clear()

    def _show_details(self, row: LiveEventRow) -> None:
        event = row.event
        self._detail_header.setText(
            f"Event {event.event_id} - {event_type_name(event.event_id)}"
        )
        meta_parts = []
        timestamp = _local_timestamp(event)
        if timestamp:
            meta_parts.append(f"{timestamp} (local)")
        if event.record_id is not None:
            meta_parts.append(f"Record {event.record_id}")
        if event.computer:
            meta_parts.append(event.computer)
        meta_parts.append(event.channel)
        self._detail_meta.setText("  |  ".join(meta_parts))

        self._tabs.setTabText(0, f"Matched rules ({row.match_count})")
        self._rules_view.setHtml(self._rules_html(row))

        self._fields_view.setRowCount(0)
        items = list(event.data.items())
        self._fields_view.setRowCount(len(items))
        for index, (name, value) in enumerate(items):
            name_item = QTableWidgetItem(name)
            value_item = QTableWidgetItem(value)
            value_item.setToolTip(value)
            self._fields_view.setItem(index, 0, name_item)
            self._fields_view.setItem(index, 1, value_item)

        self._raw_view.setPlainText(
            event.raw_xml or render_event_xml(event)
        )
        self._details_stack.setCurrentIndex(1)

    def _rules_html(self, row: LiveEventRow) -> str:
        if not row.rules:
            return (
                "<h3>No Sigma rule matched this event.</h3>"
                "<p>The event is still shown so you can inspect the live Sysmon "
                "telemetry. Rules are evaluated as the event is received.</p>"
            )

        muted = self.palette().color(QPalette.ColorRole.PlaceholderText).name()
        parts = [f"<h3>{len(row.rules)} rule(s) matched this event</h3>"]
        for rule in _rules_by_severity(row.rules):
            level = rule.level.lower()
            color = LEVEL_HTML_COLOR.get(level, "#6b6b6b")
            description = html.escape(rule.description or "No description.")
            tags = ", ".join(html.escape(tag) for tag in rule.tags) or "-"
            references = (
                "<br>".join(
                    html.escape(reference) for reference in rule.references
                )
                or "-"
            )
            category = html.escape(rule_category(rule))
            status = html.escape(rule.status or "unknown")
            parts.append(
                '<div style="margin-bottom:14px;">'
                f'<p style="margin:0 0 3px 0;"><b>{html.escape(rule.title)}</b> '
                f'<span style="color:{color}; font-weight:600;">'
                f"[{html.escape(level.upper())}]</span></p>"
                f'<p style="margin:0; color:{muted};">Rule {html.escape(rule.id)}'
                f"  |  {status}  |  {category}</p>"
                f"<p>{description}</p>"
                f'<p style="margin:0; color:{muted};">Tags: {tags}<br>'
                f"References: {references}<br>"
                f"File: {html.escape(rule.path)}</p>"
                "</div>"
                f'<hr style="border:0; border-top:1px solid {muted};">'
            )
        return "".join(parts)

    # -- shutdown ----------------------------------------------------------

    def _stop_thread(self, thread: QThread | None) -> None:
        if thread is None:
            return
        thread.quit()
        if not thread.wait(4000):
            thread.terminate()
            thread.wait(1000)

    def closeEvent(self, event) -> None:
        if not self._closing:
            self._closing = True
            self._stop_event.set()
            self._flush_timer.stop()
            if self._tray is not None:
                self._tray.hide()
            self._stop_thread(self._monitor_thread)
            self._stop_thread(self._loader_thread)
            self._monitor_worker = None
            self._monitor_thread = None
            self._loader_worker = None
            self._loader_thread = None
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Application startup and elevation
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _elevation_command(argv: Sequence[str]) -> tuple[str, str, str]:
    """Return (executable, parameter string, working directory)."""

    cwd = os.getcwd()
    extra = [*argv, "--elevation-attempted"]
    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(extra), cwd

    launcher = Path(__file__).resolve().parent.parent / "sigmatch_gui.py"
    if launcher.is_file():
        return (
            sys.executable,
            subprocess.list2cmdline([str(launcher), *extra]),
            cwd,
        )
    return (
        sys.executable,
        subprocess.list2cmdline(["-m", "sigmatch.gui", *extra]),
        cwd,
    )


def _shell_execute_runas(
    executable: str, parameters: str, cwd: str
) -> tuple[int, int]:
    """Start *executable* elevated and return (ShellExecute result, last error)."""

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    ctypes.set_last_error(0)
    result = shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        parameters,
        cwd,
        1,  # SW_SHOWNORMAL
    )
    return int(result or 0), ctypes.get_last_error()


def _native_message(text: str, *, title: str = "sigmatch", error: bool = True) -> None:
    icon = 0x10 if error else 0x40  # MB_ICONERROR / MB_ICONINFORMATION
    flags = icon | 0x00040000 | 0x00010000  # MB_TOPMOST | MB_SETFOREGROUND
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, flags)
    except Exception:
        if sys.stderr is not None:
            print(f"{title}: {text}", file=sys.stderr)


def _elevate_self(argv: Sequence[str]) -> bool:
    executable, parameters, cwd = _elevation_command(argv)
    try:
        result, winerror = _shell_execute_runas(executable, parameters, cwd)
    except Exception as exc:
        _native_message(
            "sigmatch could not request administrator rights.\n\n"
            "Start it from an elevated Command Prompt instead. "
            f"Windows reported: {type(exc).__name__}: {exc}"
        )
        return False

    if result > 32:
        return True

    if result == 1223 or winerror == 1223:
        reason = "The elevation request was cancelled."
    elif result == 5 or winerror == 5:
        reason = "Windows denied the elevation request."
    elif result in {2, 3} or winerror in {2, 3}:
        reason = "The Python executable or launcher could not be found."
    else:
        reason = f"Windows returned ShellExecute error {result} (system error {winerror})."
    _native_message(
        "sigmatch must run as administrator to read the Sysmon event log, "
        "but it could not start an elevated copy.\n\n"
        f"{reason}\n\n"
        "Launch sigmatch from an elevated Command Prompt, or try again and "
        "choose Yes in the User Account Control prompt."
    )
    return False


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigmatch-gui",
        description="Live Sysmon event viewer and Sigma matcher.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sigmatch {__version__}",
    )
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
        help="Also load the emerging-threats, threat-hunting, compliance and DFIR collections.",
    )
    parser.add_argument(
        "--no-elevate",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--elevation-attempted",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def _flatten_rule_paths(
    values: Sequence[Sequence[str]] | None,
) -> list[str]:
    if not values:
        return []
    return [item for group in values for item in group]


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_argument_parser().parse_args(argv)

    if sys.platform == "win32" and not args.no_elevate and not is_admin():
        if args.elevation_attempted:
            _native_message(
                "sigmatch is still not running with administrator rights. "
                "The Sysmon event log cannot be read without them.\n\n"
                "Close this message, then start sigmatch again from an elevated "
                "Command Prompt, or accept the User Account Control prompt."
            )
            return 4
        if _elevate_self(argv):
            return 0
        return 3

    if sys.platform == "win32":
        try:
            # Without an explicit app id Windows labels tray notifications as
            # "Python" instead of "sigmatch".
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "sigmatch"
            )
        except Exception:
            pass

    app = QApplication([sys.argv[0] if sys.argv else "sigmatch-gui"])
    app_icon = load_application_icon()
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)
    app.setApplicationName("sigmatch")
    app.setApplicationDisplayName("sigmatch")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("sigmatch")
    style_name = choose_style_name()
    if style_name is not None:
        app.setStyle(style_name)

    rule_paths = _flatten_rule_paths(args.rules)
    if not rule_paths:
        rule_paths = [str(path) for path in default_rule_paths()]

    window = MainWindow(
        rule_paths,
        all_rule_sets=args.all_rule_sets,
    )
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
