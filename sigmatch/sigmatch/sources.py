"""Event sources: live Sysmon ETW consumption, .evtx files and replay.

Live events come from the Sysmon ETW provider (pyetwkit).  The EventLog
service publishes channel records in batches (hundreds of milliseconds),
while ETW delivers them as Sysmon writes them (~13 ms measured).
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Sequence

from .bootstrap import (
    BootstrapError,
    ensure_pywin32,
    ensure_pyetwkit,
    ensure_sysmon,
)
from .events import (
    SYSMON_CHANNEL,
    SYSMON_PROVIDER,
    SysmonEvent,
    event_from_etw,
    parse_event_any,
)


class SourceError(Exception):
    """Raised when an event source cannot be opened or read."""


def _win32():
    try:
        win32evtlog, _ = ensure_pywin32()
    except BootstrapError as exc:  # pragma: no cover - Windows-only dependency
        raise SourceError(str(exc)) from exc
    return win32evtlog


def _render(event) -> str:
    win32evtlog = _win32()
    rendered = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
    if isinstance(rendered, bytes):
        return rendered.decode("utf-8", errors="replace")
    return rendered


def query_backfill(channel: str, count: int, query: str = "*") -> list[str]:
    """Return up to *count* historical events, oldest first."""

    if count <= 0:
        return []
    win32evtlog = _win32()
    try:
        handle = win32evtlog.EvtQuery(
            channel,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            query,
        )
    except Exception as exc:
        raise SourceError(f"cannot query historical events from {channel!r}: {exc}") from exc
    try:
        events = win32evtlog.EvtNext(handle, count, 0, 0)
    except Exception as exc:
        if _is_no_more_events(exc):
            return []
        raise SourceError(f"cannot read historical events from {channel!r}: {exc}") from exc
    return [_render(event) for event in reversed(tuple(events))]


def _is_no_more_events(exc: Exception) -> bool:
    winerror = getattr(exc, "winerror", None)
    text = str(exc).lower()
    return (
        winerror in {259, 4317}
        or "more items" in text
        or "operation identifier is not valid" in text
        or "no more data" in text
    )


SYSMON_PROVIDER_GUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"

# Sysmon writes its Operational channel events with this keyword.
SYSMON_OPERATIONAL_KEYWORD = 0x8000000000000000
_TRACE_LEVEL_INFORMATION = 4

# pyetwkit's next_event_timeout() does not release the GIL while it waits, so a
# poll of 200 ms blocks every other Python thread for 200 ms.  Polling without
# blocking and sleeping in Python keeps the GIL free (measured: 0.2 ms jitter on
# a 5 ms sleeper thread vs 200 ms with next_event_timeout).
ETW_POLL_INTERVAL = 0.001


def _etw_types():
    try:
        return ensure_pyetwkit()
    except BootstrapError as exc:  # pragma: no cover - Windows-only dependency
        raise SourceError(str(exc)) from exc


class EtwSource:
    """Real-time Sysmon events consumed from the Sysmon ETW provider.

    Runs its own real-time trace session (``StartTraceW`` + ``EnableTraceEx2``
    through pyetwkit) instead of subscribing to the EventLog channel.  ETW
    delivers each event as soon as Sysmon writes it, whereas the EventLog
    service publishes channel records in batches (measured p50 ~250-485 ms,
    tail >1 s on this VM); the ETW path measures p50 ~13 ms end to end.

    ``start()`` and iteration are separate so events can be buffered while
    rules are still being compiled (the Rust consumer thread drains ETW
    independently of Python, so nothing is lost and there is no blind spot).
    """

    def __init__(
        self,
        channel: str = SYSMON_CHANNEL,
        *,
        backfill: int = 0,
        query: str = "*",
        stop_event: threading.Event | None = None,
        duration: float | None = None,
        poll_interval: float = ETW_POLL_INTERVAL,
        session_name: str | None = None,
    ) -> None:
        self._channel = channel
        self._backfill = backfill
        self._query = query
        self._stop_event = stop_event
        self._duration = duration
        self._poll_interval = poll_interval
        self._session_name = session_name
        self._session = None
        self._computer = ""

    # -- lifecycle ---------------------------------------------------------

    def start(self, on_subscribe: Callable[[], None] | None = None) -> None:
        """Create the trace session and enable the Sysmon provider on it."""

        if sys.platform != "win32":
            raise SourceError("live Sysmon events are only available on Windows")
        if self._channel.casefold() != SYSMON_CHANNEL.casefold():
            raise SourceError(
                f"live ETW consumption only supports {SYSMON_CHANNEL!r}, "
                f"not {self._channel!r}"
            )
        try:
            ensure_sysmon(self._channel)
        except BootstrapError as exc:
            raise SourceError(str(exc)) from exc

        etw_session, etw_provider = _etw_types()
        self._computer = os.environ.get("COMPUTERNAME", "")
        failure: Exception | None = None
        for name in self._names():
            session = etw_session(name)
            session.add_provider(
                etw_provider(SYSMON_PROVIDER_GUID, SYSMON_PROVIDER)
                .level(_TRACE_LEVEL_INFORMATION)
                .keywords_any(SYSMON_OPERATIONAL_KEYWORD)
            )
            try:
                session.start()
            except Exception as exc:
                failure = exc
                try:
                    session.stop()
                except Exception:
                    pass
                continue
            self._session = session
            break

        if self._session is None:
            raise SourceError(
                "cannot start the Sysmon ETW trace session "
                f"({type(failure).__name__}: {failure}). Consuming ETW requires an "
                "elevated shell (Run as administrator) and a running Sysmon service."
            )
        if on_subscribe is not None:
            on_subscribe()

    def _names(self) -> Iterator[str]:
        if self._session_name:
            yield self._session_name
            return
        base = f"sigmatch-sysmon-{os.getpid()}"
        yield base
        # A stale session from a previous process with the same pid would make
        # StartTrace fail; fall back to a unique name.
        yield f"{base}-{int(time.time() * 1000) % 100000:05d}"

    def close(self) -> None:
        session, self._session = self._session, None
        if session is None:
            return
        try:
            session.stop()
        except Exception:  # pragma: no cover - defensive
            pass

    def __enter__(self) -> EtwSource:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- events ------------------------------------------------------------

    def __iter__(self) -> Iterator[SysmonEvent]:
        if self._session is None:
            raise SourceError("EtwSource.start() must be called before iterating")

        deadline = time.monotonic() + self._duration if self._duration else None

        if self._backfill:
            try:
                for xml in query_backfill(self._channel, self._backfill, self._query):
                    yield parse_event_any(xml)
            except SourceError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                raise SourceError(f"backfill failed: {exc}") from exc

        while True:
            if self._stop_event is not None and self._stop_event.is_set():
                break
            if deadline is not None and time.monotonic() >= deadline:
                break

            event = self._session.try_next_event()
            if event is None:
                # Non-blocking poll + Python sleep: time.sleep releases the GIL,
                # next_event_timeout holds it for the whole timeout.
                time.sleep(self._poll_interval)
                continue

            yield event_from_etw(
                int(event.event_id),
                getattr(event, "properties", None) or {},
                _etw_timestamp(event),
                channel=self._channel,
                provider=getattr(event, "provider_name", None) or SYSMON_PROVIDER,
                computer=self._computer,
            )


def _etw_timestamp(event) -> datetime | None:
    stamp = getattr(event, "timestamp", None)
    if isinstance(stamp, datetime):
        return stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=timezone.utc)
    nanos = getattr(event, "timestamp_ns", None)
    if nanos:
        return datetime.fromtimestamp(nanos / 1e9, timezone.utc)
    return None


def live_events(
    channel: str = SYSMON_CHANNEL,
    *,
    backfill: int = 0,
    query: str = "*",
    stop_event: threading.Event | None = None,
    duration: float | None = None,
    on_subscribe: Callable[[], None] | None = None,
) -> Iterator[SysmonEvent]:
    """Yield live Sysmon events from the Sysmon ETW provider."""

    source = EtwSource(
        channel,
        backfill=backfill,
        query=query,
        stop_event=stop_event,
        duration=duration,
    )
    try:
        source.start(on_subscribe=on_subscribe)
        yield from source
    finally:
        source.close()


def evtx_events(path: str | Path, query: str = "*") -> Iterator[str]:
    """Yield all events from an .evtx file, oldest first."""

    win32evtlog = _win32()
    try:
        handle = win32evtlog.EvtQuery(str(path), win32evtlog.EvtQueryFilePath, query)
    except Exception as exc:
        raise SourceError(f"cannot open EVTX file {path!r}: {exc}") from exc

    while True:
        try:
            events = win32evtlog.EvtNext(handle, 128, 0, 0)
        except Exception as exc:
            # pywin32 maps ERROR_NO_MORE_ITEMS / ERROR_INVALID_OPERATION from
            # EvtNext to exceptions on some versions.  Both mean EOF here.
            if _is_no_more_events(exc):
                break
            raise SourceError(f"error reading EVTX file {path!r}: {exc}") from exc
        if not events:
            break
        for event in events:
            yield _render(event)


def _iter_json_array(items: Sequence[object]) -> Iterator[str]:
    for item in items:
        if isinstance(item, str):
            yield item
        else:
            yield json.dumps(item, ensure_ascii=False)


def replay_events(
    path: str | Path | None,
    *,
    input_format: str = "auto",
) -> Iterator[str]:
    """Yield raw event documents from a replay file/stdin.

    ``xml`` accepts one or more XML documents (line-oriented or pretty-printed).
    ``json`` accepts a JSON array, a single JSON object, or newline-delimited
    JSON objects.  ``auto`` detects XML vs JSON and JSON arrays vs NDJSON.
    """

    if path is None or str(path) == "-":
        stream = sys.stdin
        should_close = False
    else:
        stream = open(path, "r", encoding="utf-8-sig", errors="replace")
        should_close = True

    try:
        if input_format == "xml":
            content = stream.read()
            # Split on complete </Event> boundaries so pretty-printed XML
            # works as well as the usual one-line Get-WinEvent output.
            for chunk in re.split(r"(?<=</Event>)", content):
                if chunk.strip():
                    yield chunk.strip()
            return

        if input_format in {"json", "jsonl", "ndjson"}:
            content = stream.read()
            stripped = content.lstrip()
            if input_format != "ndjson" and stripped.startswith("["):
                yield from _iter_json_array(json.loads(content))
                return
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line
            return

        # auto: read enough to detect a JSON array, otherwise stream lines.
        first = ""
        while True:
            char = stream.read(1)
            if not char:
                return
            if not char.isspace():
                first = char
                break
        if first == "[":
            yield from _iter_json_array(json.loads(stream.read()))
            return
        if first == "<":
            # XML documents can span lines; Sysmon's ToXml() normally emits a
            # single line, so line-oriented replay is the pragmatic format.
            pending = first
            for line in stream:
                pending += line
                if pending.rstrip().endswith("</Event>"):
                    yield pending.strip()
                    pending = ""
            if pending.strip():
                yield pending.strip()
            return

        # JSON object(s): re-assemble the first character and stream lines.
        line_buffer = first
        for line in stream:
            line_buffer += line
            stripped = line_buffer.strip()
            if stripped and stripped.startswith("{") and _json_complete(stripped):
                yield stripped
                line_buffer = ""
            elif line_buffer.count("\n") > 1 and stripped and not stripped.startswith("{"):
                line_buffer = ""
        if line_buffer.strip():
            yield line_buffer.strip()
    finally:
        if should_close:
            stream.close()


def _json_complete(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False
