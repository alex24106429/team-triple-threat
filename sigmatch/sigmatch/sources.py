"""Live Sysmon event source (ETW).

Live events come from the Sysmon ETW provider (pyetwkit).  The EventLog
service publishes channel records in batches (hundreds of milliseconds),
while ETW delivers them as Sysmon writes them (~13 ms measured).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Iterator

from .bootstrap import (
    BootstrapError,
    ensure_pyetwkit,
    ensure_sysmon,
)
from .events import (
    SYSMON_CHANNEL,
    SYSMON_PROVIDER,
    SysmonEvent,
    event_from_etw,
)


class SourceError(Exception):
    """Raised when an event source cannot be opened or read."""


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
        stop_event: threading.Event | None = None,
        duration: float | None = None,
        poll_interval: float = ETW_POLL_INTERVAL,
        session_name: str | None = None,
    ) -> None:
        self._channel = channel
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
