"""Sysmon ETW event normalisation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


@dataclass
class SysmonEvent:
    event_id: int
    data: dict[str, str] = field(default_factory=dict)
    record_id: int | None = None
    timestamp: datetime | None = None
    channel: str = SYSMON_CHANNEL
    provider: str = SYSMON_PROVIDER
    computer: str = ""
    raw_xml: str | None = None
    lookup: dict[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.lookup = {key.lower(): value for key, value in self.data.items()}

    def get(self, name: str) -> str | None:
        return self.lookup.get(name.lower())

    def has(self, name: str) -> bool:
        return name.lower() in self.lookup

    def add_field(self, name: str, value: Any, overwrite: bool = False) -> None:
        if not overwrite and self.has(name):
            return
        text = _as_text(value)
        self.data[name] = text
        self.lookup[name.lower()] = text

    def to_output(self) -> dict[str, Any]:
        return {
            "EventID": self.event_id,
            "EventRecordID": self.record_id,
            "UtcTime": self.timestamp.isoformat() if self.timestamp else self.get("UtcTime"),
            "Channel": self.channel,
            "Provider": self.provider,
            "Computer": self.computer,
            "Data": self.data,
        }


# ---------------------------------------------------------------------------
# Sysmon ETW events
#
# Sysmon's manifest-based ETW provider exposes the same EventData values as the
# XML written to Microsoft-Windows-Sysmon/Operational, but TDH decodes them
# using the manifest types.  Two normalisations keep Sigma rules (written
# against the XML form) matching identically:
#
# * ``GrantedAccess`` and ``LogonId`` arrive as integers but the XML has them
#   as lowercase hex (``0x1410``, ``0x586e7``).
# * GUIDs arrive without the braces the XML uses (``{...}``).
# ---------------------------------------------------------------------------

_ETW_HEX_FIELDS = frozenset({"grantedaccess", "logonid"})

_BARE_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Fields sigmatch synthesises for the EventLog XML form.  Rendered XML recreates
# them from the SysmonEvent instead of emitting them as EventData.
SYNTHETIC_FIELDS = frozenset(
    {
        "EventID",
        "EventRecordID",
        "Channel",
        "Provider_Name",
        "ProviderName",
        "Computer",
        "TimeCreated",
        "Security_UserID",
    }
)


def normalize_etw_value(name: str, value: Any) -> str:
    """Convert one TDH-decoded ETW property into the EventLog XML string form."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if name.casefold() in _ETW_HEX_FIELDS:
            return f"0x{value:x}"
        return str(value)
    text = _as_text(value)
    if _BARE_GUID.match(text):
        return "{" + text + "}"
    return text


def event_from_etw(
    event_id: int,
    properties: Mapping[str, Any],
    timestamp: datetime | None,
    *,
    channel: str = SYSMON_CHANNEL,
    provider: str = SYSMON_PROVIDER,
    computer: str = "",
) -> SysmonEvent:
    """Build a :class:`SysmonEvent` from TDH-decoded Sysmon ETW properties.

    The result mirrors the EventLog XML representation for the same event,
    except that there is no ``EventRecordID`` (assigned by the EventLog service,
    not ETW) and no ``Security_UserID`` (not part of the ETW payload).  No
    SigmaHQ rule in the shipped collections references either field.
    """

    data = {
        str(name): normalize_etw_value(str(name), value)
        for name, value in properties.items()
        if value is not None
    }
    event = SysmonEvent(
        event_id=int(event_id),
        data=data,
        record_id=None,
        timestamp=timestamp,
        channel=channel or SYSMON_CHANNEL,
        provider=provider or SYSMON_PROVIDER,
        computer=computer,
        raw_xml=None,
    )
    event.add_field("EventID", event.event_id, overwrite=True)
    event.add_field("Channel", event.channel, overwrite=True)
    event.add_field("Provider_Name", event.provider, overwrite=True)
    event.add_field("ProviderName", event.provider, overwrite=True)
    event.add_field("Computer", event.computer, overwrite=True)
    if timestamp is not None:
        event.add_field("TimeCreated", timestamp.isoformat(), overwrite=True)
        event.add_field(
            "UtcTime",
            timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            overwrite=False,
        )
    return event


def render_event_xml(event: SysmonEvent) -> str:
    """Render a compact EventLog-style XML document for *event*.

    ETW events have no source XML, so the desktop UI reconstructs one from the
    decoded fields (same shape as ``Get-WinEvent -ToXml()``).
    """

    from xml.sax.saxutils import escape, quoteattr

    stamp = ""
    if event.timestamp is not None:
        utc = event.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")
        stamp = f"<TimeCreated SystemTime={quoteattr(utc)}/>"
    record = (
        f"<EventRecordID>{event.record_id}</EventRecordID>"
        if event.record_id is not None
        else ""
    )
    parts = [
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>",
        "<System>",
        f"<Provider Name={quoteattr(event.provider)}/>",
        f"<EventID>{event.event_id}</EventID>",
        record,
        stamp,
        f"<Channel>{escape(event.channel)}</Channel>",
        f"<Computer>{escape(event.computer)}</Computer>",
        "</System>",
        "<EventData>",
    ]
    for name, value in event.data.items():
        if name in SYNTHETIC_FIELDS:
            continue
        parts.append(f"<Data Name={quoteattr(name)}>{escape(value)}</Data>")
    parts += ["</EventData>", "</Event>"]
    return "".join(parts)
