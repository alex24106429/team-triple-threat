"""Sigma value / detection-item matching primitives.

The implementation intentionally follows the Sigma specification rather than
Sysmon's own XML filter syntax:

* string matching is case-insensitive by default (``|cased`` opts out),
* ``*`` and ``?`` are wildcards unless escaped with ``\\``,
* ``|re`` regular expressions are case-sensitive unless combined with ``|i``,
* a list of values is OR-linked unless the ``|all`` modifier is present.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
from functools import lru_cache
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


class RuleCompileError(Exception):
    """Raised when a rule (or one of its selections) cannot be compiled."""


# ---------------------------------------------------------------------------
# Sigma string handling
# ---------------------------------------------------------------------------

_ESCAPABLE = {"*", "?", "\\"}
_DASH_VARIANTS = "[-/\u2013\u2014\u2015]"


def _expand_env_vars(value: str) -> str:
    """Expand %VAR% / %%VAR%% placeholders (used by the |expand modifier)."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) if match.group(1) is not None else match.group(2)
        return os.environ.get(name, match.group(0))

    return re.sub(r"%%([^%]+)%%|%([^%]+)%", replace, value)


def _windash_positions(value: str) -> set[int]:
    """Positions where Sigma's windash modifier expands '-' or '/'."""

    return {m.start() for m in re.finditer(r"\B[-/]\b", value)}


def compile_sigma_string(
    value: str,
    *,
    mode: str = "equals",
    case_sensitive: bool = False,
    windash: bool = False,
    expand_env: bool = False,
) -> re.Pattern[str]:
    """Compile a Sigma string (with wildcards) into a Python regex."""

    if expand_env:
        value = _expand_env_vars(value)

    dash_positions = _windash_positions(value) if windash else set()
    parts: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\":
            if i + 1 < len(value) and value[i + 1] in _ESCAPABLE:
                parts.append(re.escape(value[i + 1]))
                i += 2
            else:
                # Sigma treats a backslash not followed by a special character
                # as a literal backslash (important for Windows paths).
                parts.append(re.escape("\\"))
                i += 1
        elif char == "*":
            parts.append(".*")
            i += 1
        elif char == "?":
            parts.append(".")
            i += 1
        else:
            if i in dash_positions:
                parts.append(_DASH_VARIANTS)
            else:
                parts.append(re.escape(char))
            i += 1

    body = "".join(parts)
    if mode == "contains":
        pattern = body
    elif mode == "startswith":
        pattern = "^" + body
    elif mode == "endswith":
        pattern = body + r"\Z"
    elif mode == "equals":
        pattern = r"\A" + body + r"\Z"
    else:  # pragma: no cover - guarded by callers
        raise RuleCompileError(f"unknown string match mode: {mode}")

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error as exc:  # pragma: no cover - normally caught earlier
        raise RuleCompileError(f"invalid Sigma string pattern {value!r}: {exc}") from exc


def sigma_literal(value: str) -> str:
    """Return the literal bytes/text represented by a Sigma string.

    Wildcards are not allowed because this is used by the base64 modifiers.
    """

    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\":
            if i + 1 < len(value) and value[i + 1] in _ESCAPABLE:
                out.append(value[i + 1])
                i += 2
            else:
                out.append("\\")
                i += 1
        elif char in {"*", "?"}:
            raise RuleCompileError(f"wildcards are not allowed in base64 value {value!r}")
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _utf16_transform(value: str, modifier: str) -> str:
    """Approximate pySigma's UTF-16 modifiers.

    Sysmon normally logs UTF-16 command lines as ordinary text, so matching a
    wide-encoded value is mostly useful for base64-encoded PowerShell content.
    """

    if modifier in {"utf16", "utf16le", "wide"}:
        raw = value.encode("utf-16le")
        if modifier == "utf16":
            raw = b"\xff\xfe" + raw
        return raw.decode("latin-1")
    if modifier == "utf16be":
        return value.encode("utf-16be").decode("latin-1")
    raise RuleCompileError(f"unknown utf16 modifier: {modifier}")


def _base64_value(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _base64offset_values(value: str) -> list[str]:
    """Reproduce pySigma's SigmaBase64OffsetModifier expansion exactly."""

    data = value.encode("utf-8")
    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)
    results: list[str] = []
    for index in range(3):
        encoded = base64.b64encode(b" " * index + data).decode("ascii")
        start = start_offsets[index]
        end = end_offsets[(len(data) + index) % 3]
        results.append(encoded[start:end])
    return results


# ---------------------------------------------------------------------------
# Value matchers
# ---------------------------------------------------------------------------


class ValueMatcher:
    """Base class for one value of one field."""

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class RegexValueMatcher(ValueMatcher):
    patterns: tuple[re.Pattern[str], ...]
    all_patterns: bool = False

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        if value is None:
            return False
        if not self.patterns:
            return False
        if self.all_patterns:
            return all(p.search(value) for p in self.patterns)
        return any(p.search(value) for p in self.patterns)


@lru_cache(maxsize=1024)
def _literal_fallback_pattern(source: str, mode: str) -> re.Pattern[str]:
    """Compile the regex equivalent of a literal fast-path matcher.

    It is only needed for rare non-ASCII event values, where Python's
    ``str.lower()`` and ``re.IGNORECASE`` can disagree (for example the long
    s or dotless i).  ASCII values use the much cheaper string operations.
    """

    return compile_sigma_string(source, mode=mode, case_sensitive=False)


@dataclass(frozen=True)
class LiteralValueMatcher(ValueMatcher):
    """Fast path for Sigma values without wildcards or value transforms.

    Almost every value in the SigmaHQ Windows rule set is a plain literal.
    Matching those with ``str`` operations avoids compiling (and later
    pickling/unpickling) tens of thousands of regular expressions.  Values
    that use wildcards, ``|windash`` or non-ASCII text still take the regex
    path, as does a non-ASCII event value for case-insensitive matching so the
    exact ``re.IGNORECASE`` behaviour is preserved.
    """

    text: str
    mode: str
    case_sensitive: bool = False
    source: str = ""

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        if value is None:
            return False
        if not self.case_sensitive and not value.isascii():
            pattern = _literal_fallback_pattern(self.source or self.text, self.mode)
            return bool(pattern.search(value))
        if self.case_sensitive:
            needle = self.text
        else:
            needle = self.text.lower()
            value = value.lower()
        if self.mode == "contains":
            return needle in value
        if self.mode == "startswith":
            return value.startswith(needle)
        if self.mode == "endswith":
            return value.endswith(needle)
        return value == needle


@dataclass(frozen=True)
class NullValueMatcher(ValueMatcher):
    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        # Sigma's null value means "field absent/null".  Sysmon frequently
        # writes empty elements for values it could not obtain, so treat an
        # empty string as null as well.
        return (not present) or value is None or value == ""


@dataclass(frozen=True)
class ExistsValueMatcher(ValueMatcher):
    expected: bool

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        return present == self.expected


@dataclass(frozen=True)
class CidrValueMatcher(ValueMatcher):
    networks: tuple[ipaddress._BaseNetwork, ...]

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        if not value:
            return False
        candidate = value.strip().strip("[]")
        # Sysmon can log IPv6 with a scope/zone suffix.
        candidate = candidate.split("%", 1)[0]
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return any(address in network for network in self.networks)


@dataclass(frozen=True)
class FieldRefValueMatcher(ValueMatcher):
    other_field: str

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        if not present or value is None:
            return False
        other = fields.get(self.other_field)
        if other is None:
            return False
        return value.casefold() == other.casefold()


@dataclass(frozen=True)
class CompareValueMatcher(ValueMatcher):
    op: str
    number: float

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        if value is None:
            return False
        try:
            actual = float(value)
        except (TypeError, ValueError):
            return False
        if self.op == "lt":
            return actual < self.number
        if self.op == "lte":
            return actual <= self.number
        if self.op == "gt":
            return actual > self.number
        if self.op == "gte":
            return actual >= self.number
        return False


@dataclass(frozen=True)
class FieldMatcher:
    """Matches one field (and its list of values) in an event."""

    field: str
    values: tuple[ValueMatcher, ...]
    require_all: bool = False

    def matches(self, fields: Mapping[str, str]) -> bool:
        present = self.field in fields
        value = fields.get(self.field)
        if not self.values:
            return False
        if self.require_all:
            return all(v.matches(value, fields, present) for v in self.values)
        return any(v.matches(value, fields, present) for v in self.values)


@dataclass(frozen=True)
class KeywordMatcher:
    patterns: tuple[re.Pattern[str], ...]

    def matches(self, fields: Mapping[str, str]) -> bool:
        if not self.patterns:
            return False
        for value in fields.values():
            if not isinstance(value, str):
                value = str(value)
            for pattern in self.patterns:
                if pattern.search(value):
                    return True
        return False


@dataclass(frozen=True)
class Selection:
    """A Sigma detection item.

    A detection item is an OR across list entries / keyword alternatives and an
    AND across fields inside one mapping.
    """

    field_matchers: tuple[FieldMatcher, ...] = ()
    keyword_matcher: KeywordMatcher | None = None

    def matches(self, fields: Mapping[str, str]) -> bool:
        if self.keyword_matcher is not None:
            return self.keyword_matcher.matches(fields)
        if not self.field_matchers:
            return False
        return all(matcher.matches(fields) for matcher in self.field_matchers)


# ---------------------------------------------------------------------------
# Modifier handling / compilation
# ---------------------------------------------------------------------------

_MODE_MODIFIERS = {"contains", "startswith", "endswith"}
_COMPARE_MODIFIERS = {"lt", "lte", "gt", "gte"}
_KNOWN_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "regex",
    "all",
    "i",
    "m",
    "s",
    "cased",
    "windash",
    "cidr",
    "base64",
    "base64offset",
    "utf16",
    "utf16le",
    "utf16be",
    "wide",
    "fieldref",
    "exists",
    "lt",
    "lte",
    "gt",
    "gte",
    "expand",
    "negate",
}


def _normalise_modifier(modifier: str) -> str:
    modifier = modifier.strip().lower()
    if modifier == "regex":
        return "re"
    return modifier


def _scalar_to_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _literal_sigma_string(value: str, *, windash: bool) -> str | None:
    """Return the literal represented by a Sigma string, or None if complex.

    The fast literal path is only used for ASCII strings without wildcards,
    ``|windash`` expansion or other modifiers that alter the value's meaning.
    The unescaping rules mirror :func:`compile_sigma_string`.
    """

    if windash or not value.isascii():
        return None
    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\":
            if i + 1 < len(value) and value[i + 1] in _ESCAPABLE:
                out.append(value[i + 1])
                i += 2
            else:
                out.append("\\")
                i += 1
        elif char in {"*", "?"}:
            return None
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _compile_regex_values(
    value: str,
    *,
    mode: str,
    case_sensitive: bool,
    windash: bool,
    expand_env: bool,
) -> tuple[re.Pattern[str], ...]:
    return (
        compile_sigma_string(
            value,
            mode=mode,
            case_sensitive=case_sensitive,
            windash=windash,
            expand_env=expand_env,
        ),
    )


def compile_value(field: str, raw_value: Any, modifiers: Sequence[str]) -> ValueMatcher:
    """Compile one Sigma value (a scalar) into a ValueMatcher."""

    mods = [_normalise_modifier(m) for m in modifiers]
    unknown = [m for m in mods if m not in _KNOWN_MODIFIERS]
    if unknown:
        raise RuleCompileError(f"unsupported Sigma modifier(s): {', '.join(unknown)}")

    mods = [m for m in mods if m != "all"]

    # |negate is a newer Sigma modifier.  It is not used by the current
    # SigmaHQ Windows rules, but supporting it here is trivial and avoids
    # silently loading a rule with the wrong semantics.
    negate = "negate" in mods
    mods = [m for m in mods if m != "negate"]

    if "exists" in mods:
        expected = bool(raw_value)
        matcher: ValueMatcher = ExistsValueMatcher(expected)
        return _maybe_negate(matcher, negate)

    if raw_value is None:
        return _maybe_negate(NullValueMatcher(), negate)

    if "fieldref" in mods:
        other = str(raw_value).strip()
        if not other:
            raise RuleCompileError(f"empty field reference for field {field!r}")
        return _maybe_negate(FieldRefValueMatcher(other.lower()), negate)

    if "cidr" in mods:
        try:
            network = ipaddress.ip_network(str(raw_value).strip(), strict=False)
        except ValueError as exc:
            raise RuleCompileError(f"invalid CIDR {raw_value!r} for field {field!r}: {exc}") from exc
        return _maybe_negate(CidrValueMatcher((network,)), negate)

    compare = [m for m in mods if m in _COMPARE_MODIFIERS]
    if compare:
        if len(compare) > 1:
            raise RuleCompileError(f"multiple comparison modifiers on field {field!r}")
        try:
            number = float(raw_value)
        except (TypeError, ValueError) as exc:
            raise RuleCompileError(f"invalid numeric comparison value {raw_value!r}") from exc
        return _maybe_negate(CompareValueMatcher(compare[0], number), negate)

    mode_mods = [m for m in mods if m in _MODE_MODIFIERS]
    if len(mode_mods) > 1:
        raise RuleCompileError(f"multiple match modes on field {field!r}: {mode_mods}")
    mode = mode_mods[0] if mode_mods else "equals"

    if "re" in mods:
        if any(m in {"base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "cidr", "fieldref"} for m in mods):
            raise RuleCompileError(f"|re cannot be combined with this modifier on field {field!r}")
        if "windash" in mods:
            raise RuleCompileError(f"|re|windash is not supported (field {field!r})")
        flags = 0
        if "i" in mods:
            flags |= re.IGNORECASE
        if "m" in mods:
            flags |= re.MULTILINE
        if "s" in mods:
            flags |= re.DOTALL
        try:
            pattern = re.compile(str(raw_value), flags)
        except re.error as exc:
            raise RuleCompileError(f"invalid regular expression {raw_value!r}: {exc}") from exc
        return _maybe_negate(RegexValueMatcher((pattern,)), negate)

    case_sensitive = "cased" in mods
    windash = "windash" in mods
    expand_env = "expand" in mods

    text = _scalar_to_text(raw_value)

    if "utf16" in mods or "utf16le" in mods or "utf16be" in mods or "wide" in mods:
        utf_modifier = next(m for m in mods if m in {"utf16", "utf16le", "utf16be", "wide"})
        text = _utf16_transform(text, utf_modifier)

    if "base64" in mods or "base64offset" in mods:
        literal = sigma_literal(text)
        if "base64offset" in mods:
            encoded_values = _base64offset_values(literal)
            # Each offset is an alternative; |all applies to the original list
            # values, not to the offset expansion.
            patterns = tuple(
                compile_sigma_string(
                    encoded,
                    mode=mode,
                    case_sensitive=True,
                    windash=False,
                    expand_env=False,
                )
                for encoded in encoded_values
            )
            return _maybe_negate(RegexValueMatcher(patterns, all_patterns=False), negate)
        encoded = _base64_value(literal)
        patterns = _compile_regex_values(
            encoded,
            mode=mode,
            case_sensitive=True,
            windash=False,
            expand_env=False,
        )
        return _maybe_negate(RegexValueMatcher(patterns), negate)

    literal_text = _expand_env_vars(text) if expand_env else text
    literal = _literal_sigma_string(literal_text, windash=windash)
    if literal is not None:
        return _maybe_negate(
            LiteralValueMatcher(literal, mode, case_sensitive, literal_text), negate
        )

    patterns = _compile_regex_values(
        text,
        mode=mode,
        case_sensitive=case_sensitive,
        windash=windash,
        expand_env=expand_env,
    )
    return _maybe_negate(RegexValueMatcher(patterns), negate)


@dataclass(frozen=True)
class NegatedValueMatcher(ValueMatcher):
    inner: ValueMatcher

    def matches(self, value: str | None, fields: Mapping[str, str], present: bool) -> bool:
        return not self.inner.matches(value, fields, present)


def _maybe_negate(matcher: ValueMatcher, negate: bool) -> ValueMatcher:
    return NegatedValueMatcher(matcher) if negate else matcher


def _compile_keyword_matcher(value: Any, modifiers: Sequence[str]) -> KeywordMatcher:
    mods = [_normalise_modifier(m) for m in modifiers]
    unknown = [m for m in mods if m not in _KNOWN_MODIFIERS and m not in {"all"}]
    if unknown:
        raise RuleCompileError(f"unsupported keyword modifier(s): {', '.join(unknown)}")
    if "re" in mods:
        flags = re.IGNORECASE if "i" in mods else 0
        try:
            pattern = re.compile(str(value), flags)
        except re.error as exc:
            raise RuleCompileError(f"invalid keyword regular expression {value!r}: {exc}") from exc
        return KeywordMatcher((pattern,))
    # Sigma keyword items are substring searches.
    pattern = compile_sigma_string(
        str(value),
        mode="contains",
        case_sensitive="cased" in mods,
        windash="windash" in mods,
        expand_env="expand" in mods,
    )
    return KeywordMatcher((pattern,))


def _compile_mapping_selection(value: Mapping[str, Any]) -> Selection:
    matchers = tuple(_compile_field_entry(key, item) for key, item in value.items())
    return Selection(field_matchers=matchers)


@dataclass(frozen=True)
class SelectionGroup:
    """OR of one or more Selection alternatives."""

    alternatives: tuple[Selection, ...]

    def matches(self, fields: Mapping[str, str]) -> bool:
        return any(alt.matches(fields) for alt in self.alternatives)


def compile_detection_item(name: str, value: Any) -> SelectionGroup:
    """Compile a detection item, including OR-lists of mappings."""

    if isinstance(value, list):
        if not value:
            return SelectionGroup((Selection(),))
        if all(isinstance(item, dict) for item in value):
            return SelectionGroup(
                tuple(_compile_mapping_selection(item) for item in value)
            )
        if any(isinstance(item, dict) for item in value):
            alternatives: list[Selection] = []
            for item in value:
                if isinstance(item, dict):
                    alternatives.append(_compile_mapping_selection(item))
                elif isinstance(item, (str, int, bool)):
                    alternatives.append(
                        Selection(keyword_matcher=_compile_keyword_matcher(item, ()))
                    )
                else:
                    raise RuleCompileError(
                        f"selection {name!r} contains unsupported values"
                    )
            return SelectionGroup(tuple(alternatives))

        if not all(isinstance(item, (str, int, bool)) for item in value):
            raise RuleCompileError(f"selection {name!r} contains unsupported values")
        # A list of scalars is a keyword selection whose entries are OR-linked.
        patterns: list[re.Pattern[str]] = []
        for item in value:
            patterns.extend(_compile_keyword_matcher(item, ()).patterns)
        return SelectionGroup(
            (Selection(keyword_matcher=KeywordMatcher(tuple(patterns))),)
        )

    if isinstance(value, dict):
        return SelectionGroup((_compile_mapping_selection(value),))
    if isinstance(value, (str, int, bool)):
        return SelectionGroup(
            (Selection(keyword_matcher=_compile_keyword_matcher(value, ())),)
        )
    raise RuleCompileError(
        f"selection {name!r} has unsupported type {type(value).__name__}"
    )


def _compile_field_entry(key: str, raw_value: Any) -> FieldMatcher:
    parts = key.split("|")
    field_name = parts[0].strip().lower()
    modifiers = parts[1:]

    if not field_name:
        # A bare modified keyword, e.g. ``|contains: foo``.  It is unusual but
        # easy to support as a keyword selection rather than failing the rule.
        # FieldMatcher cannot represent that, so signal it explicitly.
        raise RuleCompileError("keyword entries must be expressed as a string list")

    if isinstance(raw_value, dict):
        raise RuleCompileError(f"nested mapping is not valid in Sigma field {key!r}")

    values = raw_value if isinstance(raw_value, list) else [raw_value]
    if not values:
        # An empty value list matches nothing.
        return FieldMatcher(field_name, ())

    compiled = tuple(compile_value(field_name, item, modifiers) for item in values)
    return FieldMatcher(field_name, compiled, require_all="all" in [m.strip().lower() for m in modifiers])


# ---------------------------------------------------------------------------
# Public helpers used by tests and the CLI
# ---------------------------------------------------------------------------


def match_sigma_string(
    value: str,
    pattern: str,
    *,
    mode: str = "equals",
    case_sensitive: bool = False,
    windash: bool = False,
) -> bool:
    """Convenience wrapper used by unit tests."""

    return bool(
        compile_sigma_string(
            pattern,
            mode=mode,
            case_sensitive=case_sensitive,
            windash=windash,
        ).search(value)
    )

