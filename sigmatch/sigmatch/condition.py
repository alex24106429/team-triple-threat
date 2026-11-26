"""Parser and evaluator for Sigma rule conditions.

Supported syntax (the subset used by SigmaHQ's Windows rule set)::

    selection
    selection and not filter
    selection1 or (selection2 and not filter)
    1 of selection_*
    any of selection_*
    all of selection_*
    1 of them
    all of them

Aggregation expressions (``... | count() > 5``) are intentionally rejected:
they require state across events and are not present in the SigmaHQ Windows
Sysmon rule set.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Mapping, Sequence

from .matchers import RuleCompileError, SelectionGroup


class ConditionNode:
    def evaluate(
        self,
        fields: Mapping[str, str],
        selections: Mapping[str, SelectionGroup],
        cache: dict[str, bool],
    ) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class IdentNode(ConditionNode):
    name: str

    def evaluate(self, fields, selections, cache) -> bool:
        if self.name not in cache:
            cache[self.name] = selections[self.name].matches(fields)
        return cache[self.name]


@dataclass(frozen=True)
class NotNode(ConditionNode):
    child: ConditionNode

    def evaluate(self, fields, selections, cache) -> bool:
        return not self.child.evaluate(fields, selections, cache)


@dataclass(frozen=True)
class AndNode(ConditionNode):
    left: ConditionNode
    right: ConditionNode

    def evaluate(self, fields, selections, cache) -> bool:
        return self.left.evaluate(fields, selections, cache) and self.right.evaluate(
            fields, selections, cache
        )


@dataclass(frozen=True)
class OrNode(ConditionNode):
    left: ConditionNode
    right: ConditionNode

    def evaluate(self, fields, selections, cache) -> bool:
        return self.left.evaluate(fields, selections, cache) or self.right.evaluate(
            fields, selections, cache
        )


@dataclass(frozen=True)
class OfNode(ConditionNode):
    names: tuple[str, ...]
    threshold: int

    def evaluate(self, fields, selections, cache) -> bool:
        if self.threshold <= 0:
            return True
        if self.threshold > len(self.names):
            return False
        matched = 0
        for name in self.names:
            if name not in cache:
                cache[name] = selections[name].matches(fields)
            if cache[name]:
                matched += 1
                if matched >= self.threshold:
                    return True
        return False


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    pos: int


def _tokenize(condition: str) -> list[_Token]:
    if "|" in condition:
        raise RuleCompileError("aggregation conditions ('| count(...)') are not supported")
    tokens: list[_Token] = []
    index = 0
    length = len(condition)
    while index < length:
        char = condition[index]
        if char.isspace():
            index += 1
            continue
        if char == "(":
            tokens.append(_Token("LPAREN", char, index))
            index += 1
            continue
        if char == ")":
            tokens.append(_Token("RPAREN", char, index))
            index += 1
            continue
        start = index
        while index < length and not condition[index].isspace() and condition[index] not in "()":
            index += 1
        word = condition[start:index]
        if not word:
            raise RuleCompileError(f"unexpected character in condition at {start}: {condition[start]!r}")
        if word.isdigit():
            tokens.append(_Token("NUMBER", word, start))
        else:
            tokens.append(_Token("IDENT", word, start))
    tokens.append(_Token("EOF", "", length))
    return tokens


class _ConditionParser:
    def __init__(self, condition: str, selection_names: Sequence[str]) -> None:
        self.condition = condition
        self.selection_names = tuple(selection_names)
        self.tokens = _tokenize(condition)
        self.index = 0

    def peek(self, offset: int = 0) -> _Token:
        return self.tokens[min(self.index + offset, len(self.tokens) - 1)]

    def advance(self) -> _Token:
        token = self.peek()
        self.index += 1
        return token

    def accept_word(self, word: str) -> bool:
        token = self.peek()
        if token.kind == "IDENT" and token.text.lower() == word:
            self.index += 1
            return True
        return False

    def expect_word(self, word: str) -> None:
        if not self.accept_word(word):
            token = self.peek()
            raise RuleCompileError(
                f"expected {word!r} in condition at position {token.pos}: {self.condition!r}"
            )

    def parse(self) -> ConditionNode:
        node = self.parse_or()
        if self.peek().kind != "EOF":
            token = self.peek()
            raise RuleCompileError(
                f"unexpected token {token.text!r} in condition at position {token.pos}: {self.condition!r}"
            )
        return node

    def parse_or(self) -> ConditionNode:
        node = self.parse_and()
        while self.accept_word("or"):
            node = OrNode(node, self.parse_and())
        return node

    def parse_and(self) -> ConditionNode:
        node = self.parse_unary()
        while self.accept_word("and"):
            node = AndNode(node, self.parse_unary())
        return node

    def parse_unary(self) -> ConditionNode:
        if self.accept_word("not"):
            return NotNode(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> ConditionNode:
        token = self.peek()
        if token.kind == "LPAREN":
            self.advance()
            node = self.parse_or()
            if self.peek().kind != "RPAREN":
                raise RuleCompileError(
                    f"missing ')' in condition at position {self.peek().pos}: {self.condition!r}"
                )
            self.advance()
            return node

        if token.kind == "NUMBER":
            number = int(self.advance().text)
            self.expect_word("of")
            target = self.peek()
            if target.kind != "IDENT":
                raise RuleCompileError(
                    f"expected selection pattern after 'of' at position {target.pos}: {self.condition!r}"
                )
            self.advance()
            return self._make_of_node(number, target.text)

        if token.kind == "IDENT":
            lowered = token.text.lower()
            if lowered in {"all", "any"} and self.peek(1).kind == "IDENT" and self.peek(1).text.lower() == "of":
                self.advance()  # all/any
                self.expect_word("of")
                target = self.peek()
                if target.kind != "IDENT":
                    raise RuleCompileError(
                        f"expected selection pattern after 'of' at position {target.pos}: {self.condition!r}"
                    )
                self.advance()
                threshold = "all" if lowered == "all" else 1
                return self._make_of_node(threshold, target.text)

            if lowered == "of":
                raise RuleCompileError(
                    f"unexpected 'of' in condition at position {token.pos}: {self.condition!r}"
                )
            self.advance()
            if token.text not in self.selection_names:
                raise RuleCompileError(
                    f"condition references unknown selection {token.text!r} "
                    f"(available: {', '.join(self.selection_names)})"
                )
            return IdentNode(token.text)

        raise RuleCompileError(
            f"unexpected token {token.text!r} in condition at position {token.pos}: {self.condition!r}"
        )

    def _make_of_node(self, threshold: int | str, pattern: str) -> ConditionNode:
        if isinstance(threshold, int) and threshold <= 0:
            raise RuleCompileError(f"invalid 'of' threshold {threshold} in condition: {self.condition!r}")
        if pattern.lower() == "them":
            names = self.selection_names
        else:
            names = tuple(
                name for name in self.selection_names if fnmatch.fnmatchcase(name, pattern)
            )
        if not names:
            raise RuleCompileError(
                f"condition pattern {pattern!r} did not match any detection items "
                f"(available: {', '.join(self.selection_names)})"
            )
        if threshold == "all":
            threshold = len(names)
        return OfNode(names, threshold)


def compile_condition(
    condition: str | Sequence[str],
    selection_names: Sequence[str],
) -> ConditionNode:
    """Compile a Sigma condition (string or list of alternatives) to an AST."""

    if isinstance(condition, (list, tuple)):
        if not condition:
            raise RuleCompileError("empty condition list")
        nodes = [
            _ConditionParser(str(item).strip(), selection_names).parse() for item in condition
        ]
        node = nodes[0]
        for other in nodes[1:]:
            node = OrNode(node, other)
        return node

    if not isinstance(condition, str) or not condition.strip():
        raise RuleCompileError("missing or empty condition")
    return _ConditionParser(condition.strip(), selection_names).parse()
