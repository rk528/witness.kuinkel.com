"""Decide whether a Sigma rule fires on a single log event.

pySigma parses a rule's condition into a tree of AND/OR/NOT nodes whose leaves compare
one field with one value. This module walks that tree against an event, a flat dict of
field name to value, the way a SIEM would. Sigma string matching is case-insensitive
unless the rule uses the |cased modifier.
"""

from __future__ import annotations

import ipaddress
import operator
import re
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

Event = dict[str, Any]

_MISSING = object()

_COMPARE = {
    SigmaCompareExpression.CompareOperators.LT: operator.lt,
    SigmaCompareExpression.CompareOperators.LTE: operator.le,
    SigmaCompareExpression.CompareOperators.GT: operator.gt,
    SigmaCompareExpression.CompareOperators.GTE: operator.ge,
    SigmaCompareExpression.CompareOperators.NEQ: operator.ne,
}

_REGEX_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
}


class UnsupportedRule(Exception):
    """The rule uses a Sigma feature this evaluator does not implement."""


def matches(rule: SigmaRule, event: Event) -> bool:
    """True if any of the rule's conditions holds for the event."""
    return any(_eval(cond.parsed, event) for cond in rule.detection.parsed_condition)


def _eval(node: Any, event: Event) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _field_matches(event, node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        # A keyword search: the value may appear anywhere in any field.
        return any(_keyword_matches(node.value, v) for v in _all_values(event))
    raise UnsupportedRule(f"condition node {type(node).__name__}")


def _field_matches(event: Event, field: str, value: Any) -> bool:
    actual = _lookup(event, field)
    if isinstance(value, SigmaExists):
        return (actual is not _MISSING) == value.exists
    if actual is _MISSING:
        return isinstance(value, SigmaNull)
    if isinstance(actual, list):
        return any(_value_matches(value, item, event) for item in actual)
    return _value_matches(value, actual, event)


def _lookup(event: Event, field: str) -> Any:
    if field in event:
        return event[field]
    # SIEMs treat field names case-insensitively; so do we, as a fallback.
    lowered = field.lower()
    for key, val in event.items():
        if key.lower() == lowered:
            return val
    return _MISSING


def _all_values(event: Event):
    for val in event.values():
        if isinstance(val, list):
            yield from val
        else:
            yield val


def _value_matches(value: Any, actual: Any, event: Event) -> bool:
    if isinstance(value, SigmaExpansion):
        return any(_value_matches(v, actual, event) for v in value.values)
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    # SigmaCasedString is a SigmaString, so it has to be checked first.
    if isinstance(value, SigmaCasedString):
        return _string_regex(value, case_sensitive=True).fullmatch(str(actual)) is not None
    if isinstance(value, SigmaString):
        return _string_regex(value, case_sensitive=False).fullmatch(str(actual)) is not None
    if isinstance(value, SigmaNumber):
        number = _as_number(actual)
        return number is not None and number == value.number
    if isinstance(value, SigmaBool):
        if isinstance(actual, bool):
            return actual == value.boolean
        return str(actual).lower() == str(value.boolean).lower()
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        for flag in value.flags:
            flags |= _REGEX_FLAGS[flag]
        return re.search(value.regexp.to_plain(), str(actual), flags) is not None
    if isinstance(value, SigmaCompareExpression):
        number = _as_number(actual)
        return number is not None and _COMPARE[value.op](number, value.number.number)
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in value.network
        except ValueError:
            return False
    if isinstance(value, SigmaFieldReference):
        other = _lookup(event, value.field)
        return other is not _MISSING and str(other).lower() == str(actual).lower()
    raise UnsupportedRule(f"value type {type(value).__name__}")


def _keyword_matches(value: Any, actual: Any) -> bool:
    if isinstance(value, SigmaExpansion):
        return any(_keyword_matches(v, actual) for v in value.values)
    if isinstance(value, SigmaString) and actual is not None:
        case_sensitive = isinstance(value, SigmaCasedString)
        return _string_regex(value, case_sensitive).search(str(actual)) is not None
    raise UnsupportedRule(f"keyword of type {type(value).__name__}")


def _as_number(actual: Any) -> float | None:
    if isinstance(actual, bool):
        return None
    if isinstance(actual, (int, float)):
        return actual
    try:
        return float(str(actual))
    except ValueError:
        return None


def _string_regex(value: SigmaString, case_sensitive: bool) -> re.Pattern[str]:
    parts = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:
            raise UnsupportedRule(f"string part {part!r} (placeholders need a pipeline)")
    flags = re.DOTALL if case_sensitive else re.DOTALL | re.IGNORECASE
    return re.compile("".join(parts), flags)
