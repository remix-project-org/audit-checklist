"""Shared helpers for checklist tooling: load/save, tree walking, semver ranges, URL checks.

Standard library only, so every script can import it without extra dependencies.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKLIST_PATH = REPO_ROOT / "checklist.json"
SCHEMA_PATH = REPO_ROOT / "schema" / "checklist.schema.json"
VOCABULARY_PATH = REPO_ROOT / "schema" / "vocabulary.json"

# Upstream serializes checklist.json with 4-space indent, ASCII escapes and no
# trailing newline. Keeping that byte format keeps upstream merges readable.
JSON_DUMP_KWARGS = {"indent": 4, "ensure_ascii": True}

# Field order for items: upstream fields first, then the additive tag fields.
ITEM_FIELD_ORDER = [
    "id", "question", "description", "remediation", "references", "tags",
    "vuln_category", "severity_prior", "applicability", "detection_hint",
    "verification", "provenance", "review_status", "review_notes",
]


def load_json(path: Path | str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def dump_checklist(data, path: Path | str = CHECKLIST_PATH) -> None:
    text = json.dumps(data, **JSON_DUMP_KWARGS)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def is_item(node: dict) -> bool:
    """Same rule the Remix consumer uses: a leaf has string `id` and `question`."""
    return isinstance(node, dict) and isinstance(node.get("id"), str) and isinstance(node.get("question"), str)


def iter_items(data, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], dict]]:
    """Yield (category_path, item) for every leaf, in file order."""
    for node in data:
        if is_item(node):
            yield path, node
        elif isinstance(node, dict) and isinstance(node.get("data"), list):
            yield from iter_items(node["data"], path + (node.get("category", "?"),))


def iter_categories(data, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], dict]]:
    for node in data:
        if isinstance(node, dict) and isinstance(node.get("data"), list) and not is_item(node):
            here = path + (node.get("category", "?"),)
            yield here, node
            yield from iter_categories(node["data"], here)


def order_item_fields(item: dict) -> dict:
    ordered = {k: item[k] for k in ITEM_FIELD_ORDER if k in item}
    for k, v in item.items():  # keep unknown fields (the validator will flag them)
        if k not in ordered:
            ordered[k] = v
    return ordered


def path_str(path: tuple[str, ...]) -> str:
    return "::".join(path)


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #

def is_well_formed_url(url: str) -> bool:
    if not isinstance(url, str) or not url or any(c.isspace() for c in url):
        return False
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc) and "." in parsed.netloc


# --------------------------------------------------------------------------- #
# Semver ranges (node-semver subset used by npm advisories and solc ranges)
# --------------------------------------------------------------------------- #

_VERSION_RE = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?"
_COMPARATOR_RE = re.compile(rf"^(>=|<=|>|<|=|\^|~)?({_VERSION_RE})$")


class RangeError(ValueError):
    pass


def parse_version(text: str) -> tuple:
    """Return a sortable key. Prereleases sort before the release."""
    core, _, pre = text.partition("-")
    major, minor, patch = (int(p) for p in core.split("."))
    if not pre:
        return (major, minor, patch, 1, ())
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (major, minor, patch, 0, parts)


def _expand(op: str, ver: str) -> list[tuple[str, tuple]]:
    key = parse_version(ver)
    major, minor, patch = key[:3]
    if op in ("", "="):
        return [("=", key)]
    if op == "^":
        if major > 0:
            upper = (major + 1, 0, 0, 0, ())
        elif minor > 0:
            upper = (0, minor + 1, 0, 0, ())
        else:
            upper = (0, 0, patch + 1, 0, ())
        return [(">=", key), ("<", upper)]
    if op == "~":
        return [(">=", key), ("<", (major, minor + 1, 0, 0, ()))]
    return [(op, key)]


def parse_range(text: str) -> list[list[tuple[str, tuple]]]:
    """Parse `>=0.8.28 <0.8.34 || =0.7.1` into OR-ed lists of AND-ed comparators."""
    if not isinstance(text, str) or not text.strip():
        raise RangeError("empty range")
    alternatives = []
    for alt in text.split("||"):
        tokens = alt.split()
        if not tokens:
            raise RangeError(f"empty alternative in {text!r}")
        comps = []
        for tok in tokens:
            m = _COMPARATOR_RE.match(tok)
            if not m:
                raise RangeError(f"bad comparator {tok!r} in {text!r}")
            comps.extend(_expand(m.group(1) or "", m.group(2)))
        lows = [k for op, k in comps if op in (">=", ">", "=")]
        highs = [k for op, k in comps if op in ("<", "<=", "=")]
        if lows and highs and max(lows) > min(highs):
            raise RangeError(f"unsatisfiable alternative {alt.strip()!r}")
        for op, k in comps:
            if op == "<" and any(lk >= k for lk in lows):
                raise RangeError(f"unsatisfiable alternative {alt.strip()!r}")
        alternatives.append(comps)
    return alternatives


def satisfies(version: str, range_text: str) -> bool:
    v = parse_version(version)
    ops = {
        "=": lambda a, b: a == b, ">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b, "<": lambda a, b: a < b,
    }
    return any(all(ops[op](v, k) for op, k in alt) for alt in parse_range(range_text))


_EVM_RANGE_RE = re.compile(r"^(>=|<=|>|<|=)?([A-Za-z]+)$")


def parse_evm_range(text: str, evm_versions: list[str]) -> list[tuple[str, int]]:
    """Parse `>=cancun` or `>=byzantium <cancun` against the ordered hard-fork list."""
    if not isinstance(text, str) or not text.strip():
        raise RangeError("empty evm_version range")
    out = []
    for tok in text.split():
        m = _EVM_RANGE_RE.match(tok)
        if not m or m.group(2) not in evm_versions:
            raise RangeError(f"bad evm_version comparator {tok!r}")
        out.append((m.group(1) or "=", evm_versions.index(m.group(2))))
    return out
