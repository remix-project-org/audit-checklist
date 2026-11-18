#!/usr/bin/env python3
"""Validate checklist.json against the schema and the closed vocabularies.

Checks:
  * JSON Schema validity (schema/checklist.schema.json)
  * unique item IDs
  * vuln_category, feature keys, compiler settings and slither IDs drawn from schema/vocabulary.json
  * valid semver ranges (applicability.solc, dependency ranges) and evm_version ranges
  * well-formed URLs in references and provenance
  * at least one provenance source per item, valid last_reviewed date
  * needs_review items carry review_notes

Usage:
  python scripts/validate.py [checklist.json] [--vocabulary PATH] [--schema PATH] [--quiet]
Exit code 0 when valid, 1 when any error is found.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import checklist_lib as lib  # noqa: E402

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    sys.exit("jsonschema is required: pip install -r requirements.txt")

IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def check_feature(key: str, vocab: dict) -> str | None:
    if key in vocab["features"] and not key.startswith("$"):
        return None
    prefix, sep, arg = key.partition(":")
    if not sep:
        return f"unknown feature key {key!r}"
    if prefix not in vocab["feature_prefixes"] or prefix.startswith("$"):
        return f"unknown feature prefix {prefix!r} in {key!r}"
    if prefix == "integrates":
        if arg not in vocab["integrations"]:
            return f"unknown integration {arg!r} in {key!r}"
    elif not IDENT_RE.match(arg):
        return f"feature argument {arg!r} in {key!r} is not an identifier"
    return None


def validate(checklist_path: Path, schema_path: Path, vocab_path: Path) -> tuple[list[str], list[str], dict]:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        data = lib.load_json(checklist_path)
    except Exception as exc:  # noqa: BLE001
        return [f"cannot parse {checklist_path}: {exc}"], warnings, {}
    schema = lib.load_json(schema_path)
    vocab = lib.load_json(vocab_path)

    # 1. JSON Schema
    validator = Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"schema: {where}: {err.message[:300]}")

    categories = {k for k in vocab["vuln_categories"] if not k.startswith("$")}
    slither_ids = set(vocab["slither_detectors"]["ids"])
    evm_versions = vocab["evm_versions"]
    mapped_paths = {p for k in categories for p in vocab["vuln_categories"][k]["source_paths"]}

    ids = collections.Counter()
    stats = collections.Counter()
    for path, item in lib.iter_items(data):
        iid = item.get("id", "<no id>")
        ids[iid] += 1
        stats[f"review_status:{item.get('review_status')}"] += 1
        stats["items"] += 1

        def err(msg: str) -> None:
            errors.append(f"{iid}: {msg}")

        cat = item.get("vuln_category")
        if cat is not None and cat not in categories:
            err(f"vuln_category {cat!r} not in vocabulary")

        appl = item.get("applicability")
        if isinstance(appl, dict):
            for clause in ("all_of", "any_of"):
                for key in appl.get(clause, []) or []:
                    problem = check_feature(key, vocab) if isinstance(key, str) else "non-string feature"
                    if problem:
                        err(f"applicability.{clause}: {problem}")
            if "solc" in appl:
                try:
                    lib.parse_range(appl["solc"])
                except lib.RangeError as exc:
                    err(f"applicability.solc: {exc}")
            settings = appl.get("compiler_settings") or {}
            if "evm_version" in settings:
                try:
                    lib.parse_evm_range(settings["evm_version"], evm_versions)
                except lib.RangeError as exc:
                    err(f"applicability.compiler_settings.evm_version: {exc}")
            for dep in appl.get("dependencies", []) or []:
                if isinstance(dep, dict) and "range" in dep:
                    try:
                        lib.parse_range(dep["range"])
                    except lib.RangeError as exc:
                        err(f"applicability.dependencies[{dep.get('package')}]: {exc}")
            if not appl:
                stats["applicability:always"] += 1

        hint = item.get("detection_hint")
        if isinstance(hint, dict):
            for sid in hint.get("slither", []) or []:
                if sid not in slither_ids:
                    err(f"detection_hint.slither: unknown detector {sid!r}")

        for ref in item.get("references", []) or []:
            if not lib.is_well_formed_url(ref):
                err(f"references: malformed URL {ref!r}")

        prov = item.get("provenance")
        if isinstance(prov, dict):
            sources = prov.get("sources") or []
            if not sources:
                err("provenance: needs at least one source")
            for src in sources:
                if isinstance(src, dict) and not lib.is_well_formed_url(src.get("url", "")):
                    err(f"provenance: malformed URL {src.get('url')!r}")
            try:
                datetime.date.fromisoformat(prov.get("last_reviewed", ""))
            except (TypeError, ValueError):
                err(f"provenance.last_reviewed: not an ISO date: {prov.get('last_reviewed')!r}")
        elif prov is None:
            err("provenance: missing")

        if item.get("review_status") == "needs_review" and not item.get("review_notes"):
            err("needs_review items must explain why in review_notes")

    for iid, n in ids.items():
        if n > 1:
            errors.append(f"{iid}: duplicate id ({n} occurrences)")

    for path, node in lib.iter_categories(data):
        has_items = any(lib.is_item(c) for c in node["data"])
        if has_items and lib.path_str(path) not in mapped_paths:
            warnings.append(f"category path {lib.path_str(path)!r} has no vuln_categories source_paths entry")

    return errors, warnings, dict(stats)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("checklist", nargs="?", default=str(lib.CHECKLIST_PATH))
    ap.add_argument("--schema", default=str(lib.SCHEMA_PATH))
    ap.add_argument("--vocabulary", default=str(lib.VOCABULARY_PATH))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    errors, warnings, stats = validate(Path(args.checklist), Path(args.schema), Path(args.vocabulary))
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    if not args.quiet and stats:
        print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items())))
    if errors:
        print(f"FAILED: {len(errors)} error(s)")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
