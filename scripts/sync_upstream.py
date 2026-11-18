#!/usr/bin/env python3
"""Rebuild checklist.json from an upstream Cyfrin checklist.json while keeping this fork's additions.

Rules (see SYNC.md):
  * Upstream is authoritative for the tree structure and for the upstream item fields
    (id, question, description, remediation, references, tags).
  * The fork's additive fields (vuln_category ... review_notes) are carried over by item ID.
  * If upstream changed an upstream field of an item that was `human_reviewed` or
    `auto_tagged`, the item drops to `needs_review` with a note: its tags may be stale.
  * Fork-only items (IDs upstream does not have) are kept in the same category path,
    after the upstream items of that category.
  * Upstream-only items (new upstream) come through without tags; run
    scripts/backfill_tags.py afterwards to tag them (they get auto_tagged/needs_review).
  * Hard errors (nothing is written): a fork-only ID that upstream now uses for a
    different question (ID collision), or a fork-only item whose category path no
    longer exists upstream.

Usage:
  python scripts/sync_upstream.py --upstream path/to/upstream-checklist.json [--fork checklist.json] [--out checklist.json]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import checklist_lib as lib  # noqa: E402

UPSTREAM_FIELDS = ["id", "question", "description", "remediation", "references", "tags"]
FORK_FIELDS = [f for f in lib.ITEM_FIELD_ORDER if f not in UPSTREAM_FIELDS]


def upstream_view(item: dict) -> dict:
    return {k: item[k] for k in UPSTREAM_FIELDS if k in item}


def is_cyfrin_sourced(item: dict) -> bool:
    sources = (item.get("provenance") or {}).get("sources") or []
    return any(s.get("type") == "cyfrin" for s in sources)


def find_category(nodes: list, path: tuple[str, ...]):
    for node in nodes:
        if not lib.is_item(node) and node.get("category") == path[0]:
            return node if len(path) == 1 else find_category(node["data"], path[1:])
    return None


def sync(upstream: list, fork: list) -> tuple[list, list[str], list[str]]:
    report: list[str] = []
    errors: list[str] = []
    fork_items = {item["id"]: (path, item) for path, item in lib.iter_items(fork)}
    upstream_items = {item["id"]: (path, item) for path, item in lib.iter_items(upstream)}
    fork_only = [iid for iid in fork_items if iid not in upstream_items]

    merged = upstream  # mutated in place: it is our own parsed copy

    def overlay(nodes, path):
        for i, node in enumerate(nodes):
            if lib.is_item(node):
                iid = node["id"]
                if iid not in fork_items:
                    report.append(f"new upstream item {iid} (untagged; run backfill_tags.py)")
                    continue
                _, mine = fork_items[iid]
                new = dict(node)
                for f in FORK_FIELDS:
                    if f in mine:
                        new[f] = mine[f]
                if upstream_view(mine) != upstream_view(node):
                    changed = [k for k in UPSTREAM_FIELDS if mine.get(k) != node.get(k)]
                    report.append(f"upstream changed {iid}: {', '.join(changed)}")
                    if new.get("review_status") in ("human_reviewed", "auto_tagged"):
                        new["review_status"] = "needs_review"
                        note = f"Upstream changed {', '.join(changed)}; re-check tags."
                        new["review_notes"] = f"{note} {new.get('review_notes', '')}".strip()
                nodes[i] = lib.order_item_fields(new)
            elif isinstance(node.get("data"), list):
                overlay(node["data"], path + (node["category"],))

    overlay(merged, ())

    for iid in fork_only:
        path, item = fork_items[iid]
        target = find_category(merged, path)
        if target is None:
            errors.append(f"fork-only item {iid}: category path {lib.path_str(path)!r} no longer exists upstream")
            continue
        target["data"].append(item)
        report.append(f"kept fork-only item {iid}")

    for iid in fork_only:
        if is_cyfrin_sourced(fork_items[iid][1]):
            errors.append(f"{iid} is Cyfrin-sourced but no longer exists upstream (removed or renumbered); resolve by hand")

    # ID collision: an item the fork added itself, whose ID upstream has now started using.
    for iid, (_, mine) in fork_items.items():
        if iid in upstream_items and "provenance" in mine and not is_cyfrin_sourced(mine):
            errors.append(f"ID collision: fork-added item {iid} now also exists upstream; renumber the fork item")

    return merged, report, errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--fork", default=str(lib.CHECKLIST_PATH))
    ap.add_argument("--out", default=str(lib.CHECKLIST_PATH))
    args = ap.parse_args(argv)

    merged, report, errors = sync(lib.load_json(args.upstream), lib.load_json(args.fork))
    for line in report:
        print(line)
    if errors:
        for e in errors:
            print(f"error: {e}")
        print("nothing written")
        return 1
    lib.dump_checklist(merged, args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
