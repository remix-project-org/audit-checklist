# Syncing with upstream Cyfrin

This repository is a fork of [Cyfrin/audit-checklist](https://github.com/Cyfrin/audit-checklist). Upstream changes `checklist.json` in place, often in bulk ("Synchronized with solodit db"). The fork adds tag fields to the same item objects, so a plain `git merge` would conflict on nearly every item. Instead, `checklist.json` is rebuilt from upstream with `scripts/sync_upstream.py`, and every other file is merged normally.

## Ownership rules

| Data | Owner | On sync |
|---|---|---|
| Tree structure, category names, item order | upstream | upstream wins |
| `id`, `question`, `description`, `remediation`, `references`, `tags` of upstream items | upstream | upstream wins |
| `vuln_category` … `review_notes` on any item | fork | carried over by item ID |
| Items the fork added (IDs upstream doesn't have) | fork | kept, appended to the same category |

The rules follow from this table:

- **Don't edit upstream fields of upstream items in this fork.** Send text fixes upstream as a PR. If a fix is urgent, record the problem in `review_notes` and leave the text alone. Otherwise the next sync silently reverts it.
- When upstream changes an item's text, the sync drops that item to `needs_review` with a note, because its tags may no longer fit.
- New upstream items arrive untagged. Run the backfill script to tag them as `auto_tagged`/`needs_review`.

## Procedure

```bash
git remote add upstream https://github.com/Cyfrin/audit-checklist.git   # once
git fetch upstream
git switch -c sync/upstream-$(date +%Y%m%d) origin/main

# 1. Merge everything except checklist.json the normal way.
git merge --no-commit upstream/main || true
git checkout HEAD -- checklist.json           # start from the fork's version, conflicted or not

# 2. Rebuild checklist.json from upstream, keeping fork tags.
git show upstream/main:checklist.json > /tmp/upstream-checklist.json
python scripts/sync_upstream.py --upstream /tmp/upstream-checklist.json

# 3. Tag new upstream items (fetch the inputs listed in the script header first).
python scripts/backfill_tags.py --solidity-bugs bugs.json --bugs-by-version bugs_by_version.json --osv-dir osv

# 4. Validate, commit, open a PR.
python scripts/validate.py
git add -A && git commit
```

`sync_upstream.py` prints every change it made: new upstream items, upstream text changes, and fork-only items it kept. Paste that output into the PR description.

## Errors that stop the sync

The script writes nothing when it finds one of these:

- **ID collision.** Upstream started using an ID that the fork had already given to one of its own items. This can happen because new fork items follow upstream numbering (e.g. `SOL-Basics-VI-SVI-49`). Renumber the fork item to the next free ID, update any external references to it, and re-run.
- **Upstream removed or renumbered a Cyfrin item.** Find the new ID (or confirm the removal), move the tags across by hand, and re-run.
- **A fork-only item's category path no longer exists upstream.** Move the item to the category that replaced it.

## When upstream adds a category

The validator warns: `category path '…' has no vuln_categories source_paths entry`. Either add the path to an existing value's `source_paths` in `schema/vocabulary.json` or add a new value, then add a `CATEGORY_DEFAULTS` row in `scripts/backfill_tags.py` before running the backfill.

## When upstream adds an item field

The schema rejects unknown item fields (`additionalProperties: false`), so CI fails until the field is added to `schema/checklist.schema.json`, `UPSTREAM_FIELDS` in `scripts/sync_upstream.py` and `ITEM_FIELD_ORDER` in `scripts/checklist_lib.py`. This is deliberate: an upstream format change should be noticed, not passed through silently.
