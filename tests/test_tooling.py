"""Tests for scripts/validate.py, scripts/checklist_lib.py and scripts/sync_upstream.py.

Run: python -m unittest discover -s tests
"""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import checklist_lib as lib  # noqa: E402
import sync_upstream  # noqa: E402
import validate  # noqa: E402

VALID_ITEM = {
    "id": "SOL-Test-1",
    "question": "Is X checked?",
    "description": "X must be checked.",
    "remediation": "Check X.",
    "references": ["https://example.com/a"],
    "tags": [],
    "vuln_category": "math",
    "severity_prior": "medium",
    "applicability": {
        "all_of": ["uses_assembly", "inherits:ERC4626"],
        "any_of": ["integrates:uniswap"],
        "solc": ">=0.8.13 <0.8.17",
        "compiler_settings": {"via_ir": True, "evm_version": ">=cancun"},
        "dependencies": [{"package": "@openzeppelin/contracts", "range": ">=4.5.0 <4.9.6 || >=5.0.0-rc.0 <5.0.2"}],
    },
    "detection_hint": {"slither": ["divide-before-multiply"], "ast_pattern": "BinaryOperation / then *"},
    "verification": {"method": "invariant_fuzz", "property": "no precision loss"},
    "provenance": {"sources": [{"type": "cyfrin", "ref": "SOL-Test-1", "url": "https://github.com/Cyfrin/audit-checklist"}],
                   "last_reviewed": "2026-11-18"},
    "review_status": "auto_tagged",
}


def wrap(*items):
    return [{"category": "Basics", "description": "", "data": [{"category": "Math", "description": "", "data": list(items)}]}]


class ValidatorTest(unittest.TestCase):
    def run_validator(self, data):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(data, fh)
        errors, _, _ = validate.validate(Path(fh.name), lib.SCHEMA_PATH, lib.VOCABULARY_PATH)
        return errors

    def assert_error(self, mutate, needle):
        item = copy.deepcopy(VALID_ITEM)
        mutate(item)
        errors = self.run_validator(wrap(item))
        self.assertTrue(any(needle in e for e in errors), f"expected {needle!r} in {errors}")

    def test_valid_item_passes(self):
        self.assertEqual(self.run_validator(wrap(copy.deepcopy(VALID_ITEM))), [])

    def test_empty_applicability_is_allowed(self):
        item = copy.deepcopy(VALID_ITEM)
        item["applicability"] = {}
        self.assertEqual(self.run_validator(wrap(item)), [])

    def test_duplicate_ids(self):
        errors = self.run_validator(wrap(copy.deepcopy(VALID_ITEM), copy.deepcopy(VALID_ITEM)))
        self.assertTrue(any("duplicate id" in e for e in errors))

    def test_unknown_category(self):
        self.assert_error(lambda i: i.update(vuln_category="made-up"), "vuln_category")

    def test_unknown_feature(self):
        self.assert_error(lambda i: i["applicability"].update(all_of=["uses_magic"]), "unknown feature key")

    def test_unknown_prefix_and_integration(self):
        self.assert_error(lambda i: i["applicability"].update(all_of=["calls:foo"]), "unknown feature prefix")
        self.assert_error(lambda i: i["applicability"].update(any_of=["integrates:sushi"]), "unknown integration")

    def test_bad_semver(self):
        self.assert_error(lambda i: i["applicability"].update(solc="0.8.x"), "applicability.solc")
        self.assert_error(lambda i: i["applicability"].update(solc=">=0.8.17 <0.8.13"), "unsatisfiable")
        self.assert_error(lambda i: i["applicability"]["dependencies"][0].update(range="4.9"), "dependencies")

    def test_bad_evm_version(self):
        self.assert_error(lambda i: i["applicability"]["compiler_settings"].update(evm_version=">=london2"), "evm_version")

    def test_unknown_compiler_setting(self):
        self.assert_error(lambda i: i["applicability"]["compiler_settings"].update(optimizer_runs=200), "schema")

    def test_malformed_urls(self):
        self.assert_error(lambda i: i.update(references=["not a url"]), "references: malformed URL")
        self.assert_error(lambda i: i["provenance"]["sources"][0].update(url="github.com/x"), "provenance: malformed URL")

    def test_provenance_required(self):
        self.assert_error(lambda i: i["provenance"].update(sources=[]), "provenance")
        self.assert_error(lambda i: i.pop("provenance"), "provenance")

    def test_unknown_slither_detector(self):
        self.assert_error(lambda i: i["detection_hint"].update(slither=["reentrancy-everything"]), "unknown detector")

    def test_needs_review_requires_notes(self):
        self.assert_error(lambda i: i.update(review_status="needs_review"), "review_notes")

    def test_item_must_not_carry_structural_keys(self):
        self.assert_error(lambda i: i.update(category="math"), "schema")

    def test_repository_checklist_is_valid(self):
        errors, _, _ = validate.validate(lib.CHECKLIST_PATH, lib.SCHEMA_PATH, lib.VOCABULARY_PATH)
        self.assertEqual(errors, [])


class SemverTest(unittest.TestCase):
    def test_satisfies(self):
        self.assertTrue(lib.satisfies("0.8.30", ">=0.8.28 <0.8.34"))
        self.assertFalse(lib.satisfies("0.8.34", ">=0.8.28 <0.8.34"))
        self.assertTrue(lib.satisfies("4.9.4", "=4.9.4"))
        self.assertTrue(lib.satisfies("5.0.1", ">=4.5.0 <4.9.6 || >=5.0.0-rc.0 <5.0.2"))
        self.assertTrue(lib.satisfies("5.0.0-rc.1", ">=5.0.0-rc.0 <5.0.2"))
        self.assertFalse(lib.satisfies("3.4.0", "<3.4.0-rc.0"))
        self.assertTrue(lib.satisfies("0.8.25", "^0.8.0"))


class SyncTest(unittest.TestCase):
    def test_round_trip_keeps_fork_fields_and_fork_only_items(self):
        tagged = copy.deepcopy(VALID_ITEM)
        fork_only = copy.deepcopy(VALID_ITEM)
        fork_only["id"] = "SOL-Test-2"
        fork_only["provenance"]["sources"] = [{"type": "ghsa", "ref": "GHSA-x", "url": "https://github.com/advisories/GHSA-x"}]
        fork = wrap(tagged, fork_only)
        upstream = wrap({k: VALID_ITEM[k] for k in sync_upstream.UPSTREAM_FIELDS})
        merged, _, errors = sync_upstream.sync(copy.deepcopy(upstream), fork)
        self.assertEqual(errors, [])
        self.assertEqual(merged, fork)

    def test_upstream_text_change_demotes_review_status(self):
        fork = wrap(copy.deepcopy(VALID_ITEM))
        up_item = {k: VALID_ITEM[k] for k in sync_upstream.UPSTREAM_FIELDS}
        up_item["question"] = "Is X checked twice?"
        merged, report, errors = sync_upstream.sync(wrap(up_item), fork)
        item = next(i for _, i in lib.iter_items(merged))
        self.assertEqual(errors, [])
        self.assertEqual(item["question"], "Is X checked twice?")
        self.assertEqual(item["review_status"], "needs_review")
        self.assertIn("question", item["review_notes"])

    def test_id_collision_is_an_error(self):
        mine = copy.deepcopy(VALID_ITEM)
        mine["provenance"]["sources"] = [{"type": "ghsa", "ref": "GHSA-x", "url": "https://github.com/advisories/GHSA-x"}]
        up_item = {k: VALID_ITEM[k] for k in sync_upstream.UPSTREAM_FIELDS}
        up_item["question"] = "Something else entirely?"
        _, _, errors = sync_upstream.sync(wrap(up_item), wrap(mine))
        self.assertTrue(any("ID collision" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
