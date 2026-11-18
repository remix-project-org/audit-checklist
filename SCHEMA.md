# Checklist item schema

`checklist.json` keeps the upstream [Cyfrin/audit-checklist](https://github.com/Cyfrin/audit-checklist) format and adds machine-readable tags to every item. The tags let tools select only the items relevant to a contract (from compiler AST features and settings) and decide how to verify a finding.

- JSON Schema: [`schema/checklist.schema.json`](schema/checklist.schema.json)
- Closed vocabularies (categories, feature keys, compiler settings, Slither IDs): [`schema/vocabulary.json`](schema/vocabulary.json)
- Validator: `python scripts/validate.py` (CI runs it on every PR)

## File structure (unchanged)

The file is an array of **category nodes**. A category node is `{category, description, data}`, and `data` holds either sub-categories or **items**. A node is an item when it has string `id` and `question` fields. Remix IDE and Solodit use the same rule, so items must never carry a `category` or `data` key. That is why the vulnerability class field below is named `vuln_category`.

## Item fields

| Field | Required | Origin | Meaning |
|---|---|---|---|
| `id` | yes | upstream | Stable ID, `SOL-<category path abbreviation>-<n>`. New items continue the numbering of their category. |
| `question` | yes | upstream | One question an auditor or model can answer from the code. |
| `description` | yes | upstream | What goes wrong and why. |
| `remediation` | yes | upstream | How to fix it. |
| `references` | yes | upstream | URLs (may be empty). Left as upstream has them; sources also go in `provenance`. |
| `tags` | yes | upstream | Free-form upstream tags (rarely used). Unchanged. |
| `vuln_category` | yes | added | Vulnerability class, one key of `vocabulary.json#/vuln_categories`. |
| `severity_prior` | yes | added | `critical` / `high` / `medium` / `low` / `informational`: how serious the issue typically is **when present**. |
| `applicability` | yes | added | When the item applies (see below). `{}` means always. |
| `detection_hint` | no | added | Slither detector IDs and/or a short AST pattern. |
| `verification` | yes | added | How a finding can be confirmed. |
| `provenance` | yes | added | Where the item comes from, and when the sources were last checked. |
| `review_status` | yes | added | `human_reviewed` / `auto_tagged` / `needs_review`. |
| `review_notes` | if `needs_review` | added | Why the item needs review, or what a reviewer decided. |

### `vuln_category`

The values come from the checklist's own hierarchy: one per selectable category, with the LSD and Chainlink sub-levels folded into their parent. Each value lists its `source_paths`. An item's default category is the one its path maps to, and an item may override it (e.g. `SOL-Basics-VI-SVI-4` is filed under compiler bugs but is a hash-collision issue, so it is `hash-merkle`). If upstream adds a category path, the validator warns until it is mapped.

```json
"vuln_category": "oracle"
```

### `applicability`

Every clause that is present must hold. Leave out clauses you can't state with confidence: a missing clause can only add noise, while a wrong clause can hide a real issue.

| Clause | Type | Holds when |
|---|---|---|
| `all_of` | feature keys | every listed feature is present |
| `any_of` | feature keys | at least one listed feature is present |
| `solc` | semver range | the compiler version is in the range (node-semver syntax: `>=0.8.28 <0.8.34`, `\|\|` for alternatives) |
| `compiler_settings` | object | every listed setting matches: `optimizer`, `yul_optimizer`, `via_ir`, `abi_encoder_v2` (booleans), `evm_version` (e.g. `>=cancun`) |
| `dependencies` | `[{package, range}]` | **any** listed npm package is installed in a matching version |

**Feature keys** are boolean properties of the compiled contract, including everything it inherits. Each one is defined in `vocabulary.json#/features` by a single line that an AST extractor can implement. Three parameterized prefixes are allowed:

- `inherits:<Name>`: the contract inherits `Name` directly or transitively (e.g. `inherits:ERC4626`)
- `uses_library:<Name>`: the contract calls library `Name` (e.g. `uses_library:ECDSA`)
- `integrates:<protocol>`: `<protocol>` must be listed in `vocabulary.json#/integrations`

Add a feature key only when several items need it, and always give it a definition. If an extractor can't compute a feature, treat it as present. Selection must fail open.

**Compiler bugs.** `solc` and `compiler_settings` are copied mechanically from [`docs/bugs.json`](https://github.com/ethereum/solidity/blob/develop/docs/bugs.json): `solc` is `>=introduced <fixed` (`<fixed` if there is no `introduced`), and the `conditions` keys map 1:1 (`viaIR` → `via_ir`, `yulOptimizer` → `yul_optimizer`, `ABIEncoderV2` → `abi_encoder_v2`, `evmVersion` → `evm_version`). `scripts/backfill_tags.py` checks every range against `docs/bugs_by_version.json`. No LLM is involved, so matching is deterministic. Features are added only where the bug **requires** the construct.

Examples:

```json
"applicability": {}
```
```json
"applicability": {"all_of": ["has_loops", "payable_functions"]}
```
```json
"applicability": {
  "solc": ">=0.8.28 <0.8.34",
  "compiler_settings": {"via_ir": true, "evm_version": ">=cancun"}
}
```
```json
"applicability": {
  "any_of": ["uses_library:Base64", "uses_library:Base64Upgradeable"],
  "dependencies": [
    {"package": "@openzeppelin/contracts", "range": ">=4.5.0 <4.9.6 || >=5.0.0-rc.0 <5.0.2"},
    {"package": "@openzeppelin/contracts-upgradeable", "range": ">=4.5.0 <4.9.6 || >=5.0.0-rc.0 <5.0.2"}
  ]
}
```

### `detection_hint`

Optional. `slither` lists detector IDs from `vocabulary.json#/slither_detectors`. `ast_pattern` is a short, human-readable description of the code shape to look for.

```json
"detection_hint": {"slither": ["msg-value-loop"]}
```
```json
"detection_hint": {"ast_pattern": "`delete` applied to an IndexAccess on a `bytes memory` variable"}
```

### `verification`

`method` is one of:

- `invariant_fuzz`: a property that holds for all inputs; suitable for a Foundry invariant or fuzz test.
- `poc_test`: a concrete attack sequence; suitable for a Foundry proof-of-concept test.
- `manual_only`: needs judgement, or is settled deterministically by version and settings (compiler bugs and dependency advisories).

`property` is optional: one line stating the property or attack.

```json
"verification": {"method": "invariant_fuzz", "property": "Rounding in every deposit/withdraw/convert path never favors the user over the protocol."}
```

### `provenance`

`sources` holds at least one `{type, ref?, url}`. The `type` is one of:

| type | Used for | `ref` |
|---|---|---|
| `cyfrin` | items that come from the upstream Cyfrin checklist | the item ID |
| `ghsa` | GitHub Security Advisories | `GHSA-xxxx-xxxx-xxxx` |
| `solidity_bugs_json` | entries in ethereum/solidity `docs/bugs.json` | the bug `uid`, e.g. `SOL-2026-1` |
| `solidity_blog` | blog.soliditylang.org bug posts | n/a |
| `audit_report` | public audit findings (e.g. Solodit issue pages) | report or finding slug |
| `other` | EIP pages, docs, articles, Snyk | optional |

`last_reviewed` is the ISO date the sources were last checked to exist and match the item. It is not a sign-off: human approval is recorded only by `review_status`. Never invent an advisory ID or URL. If a source can't be confirmed, use `needs_review`.

```json
"provenance": {
  "sources": [
    {"type": "solidity_bugs_json", "ref": "SOL-2026-1", "url": "https://github.com/ethereum/solidity/blob/develop/docs/bugs.json"},
    {"type": "solidity_blog", "url": "https://blog.soliditylang.org/2026/02/18/transient-storage-clearing-helper-collision-bug/"}
  ],
  "last_reviewed": "2026-11-18"
}
```

### `review_status`

- `auto_tagged`: tags were assigned by rules or a model and haven't been checked by a person.
- `needs_review`: the tagger was unsure, or the item itself is vague or misfiled. `review_notes` says why.
- `human_reviewed`: a named reviewer approved the item and its tags. Tools never set this. A reviewer sets it in a PR, and should update `last_reviewed` and `review_notes` at the same time.

## Tooling

| Command | Purpose |
|---|---|
| `pip install -r requirements.txt` | install `jsonschema` (the only dependency) |
| `python scripts/validate.py` | validate `checklist.json`; exits non-zero on any error |
| `python -m unittest discover -s tests` | tooling tests |
| `python scripts/backfill_tags.py --solidity-bugs … --bugs-by-version … --osv-dir …` | tag items that have no tags yet (see the script header for inputs) |
| `python scripts/sync_upstream.py --upstream …` | merge an upstream checklist.json, keeping fork tags (see [SYNC.md](SYNC.md)) |

`scripts/backfill_tags.py` holds the rule tables used for the initial backfill: per-category defaults, per-item overrides, the SVI→bugs.json mapping and the OVI→GHSA mapping. Review the tables to judge `auto_tagged` values in bulk.
