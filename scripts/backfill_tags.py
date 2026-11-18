#!/usr/bin/env python3
"""Fill the additive tag fields on checklist items that do not have them yet.

Every value this script assigns is a machine guess, so items are marked
`auto_tagged` (or `needs_review` when the rules below say a human must look).
It never touches an item that already has `review_status` unless --retag is
given, and --retag never touches `human_reviewed` items.

Inputs (pass local copies; the script makes no network calls):
  --solidity-bugs   ethereum/solidity docs/bugs.json
  --bugs-by-version ethereum/solidity docs/bugs_by_version.json (cross-check)
  --osv-dir         directory with oz-contracts.json and oz-contracts-upgradeable.json,
                    the OSV.dev query results for npm @openzeppelin/contracts[-upgradeable]

Fetch them with:
  curl -o bugs.json https://raw.githubusercontent.com/ethereum/solidity/develop/docs/bugs.json
  curl -o bugs_by_version.json https://raw.githubusercontent.com/ethereum/solidity/develop/docs/bugs_by_version.json
  curl -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"@openzeppelin/contracts","ecosystem":"npm"}}' -o osv/oz-contracts.json
  curl -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"@openzeppelin/contracts-upgradeable","ecosystem":"npm"}}' -o osv/oz-contracts-upgradeable.json

Usage:
  python scripts/backfill_tags.py --solidity-bugs bugs.json --bugs-by-version bugs_by_version.json --osv-dir osv [--retag] [--date YYYY-MM-DD]
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import checklist_lib as lib  # noqa: E402

CYFRIN_URL = "https://github.com/Cyfrin/audit-checklist/blob/main/checklist.json"
BUGS_JSON_URL = "https://github.com/ethereum/solidity/blob/develop/docs/bugs.json"
GHSA_URL = "https://github.com/advisories/{}"

# --------------------------------------------------------------------------- #
# Category defaults: path -> (severity_prior, verification method, all_of features)
# vuln_category itself comes from vocabulary.json source_paths.
# --------------------------------------------------------------------------- #
CATEGORY_DEFAULTS = {
    "Attacker's Mindset::Denial-Of-Service(DOS) Attack": ("medium", "poc_test", []),
    "Attacker's Mindset::Donation Attack": ("high", "poc_test", []),
    "Attacker's Mindset::Front-running Attack": ("medium", "poc_test", []),
    "Attacker's Mindset::Griefing Attack": ("medium", "poc_test", []),
    "Attacker's Mindset::Miner Attack": ("low", "manual_only", []),
    "Attacker's Mindset::Price Manipulation Attack": ("high", "poc_test", []),
    "Attacker's Mindset::Reentrancy Attack": ("high", "poc_test", ["has_external_calls"]),
    "Attacker's Mindset::Replay Attack": ("high", "poc_test", []),
    "Attacker's Mindset::Rug Pull": ("medium", "manual_only", ["has_privileged_roles"]),
    "Attacker's Mindset::Sandwich Attack": ("medium", "poc_test", []),
    "Attacker's Mindset::Sybil Attack": ("medium", "manual_only", []),
    "Basics::Access Control": ("high", "poc_test", []),
    "Basics::Array / Loop": ("medium", "invariant_fuzz", []),
    "Basics::Block Reorganization": ("medium", "manual_only", []),
    "Basics::Event": ("informational", "manual_only", []),
    "Basics::Function": ("medium", "invariant_fuzz", []),
    "Basics::Inheritance": ("medium", "manual_only", []),
    "Basics::Initialization": ("high", "poc_test", []),
    "Basics::Map": ("low", "invariant_fuzz", []),
    "Basics::Math": ("medium", "invariant_fuzz", []),
    "Basics::Payment": ("medium", "poc_test", []),
    "Basics::Proxy/Upgradable": ("high", "poc_test", ["is_upgradeable"]),
    "Basics::Type": ("medium", "invariant_fuzz", []),
    "Basics::Version Issues::EIP Adoption Issues": ("low", "manual_only", []),
    "Basics::Version Issues::OpenZeppelin Version Issues": ("medium", "manual_only", []),
    "Basics::Version Issues::Solidity Version Issues": ("medium", "manual_only", []),
    "Centralization Risk": ("medium", "manual_only", ["has_privileged_roles"]),
    "Defi::AMM/Swap": ("high", "poc_test", ["performs_swaps"]),
    "Defi::FlashLoan": ("high", "poc_test", []),
    "Defi::General": ("medium", "poc_test", []),
    "Defi::Lending": ("high", "poc_test", []),
    "Defi::Liquid Staking Derivatives": ("high", "poc_test", []),
    "Defi::Oracle": ("high", "poc_test", ["reads_oracle"]),
    "Defi::Staking": ("medium", "invariant_fuzz", []),
    "External Call": ("high", "poc_test", ["has_external_calls"]),
    "Hash / Merkle Tree": ("high", "poc_test", ["uses_merkle_proof"]),
    "Heuristics": ("medium", "manual_only", []),
    "Integrations::AAVE / Compound": ("medium", "manual_only", []),
    "Integrations::Balancer": ("medium", "manual_only", ["integrates:balancer"]),
    "Integrations::Chainlink::CCIP": ("high", "poc_test", ["integrates:chainlink-ccip"]),
    "Integrations::Chainlink::VRF": ("medium", "manual_only", ["integrates:chainlink-vrf"]),
    "Integrations::Gnosis Safe": ("high", "poc_test", ["integrates:gnosis-safe"]),
    "Integrations::LayerZero": ("medium", "manual_only", ["integrates:layerzero"]),
    "Integrations::LSD::cbETH": ("medium", "manual_only", ["integrates:cbeth"]),
    "Integrations::LSD::rETH": ("medium", "manual_only", ["integrates:reth"]),
    "Integrations::LSD::sfrxETH": ("medium", "manual_only", ["integrates:sfrxeth"]),
    "Integrations::LSD::stETH": ("medium", "manual_only", ["integrates:steth"]),
    "Integrations::Uniswap": ("medium", "poc_test", ["integrates:uniswap"]),
    "Low Level": ("medium", "poc_test", []),
    "Multi-chain/Cross-chain": ("medium", "manual_only", []),
    "Signature": ("high", "poc_test", ["verifies_signatures"]),
    "Timelock": ("medium", "manual_only", ["has_privileged_roles"]),
    "Token::Fungible : ERC20": ("medium", "poc_test", ["handles_erc20"]),
    "Token::Non-fungible : ERC721/1155": ("medium", "poc_test", ["handles_nft"]),
}

# Per-item applicability overrides. Replaces the category default entirely.
APPLICABILITY_OVERRIDES = {
    "SOL-AM-DOSA-3": {"all_of": ["handles_erc20"]},
    "SOL-AM-DOSA-5": {"all_of": ["handles_erc20"]},
    "SOL-AM-MA-1": {"all_of": ["uses_block_timestamp"]},
    "SOL-AM-MA-2": {"any_of": ["uses_block_randomness", "uses_block_timestamp"]},
    "SOL-AM-ReplayAttack-2": {"all_of": ["verifies_signatures"]},
    "SOL-Basics-AC-7": {"all_of": ["uses_tx_origin"]},
    "SOL-Basics-AL-1": {"all_of": ["has_loops"]},
    "SOL-Basics-AL-8": {"all_of": ["has_loops"]},
    "SOL-Basics-AL-9": {"all_of": ["has_loops"]},
    "SOL-Basics-AL-10": {"all_of": ["has_loops"]},
    "SOL-Basics-AL-11": {"all_of": ["has_loops", "payable_functions"]},
    "SOL-Basics-AL-12": {"all_of": ["has_loops"]},
    "SOL-Basics-AL-13": {"all_of": ["has_loops"]},
    "SOL-Basics-Initialization-2": {"all_of": ["inherits:Initializable"]},
    "SOL-Basics-Initialization-3": {"all_of": ["is_upgradeable"]},
    "SOL-Basics-Math-9": {"all_of": ["uses_unchecked"]},
    "SOL-Basics-Math-11": {"all_of": ["uses_assembly"]},
    "SOL-Basics-Payment-1": {"all_of": ["sends_eth"]},
    "SOL-Basics-Payment-2": {"all_of": ["payable_functions"]},
    "SOL-Basics-Payment-6": {"all_of": ["sends_eth"]},
    "SOL-Basics-Payment-7": {"all_of": ["payable_functions"]},
    "SOL-Basics-PU-4": {"all_of": ["inherits:UUPSUpgradeable"]},
    "SOL-Basics-PU-6": {"all_of": ["is_upgradeable"], "any_of": ["uses_selfdestruct", "uses_delegatecall"]},
    "SOL-Basics-VI-EAI-1": {"all_of": ["uses_selfdestruct"]},
    "SOL-Basics-VI-SVI-4": {"all_of": ["uses_abi_encode_packed"]},
    "SOL-Defi-FlashLoan-2": {"all_of": ["inherits:ERC4626"]},
    "SOL-Defi-Oracle-13": {},
    "SOL-EC-3": {"all_of": ["uses_delegatecall"]},
    "SOL-EC-10": {"all_of": ["uses_delegatecall"]},
    "SOL-EC-11": {"all_of": ["uses_delegatecall"]},
    "SOL-Heuristics-5": {"all_of": ["has_external_calls"]},
    "SOL-Heuristics-14": {"any_of": ["sends_eth", "payable_functions"]},
    "SOL-Integrations-AC-1": {"all_of": ["integrates:compound"]},
    "SOL-Integrations-AC-2": {"any_of": ["integrates:aave", "integrates:compound"]},
    "SOL-Integrations-AC-3": {"any_of": ["integrates:aave", "integrates:compound"]},
    "SOL-Integrations-AC-4": {"any_of": ["integrates:aave", "integrates:compound"]},
    "SOL-Integrations-AC-5": {"all_of": ["integrates:aave"]},
    "SOL-Integrations-AC-6": {"all_of": ["integrates:aave"]},
    "SOL-Integrations-AC-7": {"any_of": ["integrates:aave", "integrates:compound"]},
    "SOL-Integrations-AC-8": {"all_of": ["integrates:aave"]},
    "SOL-Integrations-AC-9": {"all_of": ["integrates:aave"]},
    "SOL-LL-1": {"any_of": ["uses_low_level_call", "uses_assembly"]},
    "SOL-LL-2": {"any_of": ["uses_low_level_call", "uses_assembly"]},
    "SOL-LL-3": {"any_of": ["uses_low_level_call", "uses_assembly"]},
    "SOL-LL-4": {"any_of": ["uses_low_level_call", "uses_assembly"]},
    "SOL-LL-5": {"all_of": ["uses_assembly"]},
    "SOL-McCc-1": {"all_of": ["uses_block_timestamp"]},
    "SOL-McCc-4": {"all_of": ["uses_tx_origin"]},
    "SOL-McCc-8": {"all_of": ["cross_chain_messaging"]},
    "SOL-McCc-12": {"solc": ">=0.8.20"},
    "SOL-McCc-13": {"all_of": ["cross_chain_messaging"]},
}

SEVERITY_OVERRIDES = {
    "SOL-Basics-AC-2": "critical",
    "SOL-Basics-PU-4": "critical",
    "SOL-Basics-PU-5": "critical",
    "SOL-Basics-Function-4": "informational",
    "SOL-Basics-Function-7": "informational",
    "SOL-Basics-Inheritance-1": "low",
    "SOL-Basics-Math-3": "low",
    "SOL-Basics-Type-2": "low",
    "SOL-CR-5": "low",
    "SOL-Heuristics-6": "informational",
    "SOL-Heuristics-15": "high",
    "SOL-AM-ReentrancyAttack-2": "high",
    "SOL-Basics-VI-SVI-4": "medium",
}

VERIFICATION_OVERRIDES = {
    "SOL-Basics-AC-2": ("poc_test", "An unprivileged caller can successfully call a state-changing function that should be restricted."),
    "SOL-AM-ReentrancyAttack-2": ("poc_test", "A malicious callee re-enters during the external call and observes or exploits state that is updated only after the call."),
    "SOL-Basics-Math-4": ("invariant_fuzz", "Result of the reordered (multiply-then-divide) computation never differs from the contract's result by more than 1 unit."),
    "SOL-Basics-Math-5": ("invariant_fuzz", "Rounding in every deposit/withdraw/convert path never favors the user over the protocol."),
    "SOL-Basics-Math-6": ("invariant_fuzz", "No reachable input makes a denominator zero."),
    "SOL-Heuristics-3": ("invariant_fuzz", "Calling with src == dst (or caller == receiver) leaves total balances and the actor's balance unchanged."),
    "SOL-Heuristics-17": ("invariant_fuzz", "Splitting an amount into several smaller calls yields the same final state as one call with the total."),
    "SOL-Defi-General-4": ("poc_test", "A first depositor can inflate the share price so that a later depositor receives zero or too few shares."),
    "SOL-Basics-VI-SVI-4": ("poc_test", "Two different argument tuples of dynamic types produce the same abi.encodePacked hash."),
    "SOL-Basics-Payment-7": ("manual_only", "ETH sent to payable functions or force-fed can always be withdrawn."),
    "SOL-Basics-PU-9": ("manual_only", "Storage layout of the new implementation is append-only relative to the old one."),
    "SOL-Basics-PU-10": ("manual_only", "Storage layout of the new implementation is append-only relative to the old one."),
}

SLITHER_HINTS = {
    "SOL-AM-MA-1": ["timestamp"],
    "SOL-AM-MA-2": ["weak-prng"],
    "SOL-AM-ReentrancyAttack-2": ["reentrancy-eth", "reentrancy-no-eth"],
    "SOL-EC-13": ["reentrancy-eth", "reentrancy-no-eth"],
    "SOL-EC-1": ["reentrancy-eth", "reentrancy-no-eth"],
    "SOL-Basics-AC-7": ["tx-origin"],
    "SOL-Basics-AL-11": ["msg-value-loop"],
    "SOL-Basics-AL-12": ["calls-loop"],
    "SOL-Basics-AL-10": ["calls-loop"],
    "SOL-Basics-Math-4": ["divide-before-multiply"],
    "SOL-Basics-Payment-7": ["locked-ether"],
    "SOL-Basics-PU-5": ["unprotected-upgrade"],
    "SOL-Basics-Event-1": ["events-access", "events-maths"],
    "SOL-CR-5": ["events-access", "events-maths"],
    "SOL-Basics-Function-1": ["missing-zero-check"],
    "SOL-Basics-Inheritance-3": ["missing-inheritance"],
    "SOL-Heuristics-11": ["uninitialized-state", "uninitialized-local"],
    "SOL-EC-3": ["controlled-delegatecall"],
    "SOL-EC-10": ["controlled-delegatecall"],
    "SOL-EC-11": ["controlled-delegatecall"],
    "SOL-Token-FE-1": ["unchecked-transfer"],
    "SOL-Basics-Function-2": ["unused-return"],
    "SOL-Basics-VI-SVI-4": ["encode-packed-collision"],
    "SOL-Basics-VI-SVI-29": ["storage-array"],
    "SOL-Basics-VI-SVI-30": ["abiencoderv2-array"],
    "SOL-Basics-VI-SVI-41": ["multiple-constructors"],
}

NEEDS_REVIEW = {
    "SOL-Basics-AC-1": "Process question (enumerate actors) rather than a code-answerable check; consider rewording or marking as manual guidance.",
    "SOL-Basics-AC-6": "'Does the contract inherit others?' is not a vulnerability pattern by itself; unclear what finding it should produce.",
    "SOL-Basics-Function-6": "Too broad to answer from code; needs a concrete pattern (e.g. unvalidated user-supplied addresses or calldata).",
    "SOL-Basics-Inheritance-3": "Too broad; needs a concrete pattern (e.g. declared interface functions not implemented or with mismatched signatures).",
    "SOL-Basics-Math-1": "'Is the calculation accurate?' is not tied to a specific pattern; severity and verification are placeholders.",
    "SOL-CR-1": "Unclear what 'special conditions' means; needs a concrete scenario.",
    "SOL-EC-4": "Design question; not answerable as a yes/no finding.",
    "SOL-Defi-General-5": "Open-ended; needs the concrete risk (depeg handling) spelled out.",
    "SOL-Heuristics-1": "General heuristic, not a specific vulnerability pattern.",
    "SOL-Heuristics-2": "General heuristic, not a specific vulnerability pattern.",
    "SOL-Heuristics-6": "General heuristic, not a specific vulnerability pattern.",
    "SOL-Heuristics-8": "General heuristic, not a specific vulnerability pattern.",
    "SOL-Heuristics-9": "General heuristic, not a specific vulnerability pattern.",
    "SOL-Heuristics-13": "General heuristic, not a specific vulnerability pattern.",
    "SOL-Heuristics-16": "General heuristic, not a specific vulnerability pattern.",
    "SOL-Integrations-LayerZero-2": "Open-ended ('which mechanism?'); needs the concrete risk of blocking vs non-blocking receivers.",
    "SOL-McCc-2": "Open-ended; overlaps McCc-3/4/6/10/11. Consider merging.",
    "SOL-Token-NfE1-1": "Open-ended ('how are minting and transfer implemented?'); not a specific check.",
    "SOL-Basics-VI-SVI-4": "Filed under Solidity Version Issues but abi.encodePacked hash collision is not a compiler bug and is not version-specific; the '(version >= 0.8.17)' suffix refers to a docs version. vuln_category set to hash-merkle and no solc range applied.",
    "SOL-Basics-VI-OVI-1": "Linked advisory GHSA-g4vp-m682-qqmp (same affected range) describes `_msgSender` returning address(0) for short calldata from a trusted forwarder; the item's description is about `_msgData()` reverting. Confirm the description matches the advisory.",
    "SOL-Basics-VI-OVI-4": "No GHSA exists for this ERC777 issue; the only source is Snyk (ref/1-openzeppelin_bugs.json). Range <3.4.0-rc.0 not independently verified.",
    "SOL-Basics-VI-OVI-9": "Question states >=2.3.0 <4.7.2; GHSA-7grf-83vw-6f5x lists >=2.0.0 (contracts) and >=3.2.0 (contracts-upgradeable). applicability uses the GHSA ranges; question text left unchanged.",
    "SOL-Basics-VI-OVI-18": "Question contains a malformed range ('<4.3.1\\\\n<3.4.2'). applicability uses the GHSA ranges (>=3.3.0 <3.4.2 || >=4.0.0 <4.3.1); question text left unchanged to stay in sync with upstream.",
}

VULN_CATEGORY_OVERRIDES = {
    "SOL-Basics-VI-SVI-4": "hash-merkle",
}

# Solidity Version Issues item -> bugs.json `name`, plus features that the bug
# strictly requires (narrowing only where the construct is necessary).
SVI_BUGS = {
    1: "ABIEncoderV2PackedStorage", 2: "SkipEmptyStringLiteral", 3: "ConstantOptimizerSubtraction",
    5: "FullInlinerNonExpressionSplitArgumentEvaluationOrder", 6: "StorageWriteRemovalBeforeConditionalTermination",
    7: "AbiReencodingHeadOverflowWithStaticArrayCleanup", 8: "DirtyBytesArrayToStorage",
    9: "InlineAssemblyMemorySideEffects", 10: "NestedCalldataArrayAbiReencodingSizeValidation",
    11: "AbiEncodeCallLiteralAsFixedBytesBug", 12: "UserDefinedValueTypesBug", 13: "SignedImmutables",
    14: "ABIDecodeTwoDimensionalArrayMemory", 15: "KeccakCaching", 16: "EmptyByteArrayCopy",
    17: "DynamicArrayCleanup", 18: "IncorrectEventSignatureInLibraries", 19: "UsingForCalldata",
    20: "MissingEscapingInFormatting", 21: "ArraySliceDynamicallyEncodedBaseType",
    22: "ImplicitConstructorCallvalueCheck", 23: "MemoryArrayCreationOverflow",
    24: "YulOptimizerRedundantAssignmentBreakContinue", 25: "privateCanBeOverridden",
    26: "YulOptimizerRedundantAssignmentBreakContinue0.5", 27: "ABIEncoderV2LoopYulOptimizer",
    28: "ABIEncoderV2CalldataStructsWithStaticallySizedAndDynamicallyEncodedMembers",
    29: "SignedArrayStorageCopy", 30: "ABIEncoderV2StorageArrayWithMultiSlotElement",
    31: "DynamicConstructorArgumentsClippedABIV2", 32: "UninitializedFunctionPointerInConstructor",
    33: "UninitializedFunctionPointerInConstructor_0.4.x", 34: "IncorrectEventSignatureInLibraries_0.4.x",
    35: "ABIEncoderV2PackedStorage_0.4.x", 36: "IncorrectByteInstructionOptimization",
    37: "DoubleShiftSizeOverflow", 38: "ExpExponentCleanup", 39: "EventStructWrongData",
    40: "NestedArrayFunctionCallDecoder", 41: "OneOfTwoConstructorsSkipped", 42: "ZeroFunctionSelector",
    43: "DelegateCallReturnValue", 44: "ECRecoverMalformedInput", 45: "MissingSideEffectsOnSelectorAccess",
    46: "DataLocationChangeInInternalOverride", 47: "FreeFunctionRedefinition",
    48: "TupleAssignmentMultiStackSlotComponents",
}
SVI_FEATURES = {
    9: {"all_of": ["uses_assembly"]},
    15: {"all_of": ["uses_assembly"]},
    24: {"all_of": ["uses_assembly", "has_loops"]},
    26: {"all_of": ["has_loops"]},
    43: {"all_of": ["uses_delegatecall"]},
    44: {"all_of": ["verifies_signatures"]},
}

# bugs.json severity -> severity_prior (rounded up: a confirmed miscompilation is never informational).
BUG_SEVERITY = {
    "very low": "low", "low": "low", "low/medium": "medium", "medium": "medium",
    "medium/high": "high", "high": "high",
}
BUG_SETTING_KEYS = {
    "optimizer": "optimizer", "yulOptimizer": "yul_optimizer", "viaIR": "via_ir",
    "ABIEncoderV2": "abi_encoder_v2", "evmVersion": "evm_version",
}

# OpenZeppelin Version Issues item -> (GHSA ids, affected contract/library names).
OVI_ADVISORIES = {
    1: (["GHSA-g4vp-m682-qqmp"], ["inherits:ERC2771Context"]),
    2: (["GHSA-93hq-5wgc-jc82"], ["inherits:GovernorCompatibilityBravo"]),
    3: (["GHSA-4h98-2769-gh6h"], ["uses_library:ECDSA"]),
    4: ([], ["inherits:ERC777"]),
    5: (["GHSA-wprv-93r4-jj2p"], ["uses_library:MerkleProof"]),
    6: (["GHSA-5h3x-9wvq-w4m2"], ["inherits:Governor"]),
    7: (["GHSA-mx2q-35m2-x2rh"], ["inherits:TransparentUpgradeableProxy"]),
    8: (["GHSA-878m-3g6q-594q"], ["inherits:ERC721Consecutive"]),
    9: (["GHSA-7grf-83vw-6f5x"], ["uses_library:ERC165Checker"]),
    10: (["GHSA-9j3m-g383-29qr"], ["uses_library:LibArbitrumL2", "inherits:CrossChainEnabledArbitrumL2"]),
    11: (["GHSA-xrc4-737v-9q75"], ["inherits:GovernorVotesQuorumFraction"]),
    12: (["GHSA-4g63-c64m-25w9"], ["uses_library:SignatureChecker"]),
    13: (["GHSA-qh9x-gcfh-pcrw"], ["uses_library:ERC165Checker"]),
    14: (["GHSA-m6w8-fq7v-ph4m"], ["inherits:GovernorCompatibilityBravo"]),
    15: (["GHSA-9c22-pwxw-p6hx"], ["inherits:Initializable"]),
    16: (["GHSA-wmpv-c2jp-j2xg"], ["inherits:ERC1155Supply"]),
    17: (["GHSA-5vp3-v4hc-gx76", "GHSA-q4h9-46xg-m3x9"], ["inherits:UUPSUpgradeable"]),
    18: (["GHSA-fg47-3c2x-m2wr", "GHSA-vrw4-w73r-6mm8"], ["inherits:TimelockController"]),
}
OVI_SNYK_RANGES = {4: "<3.4.0-rc.0"}
GHSA_SEVERITY = {"LOW": "low", "MODERATE": "medium", "HIGH": "high", "CRITICAL": "critical"}
OZ_PACKAGES = ["@openzeppelin/contracts", "@openzeppelin/contracts-upgradeable"]


def reference_source(url: str) -> dict:
    if "solodit.xyz/issues/" in url:
        return {"type": "audit_report", "ref": url.rstrip("/").rsplit("/", 1)[-1][:120], "url": url}
    if "blog.soliditylang.org" in url:
        return {"type": "solidity_blog", "url": url}
    m = re.search(r"github\.com/advisories/(GHSA-[\w-]+)", url)
    if m:
        return {"type": "ghsa", "ref": m.group(1), "url": url}
    return {"type": "other", "url": url}


def add_source(sources: list, src: dict) -> None:
    if not any(s.get("url") == src["url"] for s in sources):
        sources.append(src)


def bug_applicability(bug: dict) -> dict:
    fixed = bug.get("fixed")
    intro = bug.get("introduced")
    if intro and fixed:
        solc = f">={intro} <{fixed}"
    elif fixed:
        solc = f"<{fixed}"
    else:
        solc = f">={intro}"
    appl = {"solc": solc}
    settings = {BUG_SETTING_KEYS[k]: v for k, v in (bug.get("conditions") or {}).items() if k in BUG_SETTING_KEYS}
    if settings:
        appl["compiler_settings"] = settings
    return appl


def check_bug_against_versions(bug: dict, appl: dict, bugs_by_version: dict) -> list[str]:
    """Versions matched by our solc range must equal the versions bugs_by_version lists."""
    listed = {v for v, info in bugs_by_version.items() if bug["name"] in info.get("bugs", [])}
    ours = {v for v in bugs_by_version if lib.satisfies(v, appl["solc"])}
    return sorted(listed ^ ours, key=lib.parse_version)


def osv_index(osv_dir: Path) -> dict:
    """GHSA id -> {severity, ranges: {package: range}}."""
    index: dict[str, dict] = {}
    for pkg, fname in zip(OZ_PACKAGES, ["oz-contracts.json", "oz-contracts-upgradeable.json"]):
        for vuln in lib.load_json(osv_dir / fname).get("vulns", []):
            entry = index.setdefault(vuln["id"], {"severity": None, "ranges": {}, "summary": vuln.get("summary", "")})
            entry["severity"] = (vuln.get("database_specific") or {}).get("severity") or entry["severity"]
            for aff in vuln.get("affected", []):
                if aff["package"]["name"] != pkg:
                    continue
                alts = []
                for rng in aff.get("ranges", []):
                    intro = fixed = None
                    for ev in rng["events"]:
                        intro = ev.get("introduced", intro)
                        fixed = ev.get("fixed", fixed)
                    lo = f">={intro} " if intro and intro != "0" else ""
                    alts.append(f"{lo}<{fixed}" if fixed else f">={intro}")
                if alts:
                    entry["ranges"][pkg] = " || ".join(sorted(alts, key=lambda a: lib.parse_version(re.findall(r"[\d.]+(?:-[\w.]+)?", a)[0])))
    return index


def upgradeable_variants(features: list[str]) -> list[str]:
    """OZ 4.x contracts-upgradeable suffixes names with `Upgradeable`."""
    out = []
    for f in features:
        out.append(f)
        prefix, _, name = f.partition(":")
        if prefix in ("inherits", "uses_library") and not name.endswith("Upgradeable") and name != "Initializable":
            out.append(f"{prefix}:{name}Upgradeable")
    return out


def tag_item(path: tuple[str, ...], item: dict, ctx: dict) -> dict:
    iid = item["id"]
    p = lib.path_str(path)
    severity, method, all_of = CATEGORY_DEFAULTS[p]
    notes = []
    status = "auto_tagged"

    vuln_category = VULN_CATEGORY_OVERRIDES.get(iid) or ctx["path_to_category"][p]
    applicability = dict(APPLICABILITY_OVERRIDES[iid]) if iid in APPLICABILITY_OVERRIDES else ({"all_of": list(all_of)} if all_of else {})
    severity = SEVERITY_OVERRIDES.get(iid, severity)
    prop = None
    if iid in VERIFICATION_OVERRIDES:
        method, prop = VERIFICATION_OVERRIDES[iid]

    sources = [{"type": "cyfrin", "ref": iid, "url": CYFRIN_URL}]
    for ref in item.get("references", []):
        add_source(sources, reference_source(ref))

    m = re.match(r"^SOL-Basics-VI-SVI-(\d+)$", iid)
    if m and int(m.group(1)) in SVI_BUGS:
        n = int(m.group(1))
        bug = ctx["bugs"][SVI_BUGS[n]]
        applicability = bug_applicability(bug)
        applicability.update(SVI_FEATURES.get(n, {}))
        if ctx["bugs_by_version"] is not None:
            diff = check_bug_against_versions(bug, applicability, ctx["bugs_by_version"])
            if diff:
                status = "needs_review"
                notes.append(f"solc range {applicability['solc']} disagrees with bugs_by_version.json on {', '.join(diff)}.")
        severity = BUG_SEVERITY[bug["severity"]]
        method = "manual_only"
        prop = "Deterministic: compiler version and settings match the range; then confirm the triggering construct is present."
        add_source(sources, {"type": "solidity_bugs_json", "ref": bug.get("uid", bug["name"]), "url": BUGS_JSON_URL})
        if bug.get("link"):
            add_source(sources, {"type": "solidity_blog", "url": bug["link"]})

    m = re.match(r"^SOL-Basics-VI-OVI-(\d+)$", iid)
    if m and int(m.group(1)) in OVI_ADVISORIES:
        n = int(m.group(1))
        ghsas, features = OVI_ADVISORIES[n]
        ranges: dict[str, list[str]] = {}
        sev = None
        for g in ghsas:
            adv = ctx["osv"].get(g)
            if adv is None:
                raise SystemExit(f"{iid}: {g} not found in OSV data")
            for pkg, rng in adv["ranges"].items():
                ranges.setdefault(pkg, []).append(rng)
            if adv["severity"]:
                cand = GHSA_SEVERITY[adv["severity"]]
                order = ["informational", "low", "medium", "high", "critical"]
                sev = cand if sev is None or order.index(cand) > order.index(sev) else sev
            add_source(sources, {"type": "ghsa", "ref": g, "url": GHSA_URL.format(g)})
        if n in OVI_SNYK_RANGES:
            ranges = {pkg: [OVI_SNYK_RANGES[n]] for pkg in OZ_PACKAGES}
            add_source(sources, {"type": "other", "ref": "snyk", "url": "https://security.snyk.io/package/npm/@openzeppelin%2Fcontracts"})
        deps = [{"package": pkg, "range": " || ".join(dict.fromkeys(rs))} for pkg, rs in sorted(ranges.items())]
        applicability = {"any_of": upgradeable_variants(features), "dependencies": deps}
        if sev:
            severity = sev
        method = "manual_only"
        prop = "Deterministic: installed OpenZeppelin version is in range; then confirm the affected contract or function is used."

    if iid in NEEDS_REVIEW:
        status = "needs_review"
        notes.insert(0, NEEDS_REVIEW[iid])

    tagged = dict(item)
    tagged["vuln_category"] = vuln_category
    tagged["severity_prior"] = severity
    tagged["applicability"] = applicability
    if iid in SLITHER_HINTS:
        tagged["detection_hint"] = {"slither": SLITHER_HINTS[iid]}
    tagged["verification"] = {"method": method, **({"property": prop} if prop else {})}
    tagged["provenance"] = {"sources": sources, "last_reviewed": ctx["date"]}
    tagged["review_status"] = status
    if notes:
        tagged["review_notes"] = " ".join(notes)
    return lib.order_item_fields(tagged)


def apply(data, ctx: dict, retag: bool) -> dict:
    counts = {"tagged": 0, "skipped": 0}

    def walk(nodes, path):
        for i, node in enumerate(nodes):
            if lib.is_item(node):
                status = node.get("review_status")
                if status == "human_reviewed" or (status and not retag):
                    counts["skipped"] += 1
                    continue
                nodes[i] = tag_item(path, node, ctx)
                counts["tagged"] += 1
            elif isinstance(node, dict) and isinstance(node.get("data"), list):
                walk(node["data"], path + (node["category"],))

    walk(data, ())
    return counts


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--checklist", default=str(lib.CHECKLIST_PATH))
    ap.add_argument("--solidity-bugs", required=True)
    ap.add_argument("--bugs-by-version")
    ap.add_argument("--osv-dir", required=True)
    ap.add_argument("--retag", action="store_true", help="recompute auto_tagged/needs_review items too")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    args = ap.parse_args(argv)

    vocab = lib.load_json(lib.VOCABULARY_PATH)
    path_to_category = {}
    for key, spec in vocab["vuln_categories"].items():
        if key.startswith("$"):
            continue
        for p in spec["source_paths"]:
            path_to_category[p] = key
    ctx = {
        "date": args.date,
        "path_to_category": path_to_category,
        "bugs": {b["name"]: b for b in lib.load_json(args.solidity_bugs)},
        "bugs_by_version": lib.load_json(args.bugs_by_version) if args.bugs_by_version else None,
        "osv": osv_index(Path(args.osv_dir)),
    }
    data = lib.load_json(args.checklist)
    counts = apply(data, ctx, args.retag)
    lib.dump_checklist(data, args.checklist)
    print(f"tagged {counts['tagged']} item(s), skipped {counts['skipped']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
