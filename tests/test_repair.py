from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repair_check", ROOT / "src" / "repair_check.py")
assert SPEC and SPEC.loader
repair_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = repair_check
SPEC.loader.exec_module(repair_check)


class RepairConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.valid_path = ROOT / "examples" / "valid" / "subactor-resolved-repair.json"
        cls.valid = json.loads(cls.valid_path.read_text(encoding="utf-8"))
        cls.profile = json.loads(
            (ROOT / "profiles" / "subactor-semcod.profile.json").read_text(encoding="utf-8")
        )

    def codes(self, document: dict) -> set[str]:
        return {finding.code for finding in repair_check.validate_document(document)}

    def test_valid_case_and_profile_pass(self) -> None:
        self.assertEqual(set(), self.codes(self.valid))
        self.assertEqual(set(), self.codes(self.profile))

    def test_invalid_fixtures_emit_declared_codes(self) -> None:
        for path in sorted((ROOT / "examples" / "invalid").glob("*.json")):
            case = json.loads(path.read_text(encoding="utf-8"))
            observed = {finding.code for finding in repair_check.load_and_validate(path)}
            self.assertLessEqual(set(case["expectedCodes"]), observed, path.name)

    def test_diagnosis_must_remain_observation_only(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["problem"]["observationOnly"] = False
        self.assertIn(repair_check.AUTHORITY, self.codes(mutation))

    def test_repair_requires_separate_authority_grant(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["authority"]["grantDigest"] = "diagnostic-output"
        self.assertIn(repair_check.AUTHORITY, self.codes(mutation))

    def test_critical_principals_must_be_distinct(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["authority"]["validator"] = mutation["authority"]["implementer"]
        self.assertIn(repair_check.SEPARATION, self.codes(mutation))

    def test_candidate_paths_must_be_bounded(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["candidate"]["changedPaths"].append(".github/workflows/release.yml")
        self.assertIn(repair_check.SCOPE, self.codes(mutation))

    def test_file_and_attempt_budgets_are_enforced(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["maxFiles"] = 1
        self.assertIn(repair_check.SCOPE, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["lifecycle"]["attempt"] = 4
        self.assertIn(repair_check.SCOPE, self.codes(mutation))

    def test_candidate_checks_cannot_be_skipped(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["candidate"]["checks"][0]["conclusion"] = "skipped"
        self.assertIn(repair_check.CANDIDATE, self.codes(mutation))

    def test_validation_must_bind_exact_candidate(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["validation"]["candidateSha"] = "f" * 40
        self.assertIn(repair_check.VALIDATION, self.codes(mutation))

    def test_publication_must_bind_exact_candidate_and_publisher(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["publication"]["candidateSha"] = "f" * 40
        self.assertIn(repair_check.PUBLICATION, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["publication"]["publisher"] = mutation["authority"]["implementer"]
        self.assertIn(repair_check.PUBLICATION, self.codes(mutation))

    def test_resolved_requires_approved_validation_and_merge(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["validation"]["outcome"] = "rejected"
        self.assertIn(repair_check.VALIDATION, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["publication"]["status"] = "failed"
        self.assertIn(repair_check.PUBLICATION, self.codes(mutation))

    def test_resolved_requires_confirmed_exact_readback(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["readback"]["effectConfirmed"] = False
        self.assertIn(repair_check.READBACK, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["readback"]["integratedSha"] = "f" * 40
        self.assertIn(repair_check.READBACK, self.codes(mutation))

    def test_lifecycle_history_is_contiguous_and_receipts_are_unique(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["lifecycle"]["history"][2]["from"] = "observed"
        self.assertIn(repair_check.STATE, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        first = mutation["lifecycle"]["history"][0]["receipt"]["receiptId"]
        mutation["lifecycle"]["history"][1]["receipt"]["receiptId"] = first
        self.assertIn(repair_check.RECEIPT, self.codes(mutation))

    def test_rollback_terminal_state_requires_receipt(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["lifecycle"]["state"] = "rolled-back"
        mutation["lifecycle"]["history"][-1]["to"] = "rolled-back"
        self.assertIn(repair_check.ROLLBACK, self.codes(mutation))

    def test_unknown_and_secret_fields_fail_closed(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["authority"]["token"] = "Bearer example"
        codes = self.codes(mutation)
        self.assertIn(repair_check.SYNTAX, codes)
        self.assertIn(repair_check.SECRET, codes)

    def test_profile_enforces_exact_modes_and_separation(self) -> None:
        mutation = copy.deepcopy(self.profile)
        validate = next(item for item in mutation["bindings"] if item["stage"] == "validate")
        repair = next(item for item in mutation["bindings"] if item["stage"] == "repair")
        validate["principal"] = repair["principal"]
        self.assertIn(repair_check.PROFILE, self.codes(mutation))

    def test_schema_is_closed_draft_2020_12(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "repair-lifecycle.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        for name in (
            "case", "profile", "principal", "receipt", "problem", "authority", "scope",
            "transition", "lifecycle", "check", "candidate", "validation", "publication",
            "readback", "rollback", "binding",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
