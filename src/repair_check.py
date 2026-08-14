#!/usr/bin/env python3
"""Dependency-free semantic checker for autonomous repair lifecycle v1."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = (ROOT / "examples").resolve()

SYNTAX = "REPAIR-SYNTAX-001"
AUTHORITY = "REPAIR-AUTHORITY-001"
SEPARATION = "REPAIR-SEPARATION-001"
SCOPE = "REPAIR-SCOPE-001"
STATE = "REPAIR-STATE-001"
CANDIDATE = "REPAIR-CANDIDATE-001"
VALIDATION = "REPAIR-VALIDATION-001"
PUBLICATION = "REPAIR-PUBLICATION-001"
READBACK = "REPAIR-READBACK-001"
ROLLBACK = "REPAIR-ROLLBACK-001"
RECEIPT = "REPAIR-RECEIPT-001"
SECRET = "REPAIR-SECRET-001"
PROFILE = "REPAIR-PROFILE-001"

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
PRINCIPAL_URI = re.compile(r"^repair://principal/[a-z0-9][a-z0-9._/-]*$")
TRANSITIONS = {
    "observed": {"diagnosed", "blocked", "abandoned"},
    "diagnosed": {"authorized", "blocked", "abandoned"},
    "authorized": {"repairing", "blocked", "abandoned"},
    "repairing": {"candidate", "blocked", "rolled-back"},
    "candidate": {"validating", "repairing", "blocked", "rolled-back"},
    "validating": {"publishing", "repairing", "blocked", "rolled-back"},
    "publishing": {"verifying", "repairing", "blocked", "rolled-back"},
    "verifying": {"resolved", "repairing", "blocked", "rolled-back"},
    "blocked": {"diagnosed", "authorized", "repairing", "abandoned"},
    "resolved": set(),
    "rolled-back": set(),
    "abandoned": set(),
}
PROFILE_MODES = {
    "observe": "observe-only",
    "diagnose": "analysis-only",
    "authorize": "protected-authority",
    "repair": "bounded-write",
    "validate": "candidate-read",
    "publish": "bounded-publish",
    "readback": "effect-read",
    "rollback": "bounded-rollback",
}
CASE_FIELDS = {
    "schema",
    "repairId",
    "correlationId",
    "problem",
    "authority",
    "scope",
    "lifecycle",
    "candidate",
    "validation",
    "publication",
    "readback",
    "rollback",
}


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    message: str
    severity: str = "critical"

    def render(self) -> str:
        return f"{self.code} {self.severity} {self.path}: {self.message}"


def _add(findings: list[Finding], code: str, path: str, message: str) -> None:
    findings.append(Finding(code, path, message))


def _closed(
    value: Any,
    path: str,
    required: set[str],
    allowed: set[str],
    findings: list[Finding],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        _add(findings, SYNTAX, path, "must be an object")
        return None
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
    if missing:
        _add(findings, SYNTAX, path, f"missing fields: {', '.join(missing)}")
    if unknown:
        _add(findings, SYNTAX, path, f"unknown fields: {', '.join(unknown)}")
    return value


def _time(value: Any, path: str, findings: list[Finding]) -> datetime | None:
    if not isinstance(value, str):
        _add(findings, SYNTAX, path, "RFC3339 timestamp required")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _add(findings, SYNTAX, path, "RFC3339 timestamp required")
        return None
    if parsed.tzinfo is None:
        _add(findings, SYNTAX, path, "timezone required")
        return None
    return parsed


def _digest(value: Any, path: str, findings: list[Finding], code: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        _add(findings, code, path, "exact SHA-256 digest required")


def _principal(value: Any, path: str, findings: list[Finding]) -> dict[str, Any] | None:
    principal = _closed(value, path, {"uri", "kind"}, {"uri", "kind"}, findings)
    if principal is None:
        return None
    uri = principal.get("uri")
    if not isinstance(uri, str) or not PRINCIPAL_URI.fullmatch(uri):
        _add(findings, SYNTAX, f"{path}/uri", "invalid repair principal URI")
    if principal.get("kind") not in {
        "observer",
        "authority",
        "implementer",
        "validator",
        "publisher",
        "service",
    }:
        _add(findings, SYNTAX, f"{path}/kind", "unknown repair principal kind")
    return principal


def _scan_secrets(value: Any, path: str, findings: list[Finding]) -> None:
    denied = ("token", "secret", "password", "credential", "privatekey", "apikey")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if any(part in normalized for part in denied):
                _add(findings, SECRET, f"{path}/{key}", "secret-bearing field is forbidden")
            _scan_secrets(nested, f"{path}/{key}", findings)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_secrets(nested, f"{path}/{index}", findings)
    elif isinstance(value, str) and re.search(r"(?i)\bbearer\s+[a-z0-9._-]+", value):
        _add(findings, SECRET, path, "credential-like value is forbidden")


def _receipt(
    value: Any,
    path: str,
    correlation_id: str,
    findings: list[Finding],
) -> tuple[dict[str, Any] | None, datetime | None]:
    fields = {"receiptId", "actor", "at", "correlationId", "subjectDigest"}
    receipt = _closed(value, path, fields, fields, findings)
    if receipt is None:
        return None, None
    receipt_id = receipt.get("receiptId")
    if not isinstance(receipt_id, str) or not receipt_id.startswith("repair://receipt/"):
        _add(findings, RECEIPT, f"{path}/receiptId", "invalid receipt URI")
    _principal(receipt.get("actor"), f"{path}/actor", findings)
    if receipt.get("correlationId") != correlation_id:
        _add(findings, RECEIPT, f"{path}/correlationId", "correlation mismatch")
    _digest(receipt.get("subjectDigest"), f"{path}/subjectDigest", findings, RECEIPT)
    return receipt, _time(receipt.get("at"), f"{path}/at", findings)


def _validate_problem(value: Any, findings: list[Finding]) -> dict[str, Any]:
    fields = {
        "diagnosticId", "sourceUri", "observationOnly", "observedAt", "componentUri",
        "symptomDigest", "evidenceDigests", "severity",
    }
    problem = _closed(value, "/problem", fields, fields, findings) or {}
    if problem.get("observationOnly") is not True:
        _add(findings, AUTHORITY, "/problem/observationOnly", "diagnosis must be observation-only")
    _time(problem.get("observedAt"), "/problem/observedAt", findings)
    _digest(problem.get("symptomDigest"), "/problem/symptomDigest", findings, SYNTAX)
    evidence = problem.get("evidenceDigests")
    if not isinstance(evidence, list) or not evidence:
        _add(findings, SYNTAX, "/problem/evidenceDigests", "evidence is required")
    else:
        for index, digest in enumerate(evidence):
            _digest(digest, f"/problem/evidenceDigests/{index}", findings, SYNTAX)
    return problem


def _validate_authority(
    value: Any, findings: list[Finding]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    fields = {
        "grantDigest", "policyDigest", "requestedEffect", "componentOwner",
        "implementer", "validator", "publisher",
    }
    authority = _closed(value, "/authority", fields, fields, findings) or {}
    _digest(authority.get("grantDigest"), "/authority/grantDigest", findings, AUTHORITY)
    _digest(authority.get("policyDigest"), "/authority/policyDigest", findings, AUTHORITY)
    if authority.get("requestedEffect") != "repair.apply":
        _add(findings, AUTHORITY, "/authority/requestedEffect", "bounded repair effect required")
    principals: dict[str, dict[str, Any]] = {}
    expected_kinds = {
        "componentOwner": "authority",
        "implementer": "implementer",
        "validator": "validator",
        "publisher": "publisher",
    }
    for role, expected_kind in expected_kinds.items():
        principal = _principal(authority.get(role), f"/authority/{role}", findings) or {}
        principals[role] = principal
        if principal.get("kind") != expected_kind:
            code = AUTHORITY if role == "componentOwner" else SEPARATION
            _add(findings, code, f"/authority/{role}", f"{expected_kind} principal required")
    uris = [principal.get("uri") for principal in principals.values() if principal.get("uri")]
    if len(uris) != len(set(uris)):
        _add(
            findings,
            SEPARATION,
            "/authority",
            "authority, implementer, validator and publisher must differ",
        )
    return authority, principals


def _safe_path(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value not in {"*", "**", "/"}
        and not value.startswith("/")
        and ".." not in Path(value).parts
        and not value.startswith("~")
    )


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    return path == pattern


def _validate_scope(value: Any, findings: list[Finding]) -> dict[str, Any]:
    fields = {
        "repository", "baseSha", "allowedPaths", "forbiddenPaths", "maxFiles",
        "maxAttempts", "rollbackRequired",
    }
    scope = _closed(value, "/scope", fields, fields, findings) or {}
    if not isinstance(scope.get("baseSha"), str) or not SHA.fullmatch(scope["baseSha"]):
        _add(findings, SCOPE, "/scope/baseSha", "exact base SHA required")
    for field in ("allowedPaths", "forbiddenPaths"):
        paths = scope.get(field)
        if not isinstance(paths, list) or not paths:
            _add(findings, SCOPE, f"/scope/{field}", "non-empty path array required")
        elif len(paths) != len(set(paths)) or not all(_safe_path(path) for path in paths):
            _add(findings, SCOPE, f"/scope/{field}", "unsafe or duplicate path")
    for field, maximum in (("maxFiles", 100), ("maxAttempts", 20)):
        count = scope.get(field)
        if not isinstance(count, int) or not 1 <= count <= maximum:
            _add(findings, SCOPE, f"/scope/{field}", f"must be between 1 and {maximum}")
    if scope.get("rollbackRequired") is not True:
        _add(findings, ROLLBACK, "/scope/rollbackRequired", "rollback plan is mandatory")
    return scope


def _validate_history(
    value: Any,
    current_state: Any,
    correlation_id: str,
    principals: dict[str, dict[str, Any]],
    findings: list[Finding],
) -> None:
    if not isinstance(value, list) or not value:
        _add(findings, STATE, "/lifecycle/history", "non-empty history required")
        return
    expected_actor = {
        "authorized": principals.get("componentOwner", {}).get("uri"),
        "repairing": principals.get("implementer", {}).get("uri"),
        "candidate": principals.get("implementer", {}).get("uri"),
        "validating": principals.get("validator", {}).get("uri"),
        "publishing": principals.get("validator", {}).get("uri"),
        "verifying": principals.get("publisher", {}).get("uri"),
    }
    previous: str | None = None
    last_time: datetime | None = None
    receipt_ids: set[str] = set()
    fields = {"from", "to", "receipt"}
    for index, item in enumerate(value):
        path = f"/lifecycle/history/{index}"
        event = _closed(item, path, fields, fields, findings)
        if event is None:
            continue
        source, target = event.get("from"), event.get("to")
        valid = index == 0 and source is None and target == "observed"
        if not valid:
            valid = source == previous and target in TRANSITIONS.get(str(source), set())
        if not valid:
            _add(findings, STATE, path, f"invalid transition {source!r} -> {target!r}")
        receipt, timestamp = _receipt(
            event.get("receipt"), f"{path}/receipt", correlation_id, findings
        )
        if receipt:
            receipt_id = str(receipt.get("receiptId"))
            if receipt_id in receipt_ids:
                _add(findings, RECEIPT, f"{path}/receipt/receiptId", "receipt replay")
            receipt_ids.add(receipt_id)
            required_actor = expected_actor.get(str(target))
            actor_uri = (receipt.get("actor") or {}).get("uri")
            if required_actor and actor_uri != required_actor:
                _add(findings, SEPARATION, f"{path}/receipt/actor", "wrong transition actor")
        if last_time and timestamp and timestamp < last_time:
            _add(findings, STATE, f"{path}/receipt/at", "history time must be monotonic")
        if timestamp:
            last_time = timestamp
        previous = target if isinstance(target, str) else previous
    if previous != current_state:
        _add(findings, STATE, "/lifecycle/state", "state must match last transition")


def _validate_candidate(
    value: Any, scope: dict[str, Any], findings: list[Finding]
) -> dict[str, Any] | None:
    if value is None:
        return None
    fields = {"headSha", "changeDigest", "changedPaths", "worktreeReceiptDigest", "checks"}
    candidate = _closed(value, "/candidate", fields, fields, findings)
    if candidate is None:
        return None
    if not isinstance(candidate.get("headSha"), str) or not SHA.fullmatch(candidate["headSha"]):
        _add(findings, CANDIDATE, "/candidate/headSha", "exact candidate SHA required")
    for field in ("changeDigest", "worktreeReceiptDigest"):
        _digest(candidate.get(field), f"/candidate/{field}", findings, CANDIDATE)
    paths = candidate.get("changedPaths")
    allowed = scope.get("allowedPaths") or []
    forbidden = scope.get("forbiddenPaths") or []
    if not isinstance(paths, list) or not paths:
        _add(findings, CANDIDATE, "/candidate/changedPaths", "changed paths required")
    else:
        if len(paths) > int(scope.get("maxFiles") or 0):
            _add(findings, SCOPE, "/candidate/changedPaths", "file budget exceeded")
        for index, path in enumerate(paths):
            if not _safe_path(path):
                _add(findings, SCOPE, f"/candidate/changedPaths/{index}", "unsafe path")
            elif not any(_matches(path, pattern) for pattern in allowed):
                _add(findings, SCOPE, f"/candidate/changedPaths/{index}", "path is outside scope")
            elif any(_matches(path, pattern) for pattern in forbidden):
                _add(findings, SCOPE, f"/candidate/changedPaths/{index}", "path is forbidden")
    checks = candidate.get("checks")
    if not isinstance(checks, list) or not checks:
        _add(findings, CANDIDATE, "/candidate/checks", "candidate checks required")
    else:
        names: set[str] = set()
        fields = {"name", "conclusion", "profileDigest", "evidenceDigest"}
        for index, item in enumerate(checks):
            path = f"/candidate/checks/{index}"
            check = _closed(item, path, fields, fields, findings)
            if check:
                name = check.get("name")
                if name in names:
                    _add(findings, CANDIDATE, f"{path}/name", "duplicate check")
                names.add(str(name))
                if check.get("conclusion") != "success":
                    _add(findings, CANDIDATE, f"{path}/conclusion", "all checks must succeed")
                _digest(check.get("profileDigest"), f"{path}/profileDigest", findings, CANDIDATE)
                _digest(check.get("evidenceDigest"), f"{path}/evidenceDigest", findings, CANDIDATE)
    return candidate


def _validate_case(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    case = _closed(document, "", CASE_FIELDS, CASE_FIELDS, findings)
    if case is None:
        return findings
    correlation_id = str(case.get("correlationId") or "")
    _validate_problem(case.get("problem"), findings)
    _, principals = _validate_authority(case.get("authority"), findings)
    scope = _validate_scope(case.get("scope"), findings)

    lifecycle = _closed(
        case.get("lifecycle"),
        "/lifecycle",
        {"state", "attempt", "history"},
        {"state", "attempt", "history"},
        findings,
    ) or {}
    state = lifecycle.get("state")
    attempt = lifecycle.get("attempt")
    if state not in TRANSITIONS:
        _add(findings, STATE, "/lifecycle/state", "unknown repair state")
    if not isinstance(attempt, int) or not 1 <= attempt <= int(scope.get("maxAttempts") or 0):
        _add(findings, SCOPE, "/lifecycle/attempt", "attempt budget exceeded")
    _validate_history(lifecycle.get("history"), state, correlation_id, principals, findings)

    candidate = _validate_candidate(case.get("candidate"), scope, findings)
    validation = case.get("validation")
    if validation is not None:
        fields = {"validator", "candidateSha", "outcome", "evidenceDigest", "attestedAt"}
        validation = _closed(validation, "/validation", fields, fields, findings)
        if validation:
            validator = (
                _principal(validation.get("validator"), "/validation/validator", findings)
                or {}
            )
            if validator.get("uri") != principals.get("validator", {}).get("uri"):
                _add(findings, VALIDATION, "/validation/validator", "wrong validator principal")
            if not candidate or validation.get("candidateSha") != candidate.get("headSha"):
                _add(findings, VALIDATION, "/validation/candidateSha", "candidate SHA mismatch")
            _digest(
                validation.get("evidenceDigest"),
                "/validation/evidenceDigest",
                findings,
                VALIDATION,
            )
            _time(validation.get("attestedAt"), "/validation/attestedAt", findings)

    publication = case.get("publication")
    if publication is not None:
        fields = {"publisher", "candidateSha", "status", "mergeSha", "receipt"}
        publication = _closed(publication, "/publication", fields, fields, findings)
        if publication:
            publisher = (
                _principal(publication.get("publisher"), "/publication/publisher", findings)
                or {}
            )
            if publisher.get("uri") != principals.get("publisher", {}).get("uri"):
                _add(findings, PUBLICATION, "/publication/publisher", "wrong publisher principal")
            if not candidate or publication.get("candidateSha") != candidate.get("headSha"):
                _add(findings, PUBLICATION, "/publication/candidateSha", "candidate SHA mismatch")
            if publication.get("status") == "merged":
                merge_sha = publication.get("mergeSha")
                if not isinstance(merge_sha, str) or not SHA.fullmatch(merge_sha):
                    _add(findings, PUBLICATION, "/publication/mergeSha", "merge SHA required")
            receipt, _ = _receipt(
                publication.get("receipt"), "/publication/receipt", correlation_id, findings
            )
            if receipt and (receipt.get("actor") or {}).get("uri") != publisher.get("uri"):
                _add(
                    findings,
                    PUBLICATION,
                    "/publication/receipt/actor",
                    "publisher receipt required",
                )

    readback = case.get("readback")
    if readback is not None:
        fields = {"observer", "integratedSha", "effectConfirmed", "evidenceDigest", "observedAt"}
        readback = _closed(readback, "/readback", fields, fields, findings)
        if readback:
            observer = _principal(readback.get("observer"), "/readback/observer", findings) or {}
            forbidden_observers = {
                principals.get("implementer", {}).get("uri"),
                principals.get("publisher", {}).get("uri"),
            }
            if observer.get("kind") != "observer" or observer.get("uri") in forbidden_observers:
                _add(findings, READBACK, "/readback/observer", "independent observer required")
            _digest(readback.get("evidenceDigest"), "/readback/evidenceDigest", findings, READBACK)
            _time(readback.get("observedAt"), "/readback/observedAt", findings)

    rollback = _closed(
        case.get("rollback"),
        "/rollback",
        {"planDigest", "status", "receipt"},
        {"planDigest", "status", "receipt"},
        findings,
    ) or {}
    _digest(rollback.get("planDigest"), "/rollback/planDigest", findings, ROLLBACK)
    if rollback.get("receipt") is not None:
        _receipt(rollback.get("receipt"), "/rollback/receipt", correlation_id, findings)
    if state == "rolled-back" and (
        rollback.get("status") != "executed" or rollback.get("receipt") is None
    ):
        _add(findings, ROLLBACK, "/rollback", "rolled-back state requires executed receipt")

    candidate_states = {"candidate", "validating", "publishing", "verifying", "resolved"}
    if state in candidate_states and not candidate:
        _add(findings, CANDIDATE, "/candidate", "state requires a candidate")
    if state in {"publishing", "verifying", "resolved"}:
        if not validation or validation.get("outcome") != "approved":
            _add(findings, VALIDATION, "/validation", "state requires approved validation")
    if state in {"verifying", "resolved"}:
        if not publication or publication.get("status") != "merged":
            _add(findings, PUBLICATION, "/publication", "state requires merged publication")
    if state == "resolved":
        if not readback or readback.get("effectConfirmed") is not True:
            _add(findings, READBACK, "/readback", "resolved requires confirmed effect")
        elif not publication or readback.get("integratedSha") != publication.get("mergeSha"):
            _add(findings, READBACK, "/readback/integratedSha", "integrated SHA mismatch")
    _scan_secrets(case, "", findings)
    return findings


def _validate_profile(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    fields = {"schema", "profileId", "version", "ownership", "bindings"}
    profile = _closed(document, "", fields, fields, findings)
    if profile is None:
        return findings
    ownership = _closed(
        profile.get("ownership"),
        "/ownership",
        {"standardOwner", "runtimeOwner", "adopts"},
        {"standardOwner", "runtimeOwner", "adopts"},
        findings,
    ) or {}
    if ownership.get("standardOwner") != "wellmanifest/repair-lifecycle":
        _add(findings, PROFILE, "/ownership/standardOwner", "wrong standard owner")
    runtime_owner = ownership.get("runtimeOwner")
    if not isinstance(runtime_owner, str) or runtime_owner.startswith("wellmanifest/"):
        _add(findings, PROFILE, "/ownership/runtimeOwner", "runtime must remain external")
    adopts = ownership.get("adopts")
    if not isinstance(adopts, list) or "wellmanifest/autonomy" not in adopts:
        _add(findings, PROFILE, "/ownership/adopts", "autonomy adoption required")
    bindings = profile.get("bindings")
    if not isinstance(bindings, list):
        _add(findings, SYNTAX, "/bindings", "binding array required")
        return findings
    observed: dict[str, str] = {}
    principals: dict[str, str] = {}
    for index, item in enumerate(bindings):
        path = f"/bindings/{index}"
        fields = {"stage", "uri", "principal", "mode"}
        binding = _closed(item, path, fields, fields, findings)
        if binding:
            stage = str(binding.get("stage"))
            if stage in observed:
                _add(findings, PROFILE, f"{path}/stage", "duplicate stage")
            observed[stage] = str(binding.get("mode"))
            principal = _principal(binding.get("principal"), f"{path}/principal", findings) or {}
            principals[stage] = str(principal.get("uri"))
    if observed != PROFILE_MODES:
        _add(findings, PROFILE, "/bindings", "exact stage and mode mapping required")
    critical = [principals.get(stage) for stage in ("authorize", "repair", "validate", "publish")]
    if len(critical) != len(set(critical)):
        _add(findings, PROFILE, "/bindings", "authority, repair, validator and publisher differ")
    if principals.get("readback") in {principals.get("repair"), principals.get("publish")}:
        _add(findings, PROFILE, "/bindings", "read-back must be independent")
    _scan_secrets(profile, "", findings)
    return findings


def validate_document(document: Any) -> list[Finding]:
    if not isinstance(document, dict):
        return [Finding(SYNTAX, "", "document must be an object")]
    if document.get("schema") == "wellmanifest.repair/case/v1":
        return _validate_case(document)
    if document.get("schema") == "wellmanifest.repair/profile/v1":
        return _validate_profile(document)
    return [Finding(SYNTAX, "/schema", "unsupported repair schema")]


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not pointer.startswith("/"):
        raise ValueError("absolute JSON Pointer required")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def apply_invalid_case(case: dict[str, Any], case_path: Path) -> tuple[Any, list[Finding]]:
    try:
        base = (case_path.parent / str(case["base"])).resolve()
        base.relative_to(EXAMPLES)
    except (KeyError, ValueError):
        return {}, [Finding(SYNTAX, "/base", "base escapes examples root")]
    try:
        document = copy.deepcopy(json.loads(base.read_text(encoding="utf-8")))
        for mutation in case.get("mutations", []):
            parent, key = _pointer_parent(document, mutation["path"])
            if mutation["op"] == "replace":
                if isinstance(parent, list):
                    parent[int(key)] = mutation["value"]
                else:
                    parent[key] = mutation["value"]
            elif mutation["op"] == "remove":
                if isinstance(parent, list):
                    parent.pop(int(key))
                else:
                    del parent[key]
            else:
                raise ValueError("unsupported mutation")
    except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        return {}, [Finding(SYNTAX, "/mutations", f"invalid case: {error}")]
    return document, []


def load_and_validate(path: Path) -> list[Finding]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding(SYNTAX, "", str(error))]
    prefix: list[Finding] = []
    if (
        isinstance(document, dict)
        and document.get("schema") == "wellmanifest.repair/invalid-case/v1"
    ):
        document, prefix = apply_invalid_case(document, path.resolve())
    return prefix + validate_document(document)


def self_test() -> int:
    failures: list[str] = []
    for path in sorted((EXAMPLES / "valid").glob("*.json")):
        findings = load_and_validate(path)
        if findings:
            failures.append(f"{path.name}: {[item.code for item in findings]}")
    profile_findings = load_and_validate(ROOT / "profiles" / "subactor-semcod.profile.json")
    if profile_findings:
        failures.append(f"profile: {[item.code for item in profile_findings]}")
    for path in sorted((EXAMPLES / "invalid").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        observed = {item.code for item in load_and_validate(path)}
        expected = set(case.get("expectedCodes", []))
        if not expected <= observed:
            failures.append(f"{path.name}: expected {sorted(expected)}, got {sorted(observed)}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("REPAIR-PASS: valid fixtures and declared negative findings passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("path", type=Path)
    subparsers.add_parser("self-test")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return self_test()
    paths = sorted(args.path.rglob("*.json")) if args.path.is_dir() else [args.path]
    failed = False
    for path in paths:
        findings = load_and_validate(path)
        for finding in findings:
            print(f"{path}: {finding.render()}")
        failed = failed or bool(findings)
    if not failed:
        print(f"REPAIR-PASS: {len(paths)} document(s) conform")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
