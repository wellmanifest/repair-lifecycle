"""Semantic case validators for autonomous repair lifecycle v1."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import repair_primitives as rp
from repair_primitives import (
    Finding,
    _add,
    _closed,
    _digest,
    _is_int,
    _matches,
    _principal,
    _receipt,
    _safe_path,
    _scan_secrets,
    _time,
    _validate_profile,
)


def _validate_problem(value: Any, findings: list[Finding]) -> dict[str, Any]:
    fields = {
        "diagnosticId", "sourceUri", "observationOnly", "observedAt", "componentUri",
        "symptomDigest", "evidenceDigests", "severity",
    }
    problem = _closed(value, "/problem", fields, fields, findings) or {}
    diag_id = problem.get("diagnosticId")
    if not isinstance(diag_id, str) or not rp.DIAGNOSTIC_ID_RE.fullmatch(diag_id):
        _add(findings, rp.SYNTAX, "/problem/diagnosticId", "invalid diagnostic URI")
    source_uri = problem.get("sourceUri")
    if not isinstance(source_uri, str) or not rp.PROCESS_URI_RE.fullmatch(source_uri):
        _add(findings, rp.SYNTAX, "/problem/sourceUri", "invalid source process URI")
    component_uri = problem.get("componentUri")
    if not isinstance(component_uri, str) or not rp.COMPONENT_URI_RE.fullmatch(component_uri):
        _add(findings, rp.SYNTAX, "/problem/componentUri", "invalid component URI")
    if problem.get("observationOnly") is not True:
        _add(
            findings,
            rp.AUTHORITY,
            "/problem/observationOnly",
            "diagnosis must be observation-only",
        )
    _time(problem.get("observedAt"), "/problem/observedAt", findings)
    _digest(problem.get("symptomDigest"), "/problem/symptomDigest", findings, rp.SYNTAX)
    evidence = problem.get("evidenceDigests")
    if not isinstance(evidence, list) or not evidence:
        _add(findings, rp.SYNTAX, "/problem/evidenceDigests", "evidence is required")
    else:
        seen_evidence: set[str] = set()
        for index, digest in enumerate(evidence):
            _digest(digest, f"/problem/evidenceDigests/{index}", findings, rp.SYNTAX)
            if isinstance(digest, str):
                if digest in seen_evidence:
                    _add(
                        findings,
                        rp.SYNTAX,
                        f"/problem/evidenceDigests/{index}",
                        "duplicate digest",
                    )
                seen_evidence.add(digest)
    if problem.get("severity") not in {"low", "medium", "high", "critical"}:
        _add(findings, rp.SYNTAX, "/problem/severity", "unknown problem severity")
    return problem


def _validate_authority(
    value: Any, findings: list[Finding]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    fields = {
        "grantDigest", "policyDigest", "requestedEffect", "componentOwner",
        "implementer", "validator", "publisher",
    }
    authority = _closed(value, "/authority", fields, fields, findings) or {}
    _digest(authority.get("grantDigest"), "/authority/grantDigest", findings, rp.AUTHORITY)
    _digest(authority.get("policyDigest"), "/authority/policyDigest", findings, rp.AUTHORITY)
    if authority.get("requestedEffect") != "repair.apply":
        _add(findings, rp.AUTHORITY, "/authority/requestedEffect", "bounded repair effect required")
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
            code = rp.AUTHORITY if role == "componentOwner" else rp.SEPARATION
            _add(findings, code, f"/authority/{role}", f"{expected_kind} principal required")
    uris = [principal.get("uri") for principal in principals.values() if principal.get("uri")]
    if len(uris) != len(set(uris)):
        _add(
            findings,
            rp.SEPARATION,
            "/authority",
            "authority, implementer, validator and publisher must differ",
        )
    return authority, principals


def _validate_scope(value: Any, findings: list[Finding]) -> dict[str, Any]:
    fields = {
        "repository", "baseSha", "allowedPaths", "forbiddenPaths", "maxFiles",
        "maxAttempts", "rollbackRequired",
    }
    scope = _closed(value, "/scope", fields, fields, findings) or {}
    repo = scope.get("repository")
    if not isinstance(repo, str) or not rp.REPO_RE.fullmatch(repo):
        _add(findings, rp.SCOPE, "/scope/repository", "invalid repository slug")
    if not isinstance(scope.get("baseSha"), str) or not rp.SHA.fullmatch(scope["baseSha"]):
        _add(findings, rp.SCOPE, "/scope/baseSha", "exact base SHA required")
    for field in ("allowedPaths", "forbiddenPaths"):
        paths = scope.get(field)
        if not isinstance(paths, list) or not paths:
            _add(findings, rp.SCOPE, f"/scope/{field}", "non-empty path array required")
        elif not all(_safe_path(path) for path in paths) or len(paths) != len(set(paths)):
            _add(findings, rp.SCOPE, f"/scope/{field}", "unsafe or duplicate path")
    for field, maximum in (("maxFiles", 100), ("maxAttempts", 20)):
        count = scope.get(field)
        if not _is_int(count) or not 1 <= count <= maximum:
            _add(findings, rp.SCOPE, f"/scope/{field}", f"must be between 1 and {maximum}")
    if scope.get("rollbackRequired") is not True:
        _add(findings, rp.ROLLBACK, "/scope/rollbackRequired", "rollback plan is mandatory")
    return scope


def _validate_history(
    value: Any,
    current_state: Any,
    correlation_id: str,
    principals: dict[str, dict[str, Any]],
    findings: list[Finding],
) -> None:
    if not isinstance(value, list) or not value:
        _add(findings, rp.STATE, "/lifecycle/history", "non-empty history required")
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
            valid = (
                isinstance(source, str)
                and isinstance(target, str)
                and source == previous
                and target in rp.TRANSITIONS.get(source, set())
            )
        if not valid:
            _add(findings, rp.STATE, path, f"invalid transition {source!r} -> {target!r}")
        receipt, timestamp = _receipt(
            event.get("receipt"), f"{path}/receipt", correlation_id, findings
        )
        if receipt:
            receipt_id = str(receipt.get("receiptId"))
            if receipt_id in receipt_ids:
                _add(findings, rp.RECEIPT, f"{path}/receipt/receiptId", "receipt replay")
            receipt_ids.add(receipt_id)
            required_actor = expected_actor.get(str(target))
            actor_uri = (receipt.get("actor") or {}).get("uri")
            if required_actor and actor_uri != required_actor:
                _add(findings, rp.SEPARATION, f"{path}/receipt/actor", "wrong transition actor")
        if last_time and timestamp and timestamp < last_time:
            _add(findings, rp.STATE, f"{path}/receipt/at", "history time must be monotonic")
        if timestamp:
            last_time = timestamp
        previous = target if isinstance(target, str) else previous
    if previous != current_state:
        _add(findings, rp.STATE, "/lifecycle/state", "state must match last transition")


def _validate_candidate(
    value: Any, scope: dict[str, Any], findings: list[Finding]
) -> dict[str, Any] | None:
    if value is None:
        return None
    fields = {
        "headSha", "changeDigest", "changedPaths", "worktreeReceiptDigest",
        "environment", "checks",
    }
    candidate = _closed(value, "/candidate", fields, fields, findings)
    if candidate is None:
        return None
    if not isinstance(candidate.get("headSha"), str) or not rp.SHA.fullmatch(candidate["headSha"]):
        _add(findings, rp.CANDIDATE, "/candidate/headSha", "exact candidate SHA required")
    for field in ("changeDigest", "worktreeReceiptDigest"):
        _digest(candidate.get(field), f"/candidate/{field}", findings, rp.CANDIDATE)
    paths = candidate.get("changedPaths")
    raw_allowed = scope.get("allowedPaths")
    raw_forbidden = scope.get("forbiddenPaths")
    allowed = [p for p in raw_allowed if _safe_path(p)] if isinstance(raw_allowed, list) else []
    forbidden = (
        [p for p in raw_forbidden if _safe_path(p)] if isinstance(raw_forbidden, list) else []
    )
    max_files = scope.get("maxFiles")
    if not isinstance(paths, list) or not paths:
        _add(findings, rp.CANDIDATE, "/candidate/changedPaths", "changed paths required")
    else:
        if _is_int(max_files) and len(paths) > max_files:
            _add(findings, rp.SCOPE, "/candidate/changedPaths", "file budget exceeded")
        seen_paths: set[str] = set()
        for index, path in enumerate(paths):
            item_path = f"/candidate/changedPaths/{index}"
            if not _safe_path(path):
                _add(findings, rp.SCOPE, item_path, "unsafe path")
            else:
                if path in seen_paths:
                    _add(findings, rp.CANDIDATE, item_path, "duplicate path")
                seen_paths.add(path)
                if not any(_matches(path, pattern) for pattern in allowed):
                    _add(findings, rp.SCOPE, item_path, "path outside scope")
                elif any(_matches(path, pattern) for pattern in forbidden):
                    _add(findings, rp.SCOPE, item_path, "path is forbidden")

    env_fields = {"profileDigest", "dependencyDigest", "setupEvidenceDigest", "ready"}
    environment = _closed(
        candidate.get("environment"), "/candidate/environment", env_fields, env_fields, findings
    ) or {}
    for field in ("profileDigest", "dependencyDigest", "setupEvidenceDigest"):
        _digest(environment.get(field), f"/candidate/environment/{field}", findings, rp.ENVIRONMENT)
    if environment.get("ready") is not True:
        _add(
            findings,
            rp.ENVIRONMENT,
            "/candidate/environment/ready",
            "validation environment must be ready before candidate checks",
        )

    checks = candidate.get("checks")
    if not isinstance(checks, list) or not checks:
        _add(findings, rp.CANDIDATE, "/candidate/checks", "candidate checks required")
    else:
        names: set[str] = set()
        check_fields = {"name", "conclusion", "profileDigest", "evidenceDigest"}
        for index, item in enumerate(checks):
            path = f"/candidate/checks/{index}"
            check = _closed(item, path, check_fields, check_fields, findings)
            if check:
                name = check.get("name")
                if not isinstance(name, str) or not rp.CHECK_NAME_RE.fullmatch(name):
                    _add(findings, rp.CANDIDATE, f"{path}/name", "invalid check name")
                elif name in names:
                    _add(findings, rp.CANDIDATE, f"{path}/name", "duplicate check")
                else:
                    names.add(name)
                conclusion = check.get("conclusion")
                if conclusion not in {"success", "failure", "skipped", "cancelled"}:
                    _add(findings, rp.SYNTAX, f"{path}/conclusion", "unknown check conclusion")
                if conclusion != "success":
                    _add(findings, rp.CANDIDATE, f"{path}/conclusion", "all checks must succeed")
                _digest(check.get("profileDigest"), f"{path}/profileDigest", findings, rp.CANDIDATE)
                _digest(
                    check.get("evidenceDigest"), f"{path}/evidenceDigest", findings, rp.CANDIDATE
                )
                if check.get("profileDigest") != environment.get("profileDigest"):
                    _add(
                        findings,
                        rp.ENVIRONMENT,
                        f"{path}/profileDigest",
                        "check profile must match the prepared validation environment",
                    )
    return candidate


def _validate_case(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    case = _closed(document, "", rp.CASE_FIELDS, rp.CASE_FIELDS, findings)
    if case is None:
        return findings
    repair_id = case.get("repairId")
    if not isinstance(repair_id, str) or not rp.REPAIR_ID_RE.fullmatch(repair_id):
        _add(findings, rp.SYNTAX, "/repairId", "invalid repairId URI")
    raw_corr = case.get("correlationId")
    if not isinstance(raw_corr, str) or not rp.CORRELATION_ID_RE.fullmatch(raw_corr):
        _add(findings, rp.SYNTAX, "/correlationId", "invalid correlationId")
    correlation_id = raw_corr if isinstance(raw_corr, str) else ""

    _validate_problem(case.get("problem"), findings)
    _, principals = _validate_authority(case.get("authority"), findings)
    scope = _validate_scope(case.get("scope"), findings)

    lc_fields = {"state", "attempt", "history"}
    lifecycle = _closed(case.get("lifecycle"), "/lifecycle", lc_fields, lc_fields, findings) or {}
    state = lifecycle.get("state")
    attempt = lifecycle.get("attempt")
    max_attempts = scope.get("maxAttempts")
    if not isinstance(state, str) or state not in rp.TRANSITIONS:
        _add(findings, rp.STATE, "/lifecycle/state", "unknown repair state")
    if not _is_int(attempt) or attempt < 1 or (_is_int(max_attempts) and attempt > max_attempts):
        _add(findings, rp.SCOPE, "/lifecycle/attempt", "attempt budget exceeded")
    _validate_history(lifecycle.get("history"), state, correlation_id, principals, findings)

    candidate = _validate_candidate(case.get("candidate"), scope, findings)
    validation = case.get("validation")
    if validation is not None:
        val_fields = {"validator", "candidateSha", "outcome", "evidenceDigest", "attestedAt"}
        validation = _closed(validation, "/validation", val_fields, val_fields, findings)
        if validation:
            validator = (
                _principal(validation.get("validator"), "/validation/validator", findings) or {}
            )
            if validator.get("uri") != principals.get("validator", {}).get("uri"):
                _add(findings, rp.VALIDATION, "/validation/validator", "wrong validator principal")
            cand_sha = validation.get("candidateSha")
            if not isinstance(cand_sha, str) or not rp.SHA.fullmatch(cand_sha):
                _add(findings, rp.VALIDATION, "/validation/candidateSha", "exact SHA required")
            elif not candidate or cand_sha != candidate.get("headSha"):
                _add(findings, rp.VALIDATION, "/validation/candidateSha", "candidate SHA mismatch")
            if validation.get("outcome") not in {"approved", "rejected"}:
                _add(findings, rp.SYNTAX, "/validation/outcome", "unknown validation outcome")
            _digest(
                validation.get("evidenceDigest"),
                "/validation/evidenceDigest",
                findings,
                rp.VALIDATION,
            )
            _time(validation.get("attestedAt"), "/validation/attestedAt", findings)

    publication = case.get("publication")
    if publication is not None:
        pub_fields = {"publisher", "candidateSha", "status", "mergeSha", "receipt"}
        publication = _closed(publication, "/publication", pub_fields, pub_fields, findings)
        if publication:
            publisher = (
                _principal(publication.get("publisher"), "/publication/publisher", findings) or {}
            )
            if publisher.get("uri") != principals.get("publisher", {}).get("uri"):
                _add(
                    findings, rp.PUBLICATION, "/publication/publisher", "wrong publisher principal"
                )
            pub_cand_sha = publication.get("candidateSha")
            if not isinstance(pub_cand_sha, str) or not rp.SHA.fullmatch(pub_cand_sha):
                _add(findings, rp.PUBLICATION, "/publication/candidateSha", "exact SHA required")
            elif not candidate or pub_cand_sha != candidate.get("headSha"):
                _add(
                    findings, rp.PUBLICATION, "/publication/candidateSha", "candidate SHA mismatch"
                )
            pub_status = publication.get("status")
            if pub_status not in {"pending", "merged", "failed"}:
                _add(findings, rp.SYNTAX, "/publication/status", "unknown publication status")
            merge_sha = publication.get("mergeSha")
            if pub_status == "merged":
                if not isinstance(merge_sha, str) or not rp.SHA.fullmatch(merge_sha):
                    _add(findings, rp.PUBLICATION, "/publication/mergeSha", "merge SHA required")
            elif merge_sha is not None and (
                not isinstance(merge_sha, str) or not rp.SHA.fullmatch(merge_sha)
            ):
                _add(findings, rp.PUBLICATION, "/publication/mergeSha", "invalid merge SHA")
            receipt, _ = _receipt(
                publication.get("receipt"), "/publication/receipt", correlation_id, findings
            )
            if receipt and (receipt.get("actor") or {}).get("uri") != publisher.get("uri"):
                _add(
                    findings,
                    rp.PUBLICATION,
                    "/publication/receipt/actor",
                    "publisher receipt required",
                )

    readback = case.get("readback")
    if readback is not None:
        rb_fields = {"observer", "integratedSha", "effectConfirmed", "evidenceDigest", "observedAt"}
        readback = _closed(readback, "/readback", rb_fields, rb_fields, findings)
        if readback:
            observer = _principal(readback.get("observer"), "/readback/observer", findings) or {}
            forbidden_observers = {
                principals.get("implementer", {}).get("uri"),
                principals.get("publisher", {}).get("uri"),
            }
            if observer.get("kind") != "observer" or observer.get("uri") in forbidden_observers:
                _add(findings, rp.READBACK, "/readback/observer", "independent observer required")
            int_sha = readback.get("integratedSha")
            if not isinstance(int_sha, str) or not rp.SHA.fullmatch(int_sha):
                _add(
                    findings,
                    rp.READBACK,
                    "/readback/integratedSha",
                    "exact integrated SHA required",
                )
            if not isinstance(readback.get("effectConfirmed"), bool):
                _add(findings, rp.SYNTAX, "/readback/effectConfirmed", "boolean required")
            _digest(
                readback.get("evidenceDigest"), "/readback/evidenceDigest", findings, rp.READBACK
            )
            _time(readback.get("observedAt"), "/readback/observedAt", findings)

    rbk_fields = {"planDigest", "status", "receipt"}
    rollback = _closed(case.get("rollback"), "/rollback", rbk_fields, rbk_fields, findings) or {}
    _digest(rollback.get("planDigest"), "/rollback/planDigest", findings, rp.ROLLBACK)
    if rollback.get("status") not in {"not-needed", "executed", "failed"}:
        _add(findings, rp.SYNTAX, "/rollback/status", "unknown rollback status")
    if rollback.get("receipt") is not None:
        _receipt(rollback.get("receipt"), "/rollback/receipt", correlation_id, findings)
    if state == "rolled-back" and (
        rollback.get("status") != "executed" or rollback.get("receipt") is None
    ):
        _add(findings, rp.ROLLBACK, "/rollback", "rolled-back state requires executed receipt")

    candidate_states = {"candidate", "validating", "publishing", "verifying", "resolved"}
    if state in candidate_states and not candidate:
        _add(findings, rp.CANDIDATE, "/candidate", "state requires a candidate")
    if state in {"publishing", "verifying", "resolved"} and (
        not validation or validation.get("outcome") != "approved"
    ):
        _add(findings, rp.VALIDATION, "/validation", "state requires approved validation")
    if state in {"verifying", "resolved"} and (
        not publication or publication.get("status") != "merged"
    ):
        _add(findings, rp.PUBLICATION, "/publication", "state requires merged publication")
    if state == "resolved":
        if not readback or readback.get("effectConfirmed") is not True:
            _add(findings, rp.READBACK, "/readback", "resolved requires confirmed effect")
        elif not publication or readback.get("integratedSha") != publication.get("mergeSha"):
            _add(findings, rp.READBACK, "/readback/integratedSha", "integrated SHA mismatch")
    _scan_secrets(case, "", findings)
    return findings


def validate_document(document: Any) -> list[Finding]:
    if not isinstance(document, dict):
        return [Finding(rp.SYNTAX, "", "document must be an object")]
    if document.get("schema") == "wellmanifest.repair/case/v1":
        return _validate_case(document)
    if document.get("schema") == "wellmanifest.repair/profile/v1":
        return _validate_profile(document)
    return [Finding(rp.SYNTAX, "/schema", "unsupported repair schema")]
