"""Shared constants, Finding model, primitive helpers, and profile validator."""

from __future__ import annotations

import json
import re
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
ENVIRONMENT = "REPAIR-ENVIRONMENT-001"
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
RECEIPT_URI = re.compile(r"^repair://receipt/[a-z0-9][a-z0-9._/-]*$")
REPAIR_ID_RE = re.compile(r"^repair://case/[a-z0-9][a-z0-9._/-]*$")
CORRELATION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
DIAGNOSTIC_ID_RE = re.compile(r"^repair://diagnostic/[a-z0-9][a-z0-9._/-]*$")
PROCESS_URI_RE = re.compile(r"^subactor://process/[a-z0-9][a-z0-9._/-]*$")
COMPONENT_URI_RE = re.compile(r"^subactor://component/[a-z0-9][a-z0-9._/-]*$")
REPO_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
CHECK_NAME_RE = re.compile(r"^[a-z][a-z0-9._/-]{1,100}$")
PROFILE_ID_RE = re.compile(r"^repair://profile/[a-z0-9][a-z0-9._/-]*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
RUNTIME_OWNER_RE = re.compile(r"^(subactor|semcod)/[a-z0-9][a-z0-9._/-]*$")
STANDARD_ADOPT_RE = re.compile(r"^wellmanifest/[a-z0-9][a-z0-9._/-]*$")

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


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def strict_json_loads(text: str) -> Any:
    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, val in pairs:
            if key in result:
                raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
            result[key] = val
        return result

    return json.loads(text, object_pairs_hook=_reject_duplicates)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


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
        parsed = datetime.fromisoformat(value)
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


def _safe_path(value: Any) -> bool:
    if not isinstance(value, str) or not (1 <= len(value) <= 240):
        return False
    if value.strip() != value or "\\" in value:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return False
    return (
        value not in {".", "*", "**", "/"}
        and not value.startswith(("/", "~"))
        and ".." not in Path(value).parts
    )


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    return path == pattern


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
    if not isinstance(receipt_id, str) or not RECEIPT_URI.fullmatch(receipt_id):
        _add(findings, RECEIPT, f"{path}/receiptId", "invalid receipt URI")
    _principal(receipt.get("actor"), f"{path}/actor", findings)
    rc_corr = receipt.get("correlationId")
    if (
        not isinstance(rc_corr, str)
        or not CORRELATION_ID_RE.fullmatch(rc_corr)
        or rc_corr != correlation_id
    ):
        _add(findings, RECEIPT, f"{path}/correlationId", "correlation mismatch")
    _digest(receipt.get("subjectDigest"), f"{path}/subjectDigest", findings, RECEIPT)
    return receipt, _time(receipt.get("at"), f"{path}/at", findings)


def _validate_profile(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    fields = {"schema", "profileId", "version", "ownership", "bindings"}
    profile = _closed(document, "", fields, fields, findings)
    if profile is None:
        return findings
    profile_id = profile.get("profileId")
    if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
        _add(findings, PROFILE, "/profileId", "invalid profileId URI")
    version = profile.get("version")
    if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
        _add(findings, PROFILE, "/version", "semver version required")
    own_fields = {"standardOwner", "runtimeOwner", "adopts"}
    ownership = (
        _closed(profile.get("ownership"), "/ownership", own_fields, own_fields, findings) or {}
    )
    if ownership.get("standardOwner") != "wellmanifest/repair-lifecycle":
        _add(findings, PROFILE, "/ownership/standardOwner", "wrong standard owner")
    runtime_owner = ownership.get("runtimeOwner")
    if not isinstance(runtime_owner, str) or not RUNTIME_OWNER_RE.fullmatch(runtime_owner):
        _add(findings, PROFILE, "/ownership/runtimeOwner", "runtime must remain external")
    adopts = ownership.get("adopts")
    if (
        not isinstance(adopts, list)
        or "wellmanifest/autonomy" not in adopts
        or not all(isinstance(item, str) and STANDARD_ADOPT_RE.fullmatch(item) for item in adopts)
        or len(adopts) != len(set(adopts))
    ):
        _add(findings, PROFILE, "/ownership/adopts", "valid unique autonomy adoption required")
    bindings = profile.get("bindings")
    if not isinstance(bindings, list):
        _add(findings, SYNTAX, "/bindings", "binding array required")
        return findings
    observed: dict[str, str] = {}
    principals: dict[str, str] = {}
    for index, item in enumerate(bindings):
        path = f"/bindings/{index}"
        b_fields = {"stage", "uri", "principal", "mode"}
        binding = _closed(item, path, b_fields, b_fields, findings)
        if binding:
            stage = binding.get("stage")
            if not isinstance(stage, str) or stage not in PROFILE_MODES:
                _add(findings, PROFILE, f"{path}/stage", "unknown binding stage")
                continue
            if stage in observed:
                _add(findings, PROFILE, f"{path}/stage", "duplicate stage")
            uri = binding.get("uri")
            if not isinstance(uri, str) or not PROCESS_URI_RE.fullmatch(uri):
                _add(findings, PROFILE, f"{path}/uri", "invalid process URI")
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
