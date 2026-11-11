#!/usr/bin/env python3
"""Dependency-free semantic checker for autonomous repair lifecycle v1."""

from __future__ import annotations

import argparse
import copy
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any


def _bootstrap_siblings() -> tuple[Any, Any]:
    src_dir = str(Path(__file__).resolve().parent)
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    return (
        importlib.import_module("repair_primitives"),
        importlib.import_module("repair_validators"),
    )


_PRIMITIVES, _VALIDATORS = _bootstrap_siblings()

ROOT: Path = _PRIMITIVES.ROOT
EXAMPLES: Path = _PRIMITIVES.EXAMPLES
SYNTAX: str = _PRIMITIVES.SYNTAX
AUTHORITY: str = _PRIMITIVES.AUTHORITY
SEPARATION: str = _PRIMITIVES.SEPARATION
SCOPE: str = _PRIMITIVES.SCOPE
STATE: str = _PRIMITIVES.STATE
CANDIDATE: str = _PRIMITIVES.CANDIDATE
ENVIRONMENT: str = _PRIMITIVES.ENVIRONMENT
VALIDATION: str = _PRIMITIVES.VALIDATION
PUBLICATION: str = _PRIMITIVES.PUBLICATION
READBACK: str = _PRIMITIVES.READBACK
ROLLBACK: str = _PRIMITIVES.ROLLBACK
RECEIPT: str = _PRIMITIVES.RECEIPT
SECRET: str = _PRIMITIVES.SECRET
PROFILE: str = _PRIMITIVES.PROFILE
TRANSITIONS: dict[str, set[str]] = _PRIMITIVES.TRANSITIONS
PROFILE_MODES: dict[str, str] = _PRIMITIVES.PROFILE_MODES
CASE_FIELDS: set[str] = _PRIMITIVES.CASE_FIELDS
Finding = _PRIMITIVES.Finding
DuplicateKeyError = _PRIMITIVES.DuplicateKeyError
strict_json_loads = _PRIMITIVES.strict_json_loads
validate_document = _VALIDATORS.validate_document


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("absolute JSON Pointer required")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def apply_invalid_case(case: dict[str, Any], case_path: Path) -> tuple[Any, list[Any]]:
    try:
        raw_base = case_path.parent / str(case["base"])
        if raw_base.is_symlink():
            return {}, [Finding(SYNTAX, "/base", "symlinked base fixture is forbidden")]
        base = raw_base.resolve()
        base.relative_to(EXAMPLES)
    except (KeyError, ValueError):
        return {}, [Finding(SYNTAX, "/base", "base escapes examples root")]
    try:
        document = copy.deepcopy(strict_json_loads(base.read_text(encoding="utf-8")))
        mutations = case.get("mutations", [])
        if not isinstance(mutations, list):
            raise TypeError("mutations must be a list")
        for mutation in mutations:
            if not isinstance(mutation, dict):
                raise TypeError("mutation must be an object")
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
    except (
        OSError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        DuplicateKeyError,
    ) as error:
        return {}, [Finding(SYNTAX, "/mutations", f"invalid case: {error}")]
    return document, []


def load_and_validate(path: Path) -> list[Any]:
    if path.is_symlink():
        return [Finding(SYNTAX, "", "symlinked repair document is forbidden")]
    try:
        document = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, DuplicateKeyError) as error:
        return [Finding(SYNTAX, "", str(error))]
    prefix: list[Any] = []
    if (
        isinstance(document, dict)
        and document.get("schema") == "wellmanifest.repair/invalid-case/v1"
    ):
        document, prefix = apply_invalid_case(document, path.resolve())
    return prefix + validate_document(document)


def _collect_json_paths(target: Path) -> tuple[list[Path], list[tuple[Path, Any]]]:
    if target.is_symlink():
        return [], [(target, Finding(SYNTAX, "", "symlinked path is forbidden"))]
    if not target.is_dir():
        return [target], []
    discovered: list[Path] = []
    symlink_errors: list[tuple[Path, Any]] = []
    for root, dirs, files in os.walk(target, followlinks=False):
        root_path = Path(root)
        kept_dirs: list[str] = []
        for dirname in sorted(dirs):
            candidate_dir = root_path / dirname
            if candidate_dir.is_symlink():
                symlink_errors.append(
                    (candidate_dir, Finding(SYNTAX, "", "symlinked directory is forbidden"))
                )
            else:
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for filename in sorted(files):
            if filename.endswith(".json"):
                discovered.append(root_path / filename)
    return sorted(discovered), symlink_errors


def self_test() -> int:
    failures: list[str] = []
    for folder in ("src", "tests"):
        for py_file in sorted((ROOT / folder).glob("*.py")):
            line_count = len(py_file.read_text(encoding="utf-8").splitlines())
            if line_count >= 500:
                failures.append(f"{py_file.relative_to(ROOT)}: {line_count} lines >= 500")
    for path in sorted((EXAMPLES / "valid").glob("*.json")):
        findings = load_and_validate(path)
        if findings:
            failures.append(f"{path.name}: {[item.code for item in findings]}")
    profile_findings = load_and_validate(ROOT / "profiles" / "subactor-semcod.profile.json")
    if profile_findings:
        failures.append(f"profile: {[item.code for item in profile_findings]}")
    for path in sorted((EXAMPLES / "invalid").glob("*.json")):
        case = strict_json_loads(path.read_text(encoding="utf-8"))
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
    paths, symlink_errors = _collect_json_paths(args.path)
    failed = bool(symlink_errors)
    for bad_path, finding in symlink_errors:
        print(f"{bad_path}: {finding.render()}")
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
