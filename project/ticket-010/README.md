# Ticket 010: Modularize and harden repair lifecycle checker

- **ID**: ticket-010
- **Owner**: human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Modularize `src/repair_check.py` strictly below 500 lines (`repair_primitives.py`, `repair_validators.py`, `repair_check.py`) and fix semantic/security validation defects:

1. Reject `bool` values (`True`/`False`) for integer fields (`maxFiles`, `maxAttempts`, `attempt`) and prevent `ValueError` crashes when `maxFiles` or `maxAttempts` is non-numeric.
2. Validate `_safe_path` before `set(paths)` in `_validate_scope` so unhashable items (`allowedPaths: [{}]`) emit `REPAIR-SCOPE-001` instead of raising `TypeError`.
3. Harden `_safe_path` against empty strings, whitespace-padded strings, backslashes, control characters, `.` and length > 240.
4. Reject duplicate JSON keys via `strict_json_loads` and reject symlinked files/directories in `load_and_validate`, `apply_invalid_case`, and `main`.
5. Enforce JSON Schema parity on URIs, identifiers, duplicate `evidenceDigests` / `changedPaths`, and enum fields.

## Acceptance criteria

- [x] AC-01: All `src/*.py` and `tests/*.py` modules are strictly below 500 lines and pass `python3 -m unittest discover -s tests -v` and `python3 src/repair_check.py self-test`.
- [x] AC-02: Regression tests cover bool-as-int rejection, non-int budget non-crash, unhashable path non-crash, empty/backslash paths, duplicate JSON keys, symlink rejection, and schema parity.
- [x] AC-03: Passes `./project/governance-check.sh` and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
