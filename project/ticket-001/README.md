# Ticket 001: Define autonomous repair lifecycle standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-14

## Goal and scope

Define a reusable autonomous repair lifecycle that separates observation,
diagnosis, repair authority, isolated implementation, independent validation,
publication, effect read-back and rollback.

## Acceptance criteria

- [x] AC-01: The continuation request is recorded as bounded authorization.
- [x] AC-02: A closed contract defines problem evidence, separate authority,
  bounded scope, lifecycle history, candidate, validation, publication,
  read-back and rollback.
- [x] AC-03: Diagnosis remains observation-only and cannot grant repair rights.
- [x] AC-04: Implementer, validator and publisher independence is enforced.
- [x] AC-05: Lifecycle transitions and required artifacts fail closed.
- [x] AC-06: `resolved` requires exact candidate validation, publication and
  independently confirmed read-back; merge or tests alone are insufficient.
- [x] AC-07: Attempts, paths, files and rollback are bounded.
- [x] AC-08: A Subactor/Semcod profile maps Doctor, Repair, Validator,
  Publisher and read-back lanes.
- [x] AC-09: Positive and adversarial fixtures and tests cover the invariants.
- [x] AC-10: Architecture and end-to-end logic are documented.
- [x] AC-11: Governance, tests, compilation and lint pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
