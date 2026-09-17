# Ticket 7: Express the repair lifecycle and development auto-repair boundary in Policy DSL

- **ID**: ticket-007
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-09-13

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: on 2026-09-13 the user asked to correct
Wellmanifest standards that do not express their logic in the DSL standard,
and reported that the Semcod development auto-repair tool `pfix` overwrote
changes, so it is being removed from Semcod projects.

`spec/REPAIR_LIFECYCLE_STANDARD.md` states the lifecycle only as prose and a
`text` diagram whose failure edges ("Failures MAY transition to ...") do not
say from which states. The exact graph exists only in `src/repair_check.py`.
The spec also does not say that a development-time tool which applies patches
or installs dependencies automatically violates the separation of diagnosis
and authority.

This ticket adds a Policy DSL v1 projection (section 8) whose transitions equal
`TRANSITIONS` in `src/repair_check.py`, rules for sections 1 to 6, a normative
paragraph plus rule `REPAIR-DEV-001` for development-time repair tools, and a
unit test that keeps the DSL transition set equal to the checker table.

Non-goals: no schema, example, profile, checker or diagnostic-code change.

## Acceptance criteria

- [ ] AC-01: `validate-markdown` from `wellmanifest/policy-dsl` at `daaf7b7`,
  `48e95c8` and `d723271` (fail-closed selector) accepts the spec (12 states,
  32 transitions, 6 rules).
- [ ] AC-02: `python3 -m unittest discover -s tests` passes, including the new
  projection test.
- [ ] AC-03: The repository governance gate passes.

Cross-repository evidence:
`subactor/docs/architecture/analysis/semcod-library-quality.md`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
