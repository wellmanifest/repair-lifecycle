# Ticket 006: Bind repair validation to a reproducible environment

- **ID**: ticket-006
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-08-28

## Goal and scope

Close the repair-lifecycle gap exposed by Subactor Doctor Issue #65: a
candidate must prove that its validation dependencies were prepared from a
declared, digest-bound environment before its checks can authorize
publication. Keep tool-specific setup commands in the adopting runtime.

## Acceptance criteria

- [x] AC-01: The user's autonomous continuation request is recorded as bounded
  session execution authorization.
- [ ] AC-02: The candidate contract requires a ready validation environment
  with profile, dependency and setup-evidence digests.
- [ ] AC-03: Every candidate check binds the same validation profile as the
  prepared environment.
- [ ] AC-04: Missing, unready or mismatched environments fail conformance with
  a stable diagnostic code.
- [ ] AC-05: The normative spec explains that Wellmanifest defines evidence
  while Subactor owns commands such as `doctor-setup`.
- [ ] AC-06: Positive, adversarial, schema and governance checks pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
