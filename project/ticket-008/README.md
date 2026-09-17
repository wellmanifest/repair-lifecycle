# Ticket 008: Adopt wellmanifest/new-project 0.20.32 governance standard

- **ID**: ticket-008
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-09-17

## Goal and scope

Adopt the wellmanifest/new-project standard update from pinned 0.18.6
(revision `01397097ac53a01b2dd544f0b5908d22d1b526d5`) to available 0.20.32
(revision `b6ba9c21a65a6a5648ecf904b64c3b75295e136f`) inside the canonical
worktree `.worktrees/ticket-008--standard-adoption`
(branch `ticket/008-standard-adoption`, base `ecd0a1d5`).

The adoption is performed by the managed adoption tool
(`goal governance adopt --latest --upgrade`) and replaces reviewed
standard-managed drift only. Unknown local work is left untouched; the untracked
`.subactor/leases/` entry in the primary checkout was moved aside for allocation
and restored unchanged.

One repository-local override is dropped: the manifest `ticket` block required
`preprompt.md` and `changelog.md` per ticket and `ai-*.md` agent files. The
pinned 0.20.32 contract validates that block against
`.governance/manifest.base.json` and rejects any other value, so the adopted
projection fails `GOV-MANIFEST-001` until the override is replaced by the base.

## Acceptance criteria

- [x] AC-01: Scope is approved by a human owner (session instruction to execute the
      wellmanifest-standard rollout across the fleet backlog; STARTER-657 is this
      repository entry).
- [x] AC-02: `goal governance adopt --latest --check` reports no remaining
      standard-managed drift and `./project/governance-check.sh` passes.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-claude.md](ai-claude.md)
