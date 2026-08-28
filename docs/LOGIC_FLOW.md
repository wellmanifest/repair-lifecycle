# Logic flow

1. Observe and deduplicate a problem without mutation authority.
2. Produce a diagnosis with component, symptom and evidence digests.
3. Resolve a separate component-owner grant and immutable repair scope.
4. Lease one attempt and create an isolated exact-base worktree.
5. Implement only within allowed paths and budgets.
6. Prepare the declared validation environment and record its profile,
   dependency and setup-evidence digests.
7. Run checks bound to that profile and freeze the candidate SHA.
8. Validate the exact candidate with a separate principal.
9. Publish only the accepted candidate through the protected publisher.
10. Read back the integrated SHA and intended operational effect.
11. Mark `resolved` only after positive read-back; otherwise retry within the
    original scope, execute the declared rollback or enter `blocked`.

A repair attempt never widens its own grant or path scope. Exhausted attempts,
ambiguous evidence, stale base/head, failed validation, changed policy or
failed read-back stop mutation and produce a new explicit lifecycle fact.
