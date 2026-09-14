# Wellmanifest Repair Lifecycle Standard

Version `0.1.0-dev` defines a deterministic repair lifecycle for autonomous
systems. The key words MUST, MUST NOT, REQUIRED, SHOULD and MAY are normative.

## 1. Facts, not shortcuts

The lifecycle keeps these facts separate:

1. a problem was observed;
2. a diagnosis was produced;
3. repair authority was granted;
4. an isolated candidate was created and tested;
5. an independent validator accepted the exact candidate;
6. a protected publisher applied the exact candidate;
7. an independent observer confirmed the intended effect.

No earlier fact implies a later one. In particular, diagnosis MUST NOT grant
mutation, passing tests MUST NOT imply independent validation, and merge MUST
NOT imply the problem is resolved.

## 2. Problem evidence

The diagnostic source MUST be `observationOnly=true`. It MUST bind an immutable
diagnostic ID, component URI, symptom digest, evidence digests, observation
time and severity. Doctor, probe and model output are untrusted evidence until
validated. They cannot expand repair scope or select credentials.

## 3. Separate authority

A repair MUST bind a current authority grant and protected policy digest. The
component owner, implementer, validator and publisher MUST use distinct
principals where their duties conflict. The authority grant MUST be resolved
outside the candidate checkout and MUST NOT be synthesized from the diagnostic
ticket.

## 4. Bounded repair

Each attempt MUST use an isolated exact-base workspace. Allowed and forbidden
paths, maximum changed files, maximum attempts and rollback requirement are
declared before execution. Candidate changes outside this scope fail closed.
Generated shell commands or patches MUST NOT execute without the bounded
runner and registered verification profile.

Before candidate checks run, the runtime MUST prepare a declared validation
environment and record immutable digests for the verification profile,
resolved dependencies and setup evidence. The environment MUST be ready, and
every candidate check MUST bind the same profile digest. An absent, failed or
mismatched environment is an environment failure, not evidence that the
candidate failed. Tool-specific commands, dependency installation and secret
handling remain responsibilities of the adopting runtime; this standard owns
only the portable evidence contract.

A development-time repair tool is subject to the same boundary. An import
hook, exception handler, startup file or editor tool that turns a runtime error
into an applied patch or an installed dependency skips facts 3 to 7 of section
1 and overwrites work that nobody authorized it to change. Such a tool MUST
stay propose-only until a repair authority grant is bound, and tracked project
configuration or a startup hook MUST NOT enable automatic application.

## 5. Lifecycle

The normal path is:

```text
observed -> diagnosed -> authorized -> repairing -> candidate
-> validating -> publishing -> verifying -> resolved
```

Failures MAY transition to `blocked`, a new bounded repair attempt, or
`rolled-back`. `resolved`, `rolled-back` and `abandoned` are terminal. Every
transition requires a unique receipt bound to the same correlation ID and the
resulting subject digest.

## 6. Exact candidate and completion

Validation and publication MUST bind the candidate head SHA. Approval requires
a ready digest-bound validation environment and every deterministic candidate
check to succeed against its declared profile. Publication MUST be performed by
the declared publisher and produce a separate receipt.

`resolved` requires all of:

- independent validation outcome `approved` for the candidate SHA;
- publication status `merged` for that candidate;
- read-back integrated SHA equal to the publication merge SHA;
- `effectConfirmed=true` with independent evidence.

If read-back fails, the case MUST NOT close. It transitions to a bounded new
attempt, rollback or explicit blocked state.

## 7. Ownership

Wellmanifest owns this portable contract. Subactor owns Doctor, Repair,
Validator, Publisher and read-back runtimes. Semcod Planfile, Todo2code, Twin
Probes and validators MAY supply typed evidence but never implicit authority.

## 8. Policy DSL projection

The block below is the normative Policy DSL v1 projection of sections 1 to 6.
Its transition set equals `TRANSITIONS` in `src/repair_check.py`; a change to
one requires the same change to the other.

```dsl
DOCUMENT REPAIR_LIFECYCLE
VERSION 1
LANGUAGE EN
MODE STRICT
PURPOSE "deterministic repair lifecycle for autonomous systems"
TERMINAL_STATES = [resolved, rolled-back, abandoned]

STATE observed
STATE diagnosed
STATE authorized
STATE repairing
STATE candidate
STATE validating
STATE publishing
STATE verifying
STATE resolved
STATE blocked
STATE rolled-back
STATE abandoned

TRANSITION observed -> diagnosed
TRANSITION observed -> blocked
TRANSITION observed -> abandoned
TRANSITION diagnosed -> authorized WHEN REPAIR_AUTHORITY_GRANT_BOUND
TRANSITION diagnosed -> blocked
TRANSITION diagnosed -> abandoned
TRANSITION authorized -> repairing WHEN ISOLATED_EXACT_BASE_WORKSPACE_READY
TRANSITION authorized -> blocked
TRANSITION authorized -> abandoned
TRANSITION repairing -> candidate
TRANSITION repairing -> blocked
TRANSITION repairing -> rolled-back
TRANSITION candidate -> validating WHEN VALIDATION_ENVIRONMENT_READY_AND_DIGEST_BOUND
TRANSITION candidate -> repairing
TRANSITION candidate -> blocked
TRANSITION candidate -> rolled-back
TRANSITION validating -> publishing WHEN VALIDATION_OUTCOME = approved
TRANSITION validating -> repairing
TRANSITION validating -> blocked
TRANSITION validating -> rolled-back
TRANSITION publishing -> verifying WHEN PUBLICATION_STATUS = merged
TRANSITION publishing -> repairing
TRANSITION publishing -> blocked
TRANSITION publishing -> rolled-back
TRANSITION verifying -> resolved WHEN READBACK_SHA = PUBLICATION_MERGE_SHA AND EFFECT_CONFIRMED = true
TRANSITION verifying -> repairing
TRANSITION verifying -> blocked
TRANSITION verifying -> rolled-back
TRANSITION blocked -> diagnosed
TRANSITION blocked -> authorized
TRANSITION blocked -> repairing
TRANSITION blocked -> abandoned

RULE REPAIR-FACT-001 TYPE FORBIDDEN
WHEN EARLIER_LIFECYCLE_FACT_RECORDED
FORBID INFER_LATER_FACT
FORBID GRANT_MUTATION_FROM_DIAGNOSIS
FORBID TREAT_PASSING_TESTS_AS_INDEPENDENT_VALIDATION
FORBID TREAT_MERGE_AS_RESOLUTION
ASSERT EVERY_TRANSITION_HAS_UNIQUE_RECEIPT_BOUND_TO_CORRELATION_ID_AND_SUBJECT_DIGEST

RULE REPAIR-EVIDENCE-001 TYPE REQUIRED
WHEN DIAGNOSTIC_EVIDENCE_RECEIVED
DO REQUIRE OBSERVATION_ONLY = true
DO REQUIRE DIAGNOSTIC_ID COMPONENT_URI SYMPTOM_DIGEST EVIDENCE_DIGESTS OBSERVED_AT SEVERITY
FORBID EXPAND_REPAIR_SCOPE_FROM_DOCTOR_PROBE_OR_MODEL_OUTPUT
FORBID SELECT_CREDENTIALS_FROM_EVIDENCE
NEXT diagnosed OR blocked

RULE REPAIR-AUTHORITY-001 TYPE REQUIRED
WHEN REPAIR_REQUESTED
DO REQUIRE CURRENT_AUTHORITY_GRANT AND PROTECTED_POLICY_DIGEST
DO REQUIRE DISTINCT_PRINCIPALS_FOR_CONFLICTING_OWNER_IMPLEMENTER_VALIDATOR_PUBLISHER_DUTIES
FORBID RESOLVE_GRANT_INSIDE_CANDIDATE_CHECKOUT
FORBID SYNTHESIZE_GRANT_FROM_DIAGNOSTIC_TICKET
NEXT authorized OR blocked

RULE REPAIR-BOUND-001 TYPE REQUIRED
WHEN REPAIR_ATTEMPT_STARTS
DO REQUIRE ISOLATED_EXACT_BASE_WORKSPACE
DO REQUIRE DECLARED allowedPaths forbiddenPaths maxChangedFiles maxAttempts rollbackRequirement
DO REQUIRE VALIDATION_ENVIRONMENT_READY_WITH_PROFILE_DEPENDENCY_AND_SETUP_DIGESTS
FORBID EXECUTE_GENERATED_SHELL_OR_PATCH_OUTSIDE_BOUNDED_RUNNER
FORBID TREAT_ENVIRONMENT_FAILURE_AS_CANDIDATE_FAILURE
ASSERT CANDIDATE_CHANGES_OUTSIDE_SCOPE_FAIL_CLOSED
NEXT repairing OR blocked

RULE REPAIR-DEV-001 TYPE FORBIDDEN
WHEN REPAIR_TOOL_RUNS_IN_DEVELOPMENT_WORKSPACE AND REPAIR_AUTHORITY_GRANT_BOUND = false
DO REQUIRE PROPOSE_ONLY_OUTPUT
FORBID AUTO_APPLY_PATCH_TO_WORKING_TREE
FORBID AUTO_INSTALL_DEPENDENCY
FORBID ENABLE_AUTO_APPLY_FROM_TRACKED_PROJECT_CONFIGURATION_OR_STARTUP_HOOK
ASSERT FOREIGN_WORK_PRESERVED

RULE REPAIR-RESOLVE-001 TYPE REQUIRED
WHEN RESOLUTION_REQUESTED
DO REQUIRE VALIDATION_OUTCOME = approved FOR CANDIDATE_SHA
DO REQUIRE PUBLICATION_STATUS = merged FOR CANDIDATE_SHA
DO REQUIRE READBACK_SHA = PUBLICATION_MERGE_SHA
DO REQUIRE EFFECT_CONFIRMED = true WITH INDEPENDENT_EVIDENCE
FORBID CLOSE_CASE_WHEN_READBACK_FAILS
NEXT resolved OR repairing OR rolled-back OR blocked
```
