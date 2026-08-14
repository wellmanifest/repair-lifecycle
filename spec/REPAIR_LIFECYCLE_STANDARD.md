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
every deterministic candidate check to succeed. Publication MUST be performed
by the declared publisher and produce a separate receipt.

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
