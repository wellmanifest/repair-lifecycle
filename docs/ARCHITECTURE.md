# Architecture

```text
Twin Probe/Doctor (acts:false) -> diagnostic evidence
                                      |
                         protected authority resolver
                                      |
                                      v
isolated Repair Agent -> prepared environment -> exact candidate -> independent Validator
                                              |
                                      protected Publisher
                                              |
                                      merge/deploy receipt
                                              |
                                   independent EQL read-back
                                       |             |
                                    resolved      retry/rollback
```

The observer cannot mutate. The authority resolver does not implement. The
implementer cannot validate or publish. The validator cannot alter the
candidate. The publisher can apply only the attested candidate. The read-back
observer cannot be the implementer or publisher.

The prepared environment records only portable evidence: verification-profile,
resolved-dependency and setup-evidence digests plus readiness. Subactor owns
runtime commands such as `doctor-setup`; Wellmanifest does not prescribe a
package manager, Make target or credential mechanism.

Planfile should own deterministic work selection and lease one repair attempt.
Todo2code may provide provenance-bound plans. Twin Probes may supply diagnostic
evidence. Vallm findings remain advisory. Koru or IDE automation belongs in a
lower-trust experimental lane unless it produces the same isolated exact-head
receipts.

## Koru Autonomous Critical Incident Remediation

Under critical hostile attacks (DDoS, volumetric flood, or memory exhaustion),
the repair controller (Koru) executes an automated 5-stage protocol:
1. **Dynamic Vector Shunting**: Immediately divert attack traffic vectors to
   isolated tarpits / honeypots while preserving legitimate user traffic.
2. **Twin Sandbox Reproduction**: Reproduce failures inside isolated OverlayFS
   ephemeral worktrees without impacting production state.
3. **Bounded Candidate Hotfix**: Generate and verify hotfixes within strictly
   bounded tickets and governance checks (`GOV-PASS`).
4. **Atomic Rolling Swap**: Deploy verified container instances with live synthetic
   `/livez` validation and instant rollback on failure.
5. **Attested Notification**: Dispatch cryptographic incident receipts via
   `urirun-mail` connectors to system owners (Tomasz Sapletta Prototypowanie.pl).

