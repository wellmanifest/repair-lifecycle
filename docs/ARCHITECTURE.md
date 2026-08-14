# Architecture

```text
Twin Probe/Doctor (acts:false) -> diagnostic evidence
                                      |
                         protected authority resolver
                                      |
                                      v
isolated Repair Agent -> exact candidate -> independent Validator
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

Planfile should own deterministic work selection and lease one repair attempt.
Todo2code may provide provenance-bound plans. Twin Probes may supply diagnostic
evidence. Vallm findings remain advisory. Koru or IDE automation belongs in a
lower-trust experimental lane unless it produces the same isolated exact-head
receipts.
