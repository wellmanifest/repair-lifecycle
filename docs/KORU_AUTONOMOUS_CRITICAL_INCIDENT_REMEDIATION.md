# Standard: Koru Autonomous Critical Incident Remediation & Dynamic Traffic Shunting

- **Standard Authority**: `wellmanifest/repair-lifecycle`
- **Specification Version**: `1.1.0`
- **Owner Entity**: Tomasz Sapletta Prototypowanie.pl (NIP: 5881918662, REGON: 220665410)
- **Reference Implementations**: `clonerd-com/cluster`, `cluster/scripts/notify-urirun-email.py`

---

## 1. Architectural Purpose

Under critical adversarial attacks (distributed denial-of-service, automated credential stuffing, memory exhaustion, or container intrusion), traditional operations rely on human paging or blunt node-level failovers. Both fail under sustained assault:
- Human incident response incurs latency ($>15$ minutes) during which services remain offline.
- Total node shutdowns collapse cluster capacity, fulfilling the attacker's objective.

This standard specifies the **Koru Autonomous Remediation Protocol**, enabling edge nodes and cluster orchestrators to survive critical incidents by dynamically decoupling malicious attack vectors from legitimate user workloads and executing automated closed-loop repairs.

---

## 2. Dynamic Traffic Shunting (Vector Decoupling)

When telemetry detects anomalous attack vectors (e.g. rate-limit breaches $> 100\times$, ptrace tripwire trips, or signature matches):

```text
Incoming Ingress Traffic
         │
         ├─── Attacker Vector ───► Isolated Tarpit / Quarantine Twin (slow response, tarpit loop)
         │
         └─── Authenticated Users ─► Live Production Twin (full performance, SLA preserved)
```

### 2.1 Invariants of Dynamic Traffic Shunting
1. **Surgical Isolation**: Edge ingress (e.g., Caddy with rate limiting and route filters) shunts attacking IP ranges, TLS fingerprints, or user-agent patterns into tarpits (delayed chunked responses) without dropping legitimate TCP sockets.
2. **State Preservation**: Legitimate authenticated sessions continue to be served by production container twins with zero downtime.
3. **Telemetry Demarcation**: System status transitions to `ddos_mitigation` (or `operational (mitigated)`), preventing false-positive failover cascades from upstream DNS or global load balancers.

---

## 3. Autonomous 5-Stage Remediation Protocol

```text
1. OBSERVE & ISOLATE ──► 2. SANDBOX REPRODUCE ──► 3. AUTONOMOUS HOTFIX ──► 4. ZERO-DOWNTIME ROLLOUT ──► 5. NOTIFY & CLOSE
 (freeze offender,        (OverlayFS twin,        (patch candidate,       (atomic container swap,      (urirun-mail alert,
  tarpit vector)           read-only capture)      governance-check)       live synthetic verify)       immutable receipt)
```

### Stage 1: Incident Observation & Vector Shunting
- Diagnostic telemetry probes (CPU spikes, memory runaway, kernel ptrace alarms, repeated 5xx responses) trigger an incident ticket.
- Immediate action: offending traffic vectors are diverted to tarpits; affected container processes are quarantined.

### Stage 2: Sandboxed Reproduction in Digital Twin
- The repair agent spins up an ephemeral Digital Twin on an isolated OverlayFS copy-on-write scratchpad.
- Diagnostic snapshots (stack traces, memory dumps, network PCAP) are analyzed in the sandbox without touching live production databases or user sessions.

### Stage 3: Autonomous Candidate Repair
- The repair agent generates candidate configuration changes, code hotfixes, or firewall rules.
- Boundaries: Changes MUST strictly adhere to the allocated ticket's `allowedPaths` and budget constraints.
- Pre-flight validation: candidate must pass full self-tests and `./project/governance-check.sh` (`GOV-PASS`).

### Stage 4: Rolling Zero-Downtime Deployment
- The cluster control plane executes a blue/green or rolling container deployment:
  1. Pull / compile verified container image.
  2. Boot twin on ephemeral internal port.
  3. Execute synthetic end-to-end transaction test (`/livez`).
  4. Atomically swap reverse proxy upstream routing.
  5. Gracefully terminate quarantined container instance.

### Stage 5: Cryptographic Attestation & Fail-Closed Notification
- An immutable execution receipt (`repair-receipt.json`) is emitted containing:
  - Target host, incident UUID, and detection timestamp.
  - Applied Git commit SHA and diff digest.
  - Pre- and post-deployment synthetic latency percentiles ($p50$, $p95$, $p99$).
- Immediate notification is dispatched through `urirun-mail` connectors to system owners (`Tomasz Sapletta Prototypowanie.pl`).

---

## 4. Security & Zero-Trust Constraints

1. **No Lateral Network Traversal**: The Koru remediation controller operates from an isolated management plane. Edge nodes have outbound-only telemetry push and cannot initiate inbound sessions to the control plane.
2. **Deterministic Rollback**: If post-deployment synthetic verification fails within 30 seconds of upstream traffic swap, the proxy immediately reverts traffic to the previous known-good snapshot.
3. **Fail-Closed Governance**: No hotfix may be promoted to production without passing local governance checks (`GOV-PASS`).
