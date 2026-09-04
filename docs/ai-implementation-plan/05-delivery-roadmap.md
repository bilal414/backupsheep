# Delivery roadmap

This roadmap produces an open-source Recovery Intelligence preview and a private
dedicated-cell prototype in the first 90 days. It does **not** target broad hosted GA.

## 1. Desired 90-day outcome

By day 90, the team should have:

- versioned facts/evidence/output schemas and approved threat model;
- explicit recovery objectives;
- deterministic Recovery Readiness working with AI completely disabled;
- a useful deterministic failure panel;
- isolated, durable inference plumbing with local/BYOK and managed-adapter test paths;
- Failure Investigator running first in shadow mode, then for a small opt-in cohort only if
  hard gates pass;
- evaluation, red-team, feedback, cost, and kill-switch tooling;
- three to five design partners and measured product-learning results;
- one automated dedicated-cell prototype that can be provisioned, upgraded, backed up,
  and restored in a clean test environment;
- an evidence-backed decision to continue, narrow, or stop hosted/AI investment.

## 2. Team shape

Recommended parallel team:

- **Backend/reliability owner:** E1 and integration support for E2/E3.
- **Product/full-stack owner:** E4, E5, and E6.
- **AI/runtime owner:** E3 plus provider adapters.
- **Security/evaluation owner:** E0 data/threat review and E7; independent release veto.
- **Platform owner:** H0–H7 prototype.
- **Product/design/research:** interviews, UX, labels, manual output review.
- **Fractional legal/privacy:** licensing, DPA, subprocessors, model terms, trademark.

With one or two engineers, retain the same gates but sequence the work over roughly six
months: deterministic Community slice first, AI alpha second, hosted private beta third.

## 3. Week-by-week plan

### Weeks 1–2 — discovery, governance, and frozen contracts

Parallel work:

- E0 ADRs, product/edition matrix, and threat model.
- Interview 8–12 operators from the target segment.
- Recruit at least three credible design partners.
- Inventory every candidate evidence field from current `develop`.
- Freeze input/output/evidence/remediation schemas.
- Define recovery objective vocabulary and no-hidden-default policy.
- Build first synthetic golden cases from current reliability tests.
- Decide model-provider retention/no-training requirements and local/BYOK support order.

Milestone M0 exit:

- Approved schemas and data matrix.
- Three design partners willing to supply structured feedback.
- No unresolved P0 data-flow or action-authority question.
- Product copy distinguishes integrity, restore completion, and workload verification.
- Current provider acceptance items remain tracked separately.

### Weeks 3–4 — deterministic evidence foundation

Parallel work:

- E1 additive models/migrations.
- Recipient-scoped fact projector and exact data preview.
- Evidence normalization for artifacts, schedules, storage posture, execution, and restore.
- E2 objective validation and readiness rule engine.
- E7 scope, secret-canary, property, timezone, and golden tests.
- UX prototypes for posture dashboard and failure panel.

Milestone M1 exit:

- Fresh and upgrade migrations pass.
- Same facts/rule version produces stable hashes/findings.
- Golden deterministic corpus agreement is 100%.
- Secret canaries in prohibited source fields never enter snapshots.
- Restricted users receive facts only for current `visible_nodes()`.
- Deterministic posture renders with all AI processes absent.

### Weeks 5–6 — API/UI foundation and inference runtime

Parallel work:

- E4 readiness/objective/evidence/preview APIs and dashboard.
- E3 adapter interface, durable run/outbox, isolated queues, fake provider, result validator.
- Implement `off` and local adapter paths; BYOK/hosted adapters can follow once the same
  contract passes.
- E7 runtime crash matrix, forbidden-output validators, and load fixtures.
- Platform: H0 contract and H1 real capability/readiness endpoint prototype.

Milestone M2 exit:

- Recovery Readiness is usable and accessible with AI off.
- Model timeout/malformed/rate-limit tests fall back deterministically.
- Inference process has no application/provider/backup-volume access.
- Worker/broker/server fault injection yields one visible logical output and no provider
  operation change.
- p95 readiness generation meets the agreed 1,000-source target.

### Weeks 7–8 — Failure Investigator shadow mode

Parallel work:

- E5 deterministic panel and explanation request/polling UI.
- Structured Failure Investigator prompt/adapter implementation.
- Evidence-linked output and feedback.
- Expand corpus toward 500–800 labelled cases.
- Run all offline quality, scope, leakage, excessive-agency, and stale-state evaluations.
- Platform: H2 first dedicated-cell IaC and ownership ledger.

Milestone M3 exit:

- Shadow output is 100% schema/reference valid.
- Zero secret/cross-tenant/destructive/false-critical-proof failures.
- Supported factual claims >=99%, correct abstention >=95%, and top-three cause agreement
  >=90%.
- Deterministic panel remains the sole visible customer experience if any gate fails.
- First cell can be created/destroyed idempotently in a disposable environment.

### Weeks 9–10 — opt-in alpha and readiness briefs

Only if M3 hard gates pass:

- Enable Community local/BYOK alpha for explicit accounts.
- Enable hosted managed-inference alpha for design partners under approved terms.
- E6 deterministic daily/weekly changes and optional validated narrative.
- Manual review of sampled outputs and daily safety/cost monitoring.
- Measure diagnosis time, helpfulness, misleading reports, and unsafe retries.
- Platform: H3 provisioner state machine; begin H4 key/token/support-access design.

Milestone M4 exit:

- At least 50 real investigations reviewed, or documented decision to extend shadow mode.
- No safety/security incident.
- Cohort disable and provider rollback exercised.
- Recipient-specific brief scoping proven.
- Provisioning faults resume the same logical cell operation.

### Weeks 11–12 — hardening and go/no-go

- Complete E7 large-account, retention/deletion, outage, cost, and model-regression tests.
- Review 200 sampled outputs manually if volume permits; otherwise extend pilot rather than
  lowering the sample requirement.
- Complete product accessibility/responsive QA and operator documentation.
- Run full existing BackupSheep reliability suite and migration/build checks.
- Exercise cell metadata backup and clean-environment restore.
- Review unit economics, support load, design-partner adoption, licensing/legal gaps, and
  current provider acceptance status.
- Produce a written go/no-go decision for Community beta and hosted continuation.

Milestone M5 exit:

- Community preview may proceed only if all deterministic/security gates pass.
- AI beta may proceed only if all zero-tolerance and quality gates pass.
- Hosted remains private prototype unless isolation/provisioning/DR/security gates pass.
- No formal SLA or enterprise-readiness claim.

## 4. Critical path

```text
E0 schemas/threat model
  -> E1 scoped facts/evidence
  -> E2 deterministic findings
  -> E4 useful no-AI product

E0 + E1
  -> E3 isolated runtime
  -> E5 shadow investigator
  -> E7 safety/quality approval
  -> opt-in alpha

H0
  -> H1 managed-cell contract
  -> H2 dedicated infrastructure
  -> H3 idempotent provisioner
  -> H4/H5/H6 security, upgrade, DR
  -> private hosted beta
```

The AI alpha is not allowed to bypass E4: the product must remain useful without a model.
The hosted beta is not allowed to bypass H4–H6 because a working container is not an
operable managed backup service.

## 5. Milestone decision table

| Milestone | Continue when | Stop/hold when |
| --- | --- | --- |
| M0 contracts | Data boundary, schemas, owners, and design partners are clear | Product relies on raw logs/content or autonomous actions to be useful |
| M1 deterministic | Rules exact, scoped, fast, explainable, useful with AI off | Hidden defaults, ambiguous proof, scope leakage, or weak evidence semantics |
| M2 runtime | Isolation/chaos/fallback pass with no core impact | Inference needs provider/app secrets or couples to critical queues |
| M3 shadow | All zero-tolerance gates and quality thresholds pass | Any leakage, destructive advice, false proof, or unsupported critical claim |
| M4 pilot | Users find it useful and diagnosis time improves without unsafe behavior | Misleading rate/support/cost is unsustainable or safety incident occurs |
| M5 preview | Full suite, docs, privacy, retention, kill switch, and rollback pass | Core regression, unresolved security issue, or missing disable/delete behavior |
| Hosted beta | Cell isolation, provisioning, upgrade, DR, identity, and support gates pass | Shared boundary, unrecoverable secrets, duplicate resources, or no tested DR |

## 6. Product research plan

Initial target customer:

- agencies and lean SaaS/DevOps teams;
- 10–50 protected websites, databases, or cloud resources;
- no dedicated backup engineer;
- meaningful cost of missed backup/slow diagnosis;
- willing to use customer-owned storage.

Interview questions should test:

- how they currently know a backup is recoverable;
- last failure and time to diagnosis;
- whether they perform restore rehearsals and what blocks them;
- desired RPO/copy/air-gap/immutability policy language;
- what evidence they need for clients/audits;
- preference for self-hosted, managed cell, or Fleet oversight;
- acceptable support/hosting price and procurement friction;
- trust requirements for model data and local/BYOK options.

Avoid showing “AI chat” first. Test the readiness/evidence workflow and deterministic
failure panel before adding the optional narrative; otherwise novelty will obscure value.

## 7. Metrics

North-star product metric:

> Percentage of explicitly governed workloads with a recovery point inside policy and a
> non-expired workload-verified restore rehearsal.

Supporting product metrics:

- workloads with objectives configured;
- `verified_ready`, `protected_not_rehearsed`, `at_risk`, and `unknown` distribution;
- RPO violation and unresolved-reconciliation rates;
- restore-rehearsal coverage;
- time from failure detection to correct next investigation;
- finding resolution time;
- explanation helpful/misleading/unsafe feedback;
- change in unsafe duplicate manual retries;
- Community intelligence enable/disable/retention behavior.

Runtime/business metrics:

- inference success/fallback/validation failure;
- queue wait and generation latency;
- model cost per protected workload and account;
- hosted cell provisioning/activation time;
- upgrade/rollback and DR drill success;
- support time per cell;
- cell infrastructure and model contribution margin;
- retention/churn and willingness to pay.

Telemetry must follow the privacy allowlist in the evaluation plan.

## 8. Pricing experiments, not commitments

Do not meter prompts or seats. Test value around protected workloads and managed operation:

| Offer | Initial research range |
| --- | --- |
| Community | Free |
| Cloud Starter | $49/month for up to 10 protected workloads |
| Cloud Team | $149/month for up to 50 workloads and priority support/history |
| Fleet/MSP | $299/month platform minimum plus $2–$4/protected workload |
| Managed storage | Separate capacity/egress offering later |

Managed AI should be included under a reasonable-use/cost budget. Research targets:

- model cost below 5% of subscription revenue;
- positive per-cell contribution margin before GA;
- pricing sufficient for dedicated-cell infrastructure and support;
- customer-owned storage preferred initially to reduce custody and egress complexity.

These ranges require interviews and pilot evidence before publication.

## 9. Six-to-twelve-month continuation

### Months 4–6 — private Cloud alpha

- automate dedicated cells;
- managed inference gateway;
- central health/release registry;
- three to five manually supported design partners;
- safe evidence bundles and recovery briefs;
- repeated cell metadata recovery drills;
- publish alpha SLOs/exclusions, no formal SLA.

### Months 7–9 — paid beta

- at least five, target ten, paying customers or explicit rethink decision;
- SSO and audit export for Team tier;
- protected-workload/cell billing;
- staffed on-call and incident communications;
- recovery-rehearsal workflow;
- external security review;
- hosted terms, privacy, DPA, and subprocessors.

### Months 10–12 — read-only Fleet beta

- outbound mTLS connector;
- organization/customer hierarchy;
- cross-instance readiness and failure patterns;
- policy templates/drift;
- delegated customer views;
- SCIM/SLA only after operational evidence;
- managed storage considered only after BYOS operations are stable.

## 10. Final acceptance checklist

### Community preview

- [ ] Exact implementation base and migration path recorded.
- [ ] AI defaults off and core remains independent.
- [ ] Explicit objectives and deterministic rules documented.
- [ ] Scope/redaction/secret-canary suites pass.
- [ ] No opaque readiness score or AI proof claim.
- [ ] Data preview, disable, expiry, deletion, and export documented.
- [ ] Full existing reliability suite green.
- [ ] Accessibility/responsive/operator documentation reviewed.

### AI beta

- [ ] Isolated runtime and durable replay pass.
- [ ] All zero-tolerance gates pass.
- [ ] Quality thresholds pass on frozen corpus.
- [ ] Model/provider terms and retention approved.
- [ ] Kill switch and rollback exercised.
- [ ] Online pilot metrics meet target.

### Hosted private beta

- [ ] Dedicated-cell isolation demonstrated.
- [ ] Idempotent provisioner passes 20 fault-injected lifecycles.
- [ ] Scoped credentials, lane-separated keyring custody, MFA, and support audit pass.
- [ ] Ten staged upgrades pass.
- [ ] Three clean-environment DR drills pass.
- [ ] Customer export/deletion path works.
- [ ] Current provider live/cleanup/credential gates are accurately represented.
- [ ] No SLA or enterprise claim beyond evidence.

### Hosted GA

- [ ] Independent security review has no unresolved critical/high issue.
- [ ] At least 90 days of measured SLO evidence.
- [ ] Staffed incident response and tested communications.
- [ ] Legal/privacy/licensing/source/trademark documentation complete.
- [ ] Positive and sustainable per-cell economics.
- [ ] Customer-owned storage and recovery workflows have production evidence.
