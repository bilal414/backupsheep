# BackupSheep Brand Brief

## 1. Executive strategy

BackupSheep should own a specific position: **the open-source backup and recovery control plane for mixed web infrastructure**.

It should not compete primarily as a backup archive format, storage provider, virtualization appliance, or consumer backup application. Its value is coordinating the appropriate backup and recovery mechanism for websites, databases, cloud resources, and supported applications while giving the operator one place for policy, scheduling, destinations, visibility, retention, teams, and recovery.

### Strategic lock

| Element | Decision |
| --- | --- |
| Brand idea | **Own the way back.** |
| Category | **The open-source backup and recovery control plane.** |
| Promise | **Backups you control. Restores you can trust.** |
| Essence | **Quietly vigilant.** |
| Archetype | **Guardian × Engineer** |
| Primary audience | Responsible infrastructure operator |
| Secondary audience | Multi-client operator: agency, host, MSP |
| Differentiation | Source-native recovery orchestration without BackupSheep taking custody of backup data |
| Creative balance | 70% operational confidence / 30% personality |

---

## 2. Product truth

BackupSheep is a GPLv3 self-hosted application that coordinates backup and recovery across heterogeneous infrastructure.

The product currently supports several distinct mechanisms rather than forcing every workload into one proprietary format:

- Website and file backups over FTP, FTPS, SFTP, and SSH.
- MySQL, MariaDB, and PostgreSQL database dumps using native database tooling.
- Provider-native snapshots for cloud infrastructure.
- Supported application integrations.
- Multiple user-selected storage destinations, including local storage and cloud/object storage.
- Incremental and full website backup modes.
- Retention and scheduling.
- Console-driven website and database restoration.
- Notifications, activity history, teams, groups, and permissions.
- Immutable S3 retention and lifecycle controls where configured.

BackupSheep was previously operated as a paid SaaS from 2017–2023. The current project is a rewritten, self-hosted, open-source application with SaaS billing, quotas, and BackupSheep-hosted storage removed. Historical SaaS adoption may be used as provenance, but it must not be represented as current open-source adoption.

---

## 3. The customer problem

Modern infrastructure is fragmented. A small technical team may simultaneously operate:

- application servers;
- WordPress or other websites;
- PostgreSQL and MySQL databases;
- cloud volumes and managed databases;
- object storage;
- multiple cloud providers;
- client environments with separate access requirements.

Backups are often handled by a combination of provider settings, cron jobs, shell scripts, database dumps, storage tools, and runbooks. Each individual mechanism may work, but the operational system around them is inconsistent.

The customer therefore sits between two undesirable extremes.

### DIY extreme

- Cron and scripts.
- Scattered credentials.
- Provider-specific dashboards.
- Inconsistent monitoring.
- Recovery instructions living in documentation or memory.
- No shared policy or audit surface.

### Commercial-platform extreme

- Another hosted control plane.
- Subscription and resource pricing.
- Product-specific operating assumptions.
- More infrastructure and process than a small team needs.
- Potential vendor dependency in the management path.

### Core tension

> **Enterprise discipline without enterprise backup infrastructure. Open-source control without script sprawl.**

---

## 4. Audience hierarchy

### Primary — The Responsible Operator

The person responsible for recovery even though backup administration is only one part of the job.

Typical roles:

- technical founder;
- developer;
- DevOps/platform engineer;
- Linux/system administrator;
- infrastructure lead;
- agency technical lead.

#### Functional job

> Give me one reliable way to schedule, monitor, store, and recover backups across the infrastructure I already operate.

#### Emotional job

> Let me know that recovery has been accounted for so I do not have to wonder whether last night's green check was meaningful.

#### Social job

> Help me operate with disciplined recovery practices even when I do not have a dedicated backup team.

#### What this user values

- ownership;
- transparent failure states;
- broad infrastructure coverage;
- simple deployment;
- user-selected storage;
- automation without opacity;
- documented recovery;
- low operational overhead.

### Secondary — The Multi-client Operator

Typical roles:

- digital agency;
- managed hosting provider;
- freelance infrastructure consultant;
- small MSP;
- web operations team.

Additional needs:

- client separation;
- group and node/resource scoping;
- granular permissions;
- audit history;
- per-user notifications;
- a central view across many environments.

### Tertiary — The Sovereignty-minded Self-hoster

Values:

- GPL software;
- running the management layer themselves;
- local-storage support;
- selecting their own remote storage;
- avoiding mandatory hosted metadata/control services;
- source inspection and modification.

This community is important, but the brand must remain professional enough that agencies and infrastructure teams do not mistake BackupSheep for a hobby-only homelab tool.

### Not the primary audience

Do not position first for:

- consumer desktop backup;
- family photos and personal-device backup;
- nontechnical turnkey managed backup;
- large-enterprise compliance suites;
- dedicated virtualization backup appliances;
- a single database or filesystem engine.

---

## 5. Competitive frame

BackupSheep overlaps several categories but should not imitate any one of them.

### File/repository backup engines

Their center of gravity is archive format, encryption, deduplication, compression, repository integrity, or filesystem snapshots.

**BackupSheep move:** coordinate multiple mechanisms instead of making its archive format the brand.

### Infrastructure backup appliances

Their center of gravity is VMs, hypervisors, hosts, dedicated datastores, and enterprise infrastructure.

**BackupSheep move:** be a lighter operating layer for mixed websites, databases, cloud infrastructure, and storage.

### Hosted backup control planes

Their center of gravity is convenience, remote management, broad coverage, and subscriptions.

**BackupSheep move:** provide control-plane convenience as software the operator runs.

### Narrow self-hosted tools

Their center of gravity is one workload or one backup engine.

**BackupSheep move:** unify heterogeneous infrastructure while preserving appropriate source-native mechanisms.

### White space

> **Operator-owned recovery orchestration for mixed web infrastructure.**

This is stronger than generic claims such as “open source,” “bring your own storage,” “many destinations,” or “one dashboard,” which are increasingly common across the category.

---

## 6. Positioning

### Full positioning statement

> For developers, infrastructure teams, and agencies operating websites, databases, and cloud resources, BackupSheep is the open-source, self-hosted backup and recovery control plane that coordinates source-native backup methods, sends copies to storage they choose, and makes the recovery path visible. Unlike hosted backup services or single-purpose backup tools, BackupSheep unifies backup operations without taking custody of the data or replacing the underlying recovery mechanisms.

### Concise position

> **The open-source backup and recovery control plane.**

### Plain-language explanation

> **One self-hosted place to schedule, verify, store, and recover backups across websites, databases, and cloud infrastructure.**

### 15-second pitch

> BackupSheep brings website backups, database dumps, and cloud snapshots into one self-hosted console. You choose where copies live, see whether the entire job succeeded, and keep a clear recovery path without another backup SaaS in the middle.

### Repository description

> **Open-source backup and recovery control plane for websites, databases, servers, and cloud infrastructure.**

---

## 7. Purpose, mission, and vision

### Purpose

> **Make recovery an owned capability.**

### Mission

> **Give infrastructure operators one open, self-hosted place to automate, verify, and recover backups across the systems they already run.**

### Vision

> **A world where every team knows what is protected, where its recovery copies live, whether the last job truly worked, and how to get back—without depending on a vendor to own the path.**

---

## 8. Brand archetype

### Guardian — 70%

Represents:

- protection;
- responsibility;
- continuity;
- watchfulness;
- safe return;
- trust earned through consistent behavior.

### Engineer — 30%

Represents:

- precision;
- technical competence;
- explainable systems;
- practical problem solving;
- respect for operational reality;
- evidence instead of reassurance.

### Archetypes to avoid

**Hero:** do not manufacture fear so the brand can perform a dramatic rescue.

**Jester:** the sheep permits wit, but backup failures and restores are not joke surfaces.

**Ruler:** do not sound like an enterprise vendor demanding conformity to its platform.

---

## 9. Brand principles

### Recovery over backup

A completed archive is not the outcome. The outcome is a credible route back.

### Ownership over lock-in

The operator chooses the server, destinations, topology, retention, and recovery workflow. Open source is an expression of ownership, not merely a licensing badge.

### Evidence over optimism

Do not say “your data is safe” when the product can instead show completed copies, command status, validation, logs, retention state, and recovery options.

### Calm over fear

Do not rely on ransomware panic, disaster photography, countdowns, or catastrophe copy. BackupSheep exists to make incidents manageable.

### Character without cuteness

The sheep makes the brand memorable. It should feel alert, dependable, and quietly clever—not helpless, childish, fluffy for decoration, or dressed as a superhero.

---

## 10. Master brand idea

# Own the way back.

The line combines the two central product truths.

**Own** conveys:

- self-hosting;
- open source;
- user-selected storage;
- independence;
- operational control.

**The way back** conveys:

- recovery;
- a known route;
- continuity;
- reversibility;
- preparedness.

It is the emotional brand idea, not a replacement for the technical category descriptor.

### Recommended pairing

> **Own the way back.**  
> The open-source backup and recovery control plane.

---

## 11. Brand guardrails

BackupSheep must never become visually or verbally confused with:

- a consumer cloud-drive application;
- a generic padlock/shield cybersecurity company;
- an enterprise hardware appliance;
- an AI infrastructure product;
- a cute farm or children's brand;
- a fear-based disaster-recovery vendor;
- a proprietary storage service.

### Claim discipline

Historical adoption:

> “The original BackupSheep SaaS served more than 6,500 users from 2017–2023.”

Do not imply those are current open-source users.

Restore claims:

Use “one-click website and database restores” or “console-driven website and database restores.” Do not imply every cloud resource is restored directly inside BackupSheep when provider-native recovery is required.

Data control:

Use “copies go only to destinations you configure” and “no BackupSheep cloud in the data path.” Do not say data never leaves the user's infrastructure because the user may intentionally configure external destinations.

Security:

State implemented controls precisely. Avoid “unhackable,” “bulletproof,” “military-grade,” and similar absolutes.

Reliability:

Prefer observable behavior: exit statuses checked, failed transfers surfaced, disk-space preflight, resumable jobs, tracked restores, protected-copy validation.

---

## 12. Success criteria for the identity

The identity succeeds when:

1. A developer can understand what BackupSheep does within seconds.
2. The brand is recognizable without depending on provider logos or generic cloud imagery.
3. The sheep is memorable at favicon size but does not reduce perceived technical credibility.
4. The product feels appropriate for both a self-hoster and an agency managing client infrastructure.
5. Failure and restore screens remain calm, legible, and operational.
6. Open-source ownership is visible without making the product look unfinished or community-only.
7. Marketing, README, documentation, console, notifications, and social assets feel like one system.
