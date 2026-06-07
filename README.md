# AWS Behavioral Anomaly Detection with SOAR Auto-Response

A cloud detection-and-response pipeline built entirely on native AWS primitives
and managed with Terraform. It learns each IAM principal's normal behavior,
flags out-of-character activity, and runs an automated, human-gated incident
response playbook, containment, forensic evidence capture, Slack notification,
and auto-filed GitHub incident tickets.

Built end-to-end as a security engineering portfolio project, including the
real failure modes hit along the way and how they were root-caused and fixed.

---

## What it does

For every IAM principal, the system records the tuple
`(principal, eventName, awsRegion, sourceIP_ASN)`. A tuple never seen before —
on a principal older than a 7-day baseline warm-up, is flagged as a behavioral
anomaly. When that happens, a SOAR (Security Orchestration, Automation and
Response) pipeline takes over:

1. Tags the principal as under investigation
2. Pauses for human approval via a Slack link (Step Functions callback token)
3. On approval, attaches a `Deny *` policy to contain the principal
4. Snapshots the principal's recent CloudTrail activity to an evidence bucket
5. Posts a structured notification to Slack
6. Auto-files a GitHub issue with severity, evidence, and a triage checklist

Every step emits an audit event to a dedicated EventBridge bus, producing a
forensic timeline of the response itself.

## Architecture

![Architecture](docs/architecture.png)

The pipeline spans three layers:

- **Telemetry (Phase 1):** multi-region CloudTrail with log-file validation and
  KMS encryption, delivered to both an encrypted S3 bucket and CloudWatch Logs;
  GuardDuty and AWS Config enabled as foundational coverage.
- **Detection (Phase 2):** a CloudWatch Logs subscription filter streams events
  to a Lambda that maintains per-principal baselines in DynamoDB, enriches
  source IPs to ASNs with a bundled offline routing table, enforces the warm-up
  guard, and publishes anomalies to SNS.
- **SOAR (Phase 4):** SNS triggers a responder Lambda (with a break-glass
  exemption check) that starts a Step Functions state machine implementing the
  six-step playbook, with API Gateway closing the human-approval loop.

## Why native AWS instead of a SIEM platform

The original plan considered deploying Matano or Panther Community Edition. Both
were rejected: Matano's open-source project is effectively abandoned, and Panther
deprecated its self-hostable community edition. More importantly, building the
detection engine on native primitives (EventBridge, Lambda, DynamoDB, Step
Functions) demonstrates understanding of *how* behavioral detection and SOAR
orchestration work, rather than how to configure someone else's tool.

## Lessons learned (the honest part)

This project hit real systems-behavior failures during testing. Documenting them
is part of treating it as engineering, not a tutorial:

- **Self-lockout.** The containment playbook will contain whatever principal an
  alert names, including, on one run, the admin user itself. An explicit `Deny`
  on an IAM user overrides `AdministratorAccess`, so the admin was locked out and
  had to be recovered via the root user (which is exactly why root MFA was set up
  and locked away in Phase 0). **Fix:** a break-glass exemption list in the
  responder that alerts and tickets exempt principals (root, admins, the
  pipeline's own roles) but never auto-contains them.

- **Dormant high-privilege principals look anomalous.** Because the root user had
  no baseline, every root action fired an anomaly, flooding the pipeline and
  nearly starting containment playbooks against root. Same root cause as the
  self-lockout, same fix.

- **Cross-platform binary builds.** The ASN-lookup library ships a C extension.
  Building it on an Apple Silicon Mac produced a macOS/arm64 binary that Lambda's
  Linux runtime can't load. **Fix:** compile inside the AWS SAM build container
  for the exact target runtime, and run the Lambda on arm64 to match.

- **Silent Slack failures.** Malformed Block Kit buttons (caused by an unset
  environment variable) made Slack drop the approval message while still
  returning HTTP 200, so the state machine waited forever for an approval that
  could never be clicked. **Fix:** ensure the API endpoint env var is wired
  through Terraform, and log the outgoing payload for diagnosis.

These are in the runbooks and the design where relevant, the exemption guard is
called out directly in the architecture diagram.

## Detection coverage

Mapped to MITRE ATT&CK for Cloud (IaaS) and D3FEND. Full table with honest gap
analysis: [docs/mitre-attack-coverage.md](docs/mitre-attack-coverage.md).

Highlights: T1098.001 (Additional Cloud Credentials), T1098.003 (Additional
Cloud Roles), T1078.004 (Valid Accounts: Cloud), T1562.008 (Disable Cloud Logs),
with containment mapped to D3FEND Account Locking (D3-AL).

## Runbooks

SOC-style response runbooks, one per detection class:

- [Novel principal behavior tuple](runbooks/novel-principal-tuple.md)
- [IAM privilege escalation](runbooks/iam-privilege-escalation.md)
- [CloudTrail / audit logging tampering](runbooks/cloudtrail-tampering.md)

## Demo

https://www.dropbox.com/scl/fi/73h485pd4yz0sg6b2z1oj/aws-SOAR-demo.mov?rlkey=gdlvtx60zs6bn7qzvflzc4iu4&st=y2jq4ih8&dl=0 — 3-minute walkthrough: trigger → detection → Step Functions →
Slack approval → containment → GitHub issue>

## Project structure

```
.
├── terraform/
│   ├── phase1/   # CloudTrail, GuardDuty, Config, KMS, S3
│   ├── phase2/   # detector Lambda, DynamoDB baselines, SNS
│   ├── phase3/   # test users, baseline activity generator
│   └── phase4/   # responder, Step Functions playbook, API Gateway
├── scripts/phase3/   # anomaly trigger script
├── runbooks/         # SOC response runbooks
└── docs/             # architecture diagram, MITRE mapping, screenshots
```

## Reproducing from scratch

Prerequisites: an isolated AWS account, AWS CLI v2, Terraform ≥ 1.6, Docker
(for building the Lambda C extension), a Slack incoming webhook, and a GitHub
PAT scoped to one private repo.

Each phase is an independent Terraform workspace. Apply in order:

```bash
# Configure: copy example.tfvars to terraform.tfvars in each phase dir,
# fill in account_id, region, and (phase 4) Slack/GitHub values.

cd terraform/phase1 && terraform init && terraform apply
cd ../phase2        && terraform init && terraform apply
cd ../phase3        && terraform init && terraform apply
cd ../phase4        && terraform init && terraform apply
```

Phase 3 begins a 7-day baseline accumulation. After warm-up, trigger a test
anomaly:

```bash
AWS_PROFILE=security-lab python3 scripts/phase3/trigger_anomaly.py
```

GuardDuty requires one-time console enablement before its Terraform resource can
be imported (`terraform import aws_guardduty_detector.main <detector-id>`); see
the phase 1 notes.

## Cost

Designed to run under a $10/month billing alarm. Actual steady-state cost:

| Component | Monthly |
|---|---|
| KMS customer-managed key | ~$1 |
| GuardDuty (after 30-day trial) | ~$2–4 |
| AWS Config (quiet lab) | <$1 |
| Secrets Manager (Slack + GitHub) | ~$1 |
| Lambda, DynamoDB, Step Functions, SNS, EventBridge, API Gateway | ~$0 (free tier) |
| S3 (logs + evidence, short lifecycle) | ~$0 |
| **Total** | **~$5–7/month** |

Teardown (below) returns the account to $0.

## Teardown

Destroy in reverse order to respect dependencies:

```bash
cd terraform/phase4 && terraform destroy
cd ../phase3        && terraform destroy
cd ../phase2        && terraform destroy
cd ../phase1        && terraform destroy
```

GuardDuty and a few one-time console resources require a manual final sweep — see
the teardown checklist.

## What I'd build next

- A dedicated, warm-up-bypassing, auto-containing rule for CloudTrail/Config/
  GuardDuty tampering (the highest-value gap, documented in the tampering runbook)
- Integrate GuardDuty findings into the same SOAR response pipeline
- Geo and known-good-IP layers on top of ASN granularity
- Athena-over-S3 for evidence queries instead of the rate-limited
  `cloudtrail:LookupEvents` API
- Tighten the admin IAM user from `AdministratorAccess` to a scoped policy
  (started broad deliberately to focus on the security content; narrowing it is a
  documented follow-up)

---

*Built as a hands-on cloud security engineering project. Infrastructure is
Terraform; detection and response logic is Python on Lambda and Step Functions.*
