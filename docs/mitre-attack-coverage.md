# MITRE ATT&CK Coverage — AWS Behavioral Anomaly Detection with SOAR

This document maps the detection and response capabilities of this project to
the [MITRE ATT&CK for Cloud (IaaS)](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
matrix. Defensive response actions are additionally mapped to
[MITRE D3FEND](https://d3fend.mitre.org/) where applicable.

The core detection is a per-principal behavioral baseline: for every IAM
principal, the tuple `(principal, eventName, awsRegion, sourceIP_ASN)` is
recorded. A never-before-seen tuple on a principal older than the 7-day
warm-up window is flagged anomalous. This is a **behavioral** detection
strategy, so it covers techniques by *deviation from a learned baseline*
rather than by signature. The table below lists the techniques most
relevant to the test scenarios and the detection's design intent.

## Detection coverage

| Tactic | Technique | ID | How this project detects it |
|---|---|---|---|
| Persistence / Privilege Escalation | Account Manipulation: Additional Cloud Credentials | T1098.001 | A principal calling `iam:CreateAccessKey` for the first time produces a novel tuple. This is the primary anomaly demonstrated end-to-end in the project. |
| Persistence / Privilege Escalation | Account Manipulation: Additional Cloud Roles/Permissions | T1098.003 | First-time `iam:AttachUserPolicy` / `iam:PutUserPolicy` by a principal is a novel `eventName` tuple and fires. |
| Defense Evasion | Modify Cloud Resource: Storage policy change | T1098 / T1525 | First-time `s3:PutBucketPolicy` by a principal is novel and fires; relevant to data-exposure and backdoor scenarios. |
| Initial Access / Defense Evasion | Valid Accounts: Cloud Accounts | T1078.004 | The ASN component of the tuple means a principal acting from a never-seen network (e.g., AWS → residential ISP, or a new hosting provider) fires even if the API call itself is routine. This is the credential-theft / session-hijack detection vector. |
| Defense Evasion | Impair Defenses: Disable or Modify Cloud Logs | T1562.008 | `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail` are novel high-severity tuples. **Detection is in place** (any novel tuple fires); a dedicated severity rule for these is a documented next step (see Gaps). |
| Discovery | Cloud Service Discovery | T1526 | Unusual enumeration patterns (e.g., a principal that never lists IAM suddenly calling `iam:ListUsers` from a new region) surface as novel tuples. Coverage is incidental, not targeted. |
| Collection / Exfiltration | Data from Cloud Storage | T1530 | First-time `s3:GetObject` patterns from a new ASN can fire, but high-volume read baselining is noisy; this is partial coverage. |

## Response action mapping (MITRE D3FEND)

| Response step | D3FEND technique | ID | Description |
|---|---|---|---|
| Apply inline `Deny *` policy (quarantine) | Account Locking | D3-AL | After human approval, the offending principal is denied all actions, containing an active compromise without deleting the identity (preserving forensic state). |
| Tag principal `quarantine=true` | Administrative Account Management | D3-AAM | Passive audit marker applied before the approval gate; flags the principal as under investigation for any other operator. |
| CloudTrail evidence snapshot to S3 | Operating System Monitoring / Forensic capture | — | Captures the principal's recent activity at incident time for offline forensics, independent of log-retention windows. |
| Break-glass exemption check | (design control) | — | Prevents automated containment of root, admin, and SOAR's own roles — a deliberate guardrail against self-lockout, learned from a real failure during testing. |

## Coverage gaps and honest limitations

A behavioral baseline is powerful but has known blind spots. Documenting them
is part of treating this as real security engineering:

1. **First-7-days blindness.** The warm-up window means a principal compromised
   within its first week generates no alerts. Mitigation in a real environment:
   shorten warm-up for high-privilege principals, or seed baselines from a
   trusted historical period rather than learning live.

2. **Slow-and-low evasion.** An attacker who only performs actions the principal
   has done before, from the same ASN, evades the tuple model entirely. This
   detection complements — does not replace — signature and threshold-based
   detection (which is why GuardDuty is also enabled).

3. **ASN granularity.** Large cloud and CDN ASNs (e.g., AWS 16509) bucket huge
   IP ranges, so intra-ASN pivots are invisible. A production system would add
   geo and known-good-IP layers.

4. **Single-occurrence alerting.** Once a novel tuple fires, it's recorded and
   won't fire again. Repeated abuse of the same tuple is silenced. This is
   standard baseline behavior but means frequency-based detection must come from
   another layer.

5. **GuardDuty and AWS Config are enabled but not yet integrated** into the
   custom detection pipeline. They provide foundational managed-threat and
   resource-state coverage; wiring GuardDuty findings into the same SOAR
   response pipeline is the highest-value next iteration.

6. **No detection for `cloudtrail:StopLogging` / `DeleteTrail` as elevated
   severity.** These fire as ordinary novel tuples today. Because log-tampering
   is a defense-evasion precursor to almost every serious attack, a dedicated
   high-severity rule (bypassing warm-up, escalating directly) is the most
   important detection to add next.

## Summary

The project provides targeted behavioral detection for the credential-abuse and
privilege-escalation techniques most associated with AWS account compromise
(T1098.x, T1078.004), with an automated, human-gated containment response mapped
to D3FEND account-locking. It is explicitly designed as one layer in a
defense-in-depth strategy, not a complete detection program — the gaps above
define the roadmap.