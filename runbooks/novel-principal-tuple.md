# Runbook: Novel Principal Behavior Tuple

**Detection rule:** `novel_principal_tuple`
**Severity:** Medium (escalates to High based on event — see triage)
**Owner:** Cloud Security
**Last reviewed:** 2026-06

---

## Summary

The behavioral detector flagged an IAM principal performing an action it has
never performed before, from a region/network it has never used before, after
the principal's 7-day baseline warm-up period had elapsed. The alerting unit is
the tuple `(principal_arn, eventName, awsRegion, sourceIP_ASN)`. A never-seen
tuple on a mature principal is treated as anomalous.

This is a behavioral signal, not a known-bad signature. It means "this is out of
character for this identity," which may be benign (new legitimate activity) or
malicious (credential compromise, insider action).

## Trigger conditions

All of the following are true:
- The tuple has not been recorded in the `seen_tuples` DynamoDB table.
- `principal_age_days >= 7` (the principal is past warm-up).
- The `eventName` is not in the noise-suppression list (`AssumeRole`,
  `GetCallerIdentity`, `Decrypt`, `GenerateDataKey`,
  `DescribeInstanceInformation`).
- The principal type is not `AWSService` or `AWSAccount`.

## Triage steps

1. **Read the alert payload.** The Slack message and SNS email contain
   `principal_arn`, `event_name`, `aws_region`, `source_ip`, `source_ip_asn`,
   and `cloudtrail_event_id`.

2. **Classify severity by event_name.** Treat as **High** if the event is one
   of: `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`,
   `PutBucketPolicy`, `DeleteTrail`, `StopLogging`, `CreateUser`,
   `CreateLoginProfile`. These are persistence/privilege-escalation/defense-
   evasion actions. Otherwise Medium.

3. **Pull the evidence snapshot.** The SOAR playbook wrote a JSON snapshot to
   the evidence S3 bucket (`s3://security-lab-evidence-.../snapshots/<user>/`).
   It contains the principal's last 24h of CloudTrail activity. Review for:
   - Other novel actions clustered around the trigger event
   - A burst of activity after a quiet period
   - Source IP / ASN changes mid-session

4. **Determine if the ASN is the anomaly or the action is.** If the action is
   routine for this principal but the ASN is new, suspect credential theft or
   session hijack. If the action is new but the ASN matches the principal's
   normal network, suspect legitimate new work or insider privilege abuse.

5. **Check for false-positive causes:**
   - Did the user start a legitimately new task (new project, new region rollout)?
   - Did an automation/CI principal get a new pipeline step?
   - Is the source ASN a VPN/corporate egress the user newly adopted?

## Containment

If the alert is assessed as a true positive:

- The SOAR playbook has already requested approval in Slack. Click **Approve
  containment** to apply the `Deny *` inline policy, or contain manually:
aws iam put-user-policy --user-name <USER> 
--policy-name SOAR-QuarantineDenyAll 
--policy-document '{"Version":"2012-10-17","Statement":[{"Sid":"QuarantineDenyAll","Effect":"Deny","Action":"","Resource":""}]}'

- The principal retains its identity (for forensics) but can perform no actions.
- **Do not delete the principal** — preserve it for investigation.

## Eradication

- Rotate or delete any credentials the principal holds
  (`aws iam list-access-keys --user-name <USER>`, then delete the compromised
  key). Note: deletion requires removing the quarantine Deny first or using an
  admin identity.
- If a new access key, login profile, or policy was created by the attacker,
  remove it.
- Review and revoke any sessions the principal had open
  (`aws iam` does not directly revoke sessions; attach a Deny with a
  `aws:TokenIssueTime` condition if active STS tokens must be killed).

## Recovery

- Once eradication is confirmed, remove the quarantine:
aws iam delete-user-policy --user-name <USER> --policy-name SOAR-QuarantineDenyAll
aws iam untag-user --user-name <USER> --tag-keys quarantine quarantine_event_id quarantine_detected_at

- Re-issue legitimate credentials to the user through the normal provisioning path.
- The principal's baseline resumes; the action that triggered the alert is now
  recorded, so a legitimate repeat won't re-alert.

## Known limitations

- A single novel tuple fires once; repeated abuse of the same tuple is silenced
  after the first alert. Frequency-based abuse needs a separate detection layer.
- Within the 7-day warm-up, the principal generates no alerts — a new principal
  compromised early is blind to this rule.
- ASN granularity is coarse; intra-ASN pivots (e.g., within AWS) are invisible.

## Related

- MITRE: T1098.001, T1098.003, T1078.004
- Escalation path for privilege-escalation events: see
  `iam-privilege-escalation.md`