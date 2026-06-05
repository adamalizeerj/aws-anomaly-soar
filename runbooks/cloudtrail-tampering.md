# Runbook: CloudTrail / Audit Logging Tampering

**Applies to events:** `StopLogging`, `DeleteTrail`, `UpdateTrail`,
`PutEventSelectors` (when narrowing coverage), `DeleteFlowLogs`
**Severity:** Critical
**Owner:** Cloud Security
**Status:** Detection partially implemented — see Known Limitations
**Last reviewed:** 2026-06

---

## Summary

A principal attempted to disable, delete, or weaken the account's audit logging.
This is a defense-evasion action (MITRE T1562.008) and is almost never
legitimate outside a planned, change-managed event. Disabling CloudTrail is a
common precursor to a larger attack — the adversary is trying to go dark before
acting. Treat as **Critical** and respond before the logging gap widens.

## Trigger conditions

Today, these events fire through the standard novel-principal-tuple rule like
any other API. There is **not yet** a dedicated bypass-warmup, auto-escalate
rule for them (see Known Limitations). When the dedicated rule is added, it
should fire regardless of warm-up state and skip the human-approval gate for
containment, because the cost of a logging gap is high and time-sensitive.

## Triage steps

1. **Confirm logging state right now.**
aws cloudtrail get-trail-status --name security-lab-trail
aws cloudtrail describe-trails
   Check `IsLogging: true` and that the trail still exists with multi-region and
   validation enabled.

2. **Identify the actor** from the triggering CloudTrail event's `userIdentity`.
   Note: if logging was successfully stopped, you have a blind spot starting at
   the `StopLogging` timestamp. Everything after is invisible until restored.

3. **Establish the gap window.** From the event time of the tampering to the
   moment logging is restored is your forensic blind spot. Record it.

4. **Check log-file integrity** for the period before tampering using the digest
   validation:
aws cloudtrail validate-logs --trail-arn <ARN> --start-time <BEFORE_TAMPER>
   This proves whether pre-tampering logs were also altered.

## Containment

**Restore logging first — it is the priority over containing the principal,**
because every second of gap compounds the investigation difficulty.

- Re-enable the trail:
aws cloudtrail start-logging --name security-lab-trail
- If the trail was deleted, recreate it from the Terraform in `terraform/phase1`
  (`terraform apply`) — the IaC definition is the source of truth.
- Then contain the acting principal (Deny policy, as in
  `novel-principal-tuple.md`).

## Eradication

- Rotate the acting principal's credentials.
- Review what happened during the logging gap using any secondary telemetry:
  GuardDuty findings, VPC Flow Logs, AWS Config timeline, S3 access logs, billing
  anomalies. Reconstruct the gap as best as possible from sources the attacker
  may not have disabled.
- Verify no other defenses were weakened (Config recorder stopped, GuardDuty
  detector disabled, SCPs altered).

## Recovery

- Confirm logging is fully restored: multi-region, validation on, delivering to
  both S3 and CloudWatch Logs.
- Remove quarantine once the account is confirmed clean.
- Add a CloudWatch alarm / Config rule that alerts on any future change to the
  trail's logging state, so the next attempt is caught instantly.

## Known limitations

- **This detection is not yet specialized.** Log-tampering events currently fire
  only as ordinary novel tuples, subject to the 7-day warm-up and the standard
  approval gate. The highest-priority improvement to this project is a dedicated
  rule that: (a) fires on these events regardless of warm-up, (b) escalates to
  Critical, and (c) auto-contains without waiting for approval, because a logging
  gap cannot wait for a human to wake up.
- AWS Config (`config:StopConfigurationRecorder`) and GuardDuty
  (`guardduty:DeleteDetector`) tampering should be added to the same dedicated
  rule's event set.

## Related

- MITRE: T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)
- Base detection: `novel-principal-tuple.md`