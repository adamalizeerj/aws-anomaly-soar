# Runbook: IAM Privilege Escalation

**Applies to events:** `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`,
`AttachRolePolicy`, `PutRolePolicy`, `CreateLoginProfile`, `UpdateLoginProfile`,
`CreatePolicyVersion`, `AddUserToGroup`
**Severity:** High
**Owner:** Cloud Security
**Last reviewed:** 2026-06

---

## Summary

An IAM principal performed an action that grants itself or another identity
additional access. In an attack chain, this is the step where an adversary who
has obtained a foothold expands it — minting new credentials, attaching broader
policies, or creating persistence. Because the behavioral detector flags these
as novel tuples and severity is High, treat as a probable active intrusion until
proven otherwise.

## Trigger conditions

A novel-principal-tuple alert (see `novel-principal-tuple.md`) where the
`event_name` is one of the privilege-escalation APIs listed above.

## Triage steps

1. **Establish blast radius immediately.** What did the escalation grant?
   - `CreateAccessKey`: a new long-lived credential now exists. Identify the key
     ID from the evidence snapshot's `request_parameters` / `responseElements`.
   - `AttachUserPolicy` / `PutUserPolicy`: what policy, and what does it permit?
     Pull the policy document.
   - `CreateLoginProfile`: a console password was set on a previously
     programmatic-only user — strong compromise signal.

2. **Identify the acting principal vs. the target.** The escalation may be a
   principal modifying *itself* (self-escalation) or *another* identity (lateral
   movement). Both are in the CloudTrail event's `userIdentity` (actor) and
   `requestParameters` (target).

3. **Correlate with the source ASN.** A privilege-escalation action from a novel
   ASN is near-certainly malicious. From the principal's normal ASN, it may be a
   misconfigured automation or a legitimate admin task — verify with the owner.

4. **Hunt for the precursor.** Privilege escalation rarely happens first. Query
   the evidence snapshot and CloudTrail for what this principal did in the hours
   before — initial access, discovery, the credential that was used.

## Containment

**Contain fast — this event class warrants immediate action.**

- Approve the SOAR containment in Slack, or apply the Deny manually (see
  `novel-principal-tuple.md` → Containment).
- **Additionally**, neutralize what the escalation created:
  - New access key: deactivate then delete it.
aws iam update-access-key --user-name <TARGET> --access-key-id <NEW_KEY> --status Inactive
aws iam delete-access-key --user-name <TARGET> --access-key-id <NEW_KEY>
  - Attached policy: detach or delete the inline policy.
  - New login profile: delete it (`aws iam delete-login-profile`).

## Eradication

- Enumerate everything the actor touched in the session and reverse each change.
- Rotate credentials for **both** the acting principal and any target identity.
- If a role was involved, review its trust policy for tampering.
- Search other principals for the same novel behavior — escalation is often
  performed across multiple identities to establish redundant persistence.

## Recovery

- Remove quarantine once eradication is verified.
- Restore legitimate access through normal provisioning.
- If this was a real compromise, file for a broader account review: were other
  services (S3, EC2, Lambda) touched using the escalated access?

## Known limitations

- If the attacker escalated using an action the principal had performed before
  (rare for these APIs, but possible for automation principals), the tuple is
  not novel and this rule does not fire. GuardDuty's IAM-focused findings are the
  backstop.

## Related

- MITRE: T1098.001 (Additional Cloud Credentials), T1098.003 (Additional Cloud
  Roles)
- Base detection: `novel-principal-tuple.md`