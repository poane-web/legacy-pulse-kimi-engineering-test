# ChatGPT V2 Temporal Adversarial Audit

Target: `chatgpt-v2-temporal-hardening`

Method: attacker-driven review of the actual implementation after the first temporal-hardening pass. No production fix is included in this audit commit.

## Finding C1 — Owner can manufacture trusted-contact quorum

**Severity: CRITICAL**

### Invariant that should hold

For a `trusted_contact_confirmation` release, the owner must not be able to satisfy the independent trusted-contact quorum using identities that they themselves control.

### Attack path

1. Owner creates trusted contact A using the owner's own email address.
2. Owner claims contact A using the owner's authenticated account.
3. Owner repeats the operation with trusted contact B, again using the owner's email.
4. Both contact records become `active` and both have `linked_user_id = owner.id`.
5. Owner creates a pending message requiring two confirmations.
6. Owner calls `POST /api/trusted-contacts/confirm/:messageId` once for each contact record.
7. Confirmation uniqueness is keyed by `(legacy_message_id, trusted_contact_id)`, so the two records count as two distinct confirmations.
8. The message transitions to `released` even though no independent third-party trusted contact participated.

### Code evidence

`trustedContacts.routes.js` allows a trusted-contact invite to be created for any email and allows the authenticated owner to claim an invite addressed to the owner's own email. The confirmation lookup only requires `owner_id = message.owner_id`, `linked_user_id = req.user.id`, and `status = active`; it does not reject `req.user.id === message.owner_id`.

The database also permits multiple trusted-contact records for the same owner/email/user identity.

### Proof

`backend/src/__tests__/adversarialTemporal.test.js` reproduces the complete attack and observes the message reach `released` after two owner-controlled confirmations.

### Required remediation direction

Introduce an explicit authority boundary:

- reject owner-as-trusted-contact at creation and claim time;
- prevent a trusted contact whose `linked_user_id` equals the owner from confirming;
- enforce a meaningful uniqueness/independence invariant for trusted-contact identities;
- re-evaluate confirmation semantics for contacts who become revoked/disabled before release.

Do not merely patch the test. The invariant belongs in the service/database authorization boundary.

## Additional temporal pressure to run next

- concurrent contact creation/claim and confirmation;
- trusted-contact revocation racing with the final confirmation;
- account disable/password-reset/MFA-reset racing with release;
- beneficiary reassignment or identity-link changes racing with release;
- scheduler release racing with owner edits and revocation;
- duplicate notifications after release retries or process restart;
- clock/SQLite process boundaries and migration correctness;
- exactly-once milestone release semantics for future Life Vault birthday/gift triggers.

This document intentionally records the discovered vulnerability before remediation so the attack remains independently reproducible.
