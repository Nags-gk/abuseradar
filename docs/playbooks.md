# Response playbooks

Each section is one playbook. Action IDs in square brackets are the only actions the
triage assistant may recommend; anything else is rejected by the grounding guard.

## credential_stuffing
Signals: many failed logins across many accounts from one IP or ASN; usernames that do not exist; scripted user agents; never-seen device fingerprints.
Investigate: count distinct targeted accounts, list any successful logins from the same infrastructure, and check whether those accounts changed MFA, email or paired devices afterwards.
Actions:
- [A1] Block the source IPs at the edge for 24 hours.
- [A2] Require CAPTCHA and email verification for logins from the source ASN for 6 hours.
- [A3] Force a password reset on every account that had a successful login from the attacking infrastructure.
- [A4] Revoke all active sessions and refresh tokens on those accounts.

## password_spray
Signals: one keyed password hash failing on many accounts, low attempts per account, often slow and spread across IPs.
Investigate: check whether the hash ever succeeded; if it did, treat those accounts as compromised.
Actions:
- [A9] Add the password hash to the banned-password list so it can no longer be set or used.
- [A3] Force a password reset on every account where the sprayed password succeeded.
- [A1] Block the source IPs at the edge for 24 hours.

## account_takeover
Signals: a successful login from an ASN and device the account has never used, impossible travel, then MFA, email or device-pairing changes within hours.
Investigate: build the account timeline 24 hours either side, compare networks and devices against history, and list every change made after the suspicious login.
Actions:
- [A5] Freeze the account and roll back MFA and email changes made after the suspicious login.
- [A6] Unpair any device paired after the suspicious login and rotate its credentials.
- [A4] Revoke all active sessions and refresh tokens.
- [A3] Force a password reset and notify the owner through the original email address.

## device_clone
Signals: one device serial checking in from two or more networks within hours; the new network is usually a hosting provider.
Investigate: compare check-in cadence and firmware version from each network; the legitimate device keeps its home network.
Actions:
- [A6] Rotate the device credential and quarantine check-ins from the new network.
- [A7] Revoke the API tokens associated with the cloned device.

## api_enumeration
Signals: one account or token requesting hundreds of sequential device IDs with mostly 403/404 responses.
Investigate: check whether any request returned 200 for a device the account does not own, which would be an authorization flaw.
Actions:
- [A7] Revoke the API token and rate-limit the account to 1 request per second.
- [A10] Open an engineering ticket to replace sequential device IDs with unguessable identifiers.

## fake_account_ring
Signals: many new accounts sharing a few device fingerprints and IPs, followed by promo or referral claims.
Investigate: size the connected component, list promo redemptions, and look for the same fingerprints on older accounts.
Actions:
- [A8] Hold promo and referral payouts for every account in the ring and require phone verification.
- [A1] Block the source IPs at the edge for 24 hours.

## benign
Signals: a traveller logging in from a hotel, a VPN user, a new phone, or a home-automation integration with a scripted user agent.
Investigate: confirm the device or network was later used normally and that no account changes followed.
Actions:
- [A0] Close as benign and add the pattern to the rule's false-positive notes.
