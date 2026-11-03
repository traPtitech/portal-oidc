# Portal identity integration

The internal API is specified in `api/internal.openapi.yaml`. Configure
`OIDC_INTERNAL__TOKEN` with the same secret as Portal's `PORTAL_INTERNAL_TOKEN`.
An empty token disables the internal routes. Expose these routes only to Portal
through the service network; the token must never be given to a browser.

Apply the OIDC schema before starting the new binary. The Portal database is
owned by Portal and must not be migrated with the OIDC schema task.

Provisioning is synchronous and keyed by the Portal-generated user UUID. The
normalized payload fingerprint makes identical replays successful without
changing credentials; different content or a duplicate email returns 409.
The account stores the supplied SHA-256 verifier, not the password or auth secret.
The membership expiry is not a request timeout. Expired initial requests are
rejected; identical retries still acknowledge a previously committed account.

Portal calls provision before committing its own transaction. There is therefore
no cross-database foreign key or profile lookup during provisioning. DELETE is
compensation for a confirmed provision followed by a confirmed Portal rollback.
It does not fence a delayed POST. After a lost response or uncertain commit,
operators must reconcile the UUID in both databases before retrying registration
or deleting anything. Logs contain UUID and failure category only.

Registration and login ship as separate stacked PRs. Deploy both with the matching
Portal branch; this first PR alone does not enable login for the new credentials.
