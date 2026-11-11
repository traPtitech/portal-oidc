# Portal identity integration

Portal provisions authentication accounts through the internal API in
`api/internal.openapi.yaml`. Set `OIDC_INTERNAL__TOKEN` to the same value as
Portal's `PORTAL_INTERNAL_TOKEN`. If the token is empty, the server does not
register the internal routes. Expose these routes only to Portal on the service
network.

`POST /internal/users/provision` stores the account under the Portal user UUID.
The account keeps the SHA-256 verifier that Portal sends. It does not keep the
password or the auth secret. A request that repeats a stored account exactly
returns 200. A request with the same UUID and different content returns 409. A
request with an email that another account uses also returns 409. A request
whose `expiresAt` is not in the future returns 422.

Portal calls provision before it commits its own transaction. For this reason,
provisioning does not read the Portal database. `DELETE /internal/users/{userId}`
removes the account after a confirmed provision and a confirmed Portal rollback.
It does not stop a delayed POST. If a provision response is lost, operators must
compare the UUID in both databases before they retry or delete anything.
