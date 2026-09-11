# Pulp-ext-jwt

Host-owned HS256 JWT signing and verification for Pulp cells.

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-jwt"
```

The provider registers `identity.jwt.hs256` and exports `jwt_sign` and
`jwt_verify`. Requests and responses use MessagePack. The host reads the key
from `PULP_JWT_HS256_SECRET`; it must be a dedicated key used only for this
capability, contain at least 32 bytes, and is never supplied by a cell or
manifest. Sharing the key with another JWT protocol defeats the provider's
cross-protocol boundary. Missing or weak keys fail closed with error code `99`.

Signing accepts `account_id`, `session_id`, and a future `expires_at` Unix
timestamp in milliseconds. Verification accepts `token`, requires an expiry,
accepts only HS256, requires issuer `github.com/BananaLabs-OSS/Pulp-ext-jwt`
and audience `identity.jwt.hs256`, and returns `account_id` and `session_id`.
The provider enforces the caller-supplied expiry but deliberately does not set
a universal maximum TTL: the session owner owns lifetime policy. Verification
does not provide revocation or replay prevention; consumers must resolve the
returned session ID against their authoritative active-session record.

## Development

```sh
go test ./...
go test -race ./...
```
