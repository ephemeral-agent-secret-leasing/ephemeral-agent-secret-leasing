# Low-level design

The broker checks SPIFFE-ID glob policy, fetches a backend value, binds the lease to SPIFFE ID and certificate SHA-256, registers the value in the taint registry, and enforces TTL/use counts. Backends include AES-256-GCM envelope JSON storage, dynamic tokens, and Vault KV v2. Audit logs are Ed25519-signed hash chains.
