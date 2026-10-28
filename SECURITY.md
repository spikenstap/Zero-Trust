# Scope and security expectations

This is a local educational demonstration with synthetic medical records. Seed usernames and the shared demo password are intentionally public. The UI deliberately logs in as any demo role, offers an explicit separate admin audit observer, and exposes a night-simulation header. These are product requirements, not production identity assurance.

Required boundaries: missing, expired or modified JWTs fail with 401; verified identities are checked against DB roles and session versions; doctors see only assigned patients, patients see only themselves, nurses never decrypt diagnosis or notes, admins cannot read patient data. Unknown API actions fail closed. Reset requires admin and revokes all prior JWTs. Every API request is audited without passwords, tokens or medical plaintext. Cryptographic keys must be random and loaded from .env/environment. Frontend must not insert untrusted text as HTML.

Single-process sliding-window limiting, mutable local SQLite audit, unbounded journal retention, public demo credentials, and lack of login throttling / MFA / production TLS are explicit demo limitations. The default network bind is local. No real patient data, external transmissions, or remote deployment are in scope.

Review authentication and object authorization, encryption boundaries, audit attribution, concurrency/reset behavior, browser rendering, secret handling and container configuration. Do not infer production compliance or cryptographic key management from this demo.
