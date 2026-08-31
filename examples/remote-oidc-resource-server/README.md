# Remote OIDC resource server

Remote mode is fail-closed and expects an existing OIDC authorization server. It
does not issue identities or tokens. A reviewed configuration supplies:

```yaml
listeners:
  remote:
    tls_certificate: /run/gaugemesh/tls.crt
    tls_private_key: /run/gaugemesh/tls.key
    public_origin: https://mesh.example.test/
    issuer: https://id.example.test/
    audience: gaugemesh
    resource: https://mesh.example.test/
    jwks_url: https://id.example.test/.well-known/jwks.json
    required_scopes: [gaugemesh.invoke]
    trusted_proxies: [192.0.2.10]
policy:
  default: deny
  rules:
    - id: allow-reviewed-tenant-mcp
      phase: request_metadata
      priority: 1
      effect: allow
      all:
        - field: tenant.id
          equals: tenant-a
        - field: request.protocol
          equals: mcp
```

Use deployment-specific absolute certificate/key paths and policy values; do not
copy the documentation addresses into a live configuration. Startup and requests
validate TLS material, issuer, audience, resource, expiry, not-before, key ID,
scope, public origin, proxy trust, and policy. The test suite uses local OIDC/JWKS
fixtures; no external identity provider is claimed as verified.
