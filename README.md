# OIDC config check

Review what your identity provider advertises. Point it at an issuer, or paste its `/.well-known/openid-configuration`, and it flags the flows it still allows, PKCE, signing algorithms, client authentication and the newer defenses, against [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html), the [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700) and [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725).

**Use it in the browser:** [jamalsjones.github.io/oidc-config-check](https://jamalsjones.github.io/oidc-config-check/). Your browser fetches the document from your provider directly; nothing goes through a server of mine. Some providers block cross-site requests, in which case paste the JSON instead.

## What it checks

| Area | Flags |
|---|---|
| Issuer | missing, not https, has a query or fragment, doesn't match the URL it came from |
| Endpoints | any endpoint over plain HTTP, endpoints on hosts other than the issuer's |
| Flows | implicit and token-returning hybrid flows, the password grant, no plain `code` flow |
| PKCE | not advertised, `S256` missing, `plain` allowed |
| Signing | `none` accepted, RS256 missing, only shared-secret algorithms |
| Client auth | shared secrets only, with no `private_key_jwt` or mTLS |
| Defenses | no `iss` in authorization responses (RFC 9207), no PAR, no DPoP or mTLS-bound tokens, unrestricted `request_uri`, open dynamic registration, no logout or revocation endpoint |

A discovery document says what a provider offers, not how each client is set up. A provider that still offers the implicit flow is worth fixing even if none of your apps use it, because any client registered later can.

## In a pipeline

`oidc-config-check.js` is one file with no dependencies, shared by the page and the command line. Run it on a schedule against each of your issuers to catch a setting that gets turned back on. It exits 1 on errors.

```bash
node oidc-config-check.js https://login.example.com
node oidc-config-check.js discovery.json --fail-on warn
curl -s https://login.example.com/.well-known/openid-configuration | node oidc-config-check.js --json
```

`examples/` has a legacy and a modern configuration to compare.

## Make it yours

Fork it and adjust the levels to your policy: if your organization has banned the implicit flow, make that an error instead of a warning. Each check is a few lines in `check()`; add a test in `test/` and run `npm test` (Node 18 or later, nothing to install).

To host your own copy, turn on GitHub Pages for your fork (Settings → Pages → deploy from the `main` branch).

## Related

- [SAML check](https://github.com/jamalsjones/saml-check): review SAML responses, requests and metadata.
- [JWT lint](https://github.com/jamalsjones/jwt-lint): check the access tokens your provider mints.
- [Leaver check](https://github.com/jamalsjones/leaver-check): find accounts that outlived the people who owned them.

## Author

Jamal Jones. Fifteen years leading enterprise identity. More at [jamalsjones.com](https://www.jamalsjones.com).

MIT licensed.
