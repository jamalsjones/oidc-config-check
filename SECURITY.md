# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately instead: **[Report a vulnerability](https://github.com/jamalsjones/oidc-config-check/security/advisories/new)**. Only you and I can see the report.

Tell me what you found, how to reproduce it (a sample input is ideal), and what you think an attacker could do with it.

I maintain this on my own, so I can't promise a fixed response time. I'll reply, keep you posted while I work on a fix, and credit you in the advisory unless you'd rather I didn't.

## Supported versions

Only the latest commit on `main`. That's also what the hosted page at [https://jamalsjones.github.io/oidc-config-check/](https://jamalsjones.github.io/oidc-config-check/) runs. Fixes aren't backported.

## In scope

- A discovery document that makes the page run script
- The page sending anything anywhere other than the issuer you entered (your browser is meant to fetch from your provider directly, and nowhere else)
- A check that misses what this README says it flags, such as `none` accepted as a signing algorithm without a finding
- Anything in the command-line tool that runs code or reads files it wasn't pointed at

## Out of scope

- Providers that block cross-site requests. Paste the JSON instead.
- Findings that are about level (a warning you think should be an error). Open an ordinary issue for those.
