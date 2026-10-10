<div align="center">
  <img src="./banner.svg" alt="oauth-auditor" width="800">
</div>

# oauth-auditor

A small, dependency-free OAuth/OIDC configuration auditor. It audits local OIDC
discovery JSON without network access, or fetches one discovery document using a
bounded read-only request. It does not sign in, submit credentials, obtain
tokens, or send authorization requests.

## Requirements

Python 3.7 or newer; only the Python standard library is required.

## Usage

Audit a saved discovery document entirely offline:

```bash
python oauth_auditor.py audit discovery.json --issuer https://id.example.test
```

Fetch OIDC discovery for an issuer:

```bash
python oauth_auditor.py discover https://id.example.test
```

`discover` accepts HTTPS issuers (HTTP is permitted only for loopback fixture
servers). The request uses a 5-second socket timeout, reads at most 1 MiB, and
refuses cross-origin redirects. Issuer and metadata URLs are validated before
use.

Validate authorization and redirect URI syntax without sending a request:

```bash
python oauth_auditor.py probe https://id.example.test/authorize --redirect https://app.example.test/oauth/callback
```

The `probe` command is intentionally offline. It cannot verify that a redirect
URI is registered or determine how the authorization server matches it.
Redirect URIs may use HTTPS, loopback HTTP, or a native-app URI scheme.

All commands print JSON; use `--out result.json` to save it. Invalid input or
failed discovery returns a nonzero exit status.

## Interpreting results

`findings` contain issues evidenced by the inspected metadata, including issuer
mismatches and advertised implicit response types or password grants. An
advertised capability is not proof that a specific client can use it.
`assumptions` clearly identify checks that metadata cannot establish: missing
PKCE metadata does not prove PKCE is unsupported, and advertising
`token_endpoint_auth_methods_supported: ["none"]` is valid for public clients
and is not itself a vulnerability.

This tool does not test runtime behavior, client registrations, token handling,
or JWKS key quality. Treat its output as configuration evidence, not a complete
security assessment.

## Tests

Tests use only local HTTP fixtures and mocks:

```bash
python -m unittest discover -s tests -v
```

## Disclaimer

Use only for systems you are authorized to assess.

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)
