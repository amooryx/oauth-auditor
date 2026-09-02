#!/usr/bin/env python3
"""
OAuth Auditor — OAuth 2.0 / OIDC Security Testing Tool
Tests for common OAuth misconfigurations: open redirects, token leakage, PKCE bypass.
Author: Omar Khalid (amooryx) | github.com/amooryx/oauth-auditor
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
import urllib.error

TESTS = {
    "redirect_wildcard":    "Open redirect via wildcard or lax redirect_uri matching",
    "state_missing":        "CSRF: authorization request lacks state parameter",
    "token_in_fragment":    "Token leakage: implicit flow exposes token in URL fragment",
    "pkce_bypass":          "PKCE bypass: authorization_code flow accepts request without code_challenge",
    "scope_escalation":     "Scope escalation: server grants broader scopes than requested",
    "client_secret_leak":   "Client secret exposed in public client or JS source",
    "token_reuse":          "Authorization code reuse not rejected by server",
}

def check_auth_endpoint(auth_url: str, client_id: str, redirect_uri: str) -> dict:
    """Probe the authorization endpoint for misconfigurations."""
    results = {}

    # 1. Build a minimal auth request
    params = {
        "response_type": "code",
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "scope":         "openid profile email",
        "state":         "audit_test_state",
    }
    full_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
    results["auth_url"] = full_url

    # 2. Test redirect_uri manipulation
    evil_redirects = [
        redirect_uri.replace("https://", "https://evil.example.com@"),
        redirect_uri.rstrip("/") + ".evil.example.com",
        redirect_uri.rstrip("/") + "/../../../evil",
        "https://evil.example.com",
        "javascript:alert(1)",
    ]
    redirect_tests = []
    for evil in evil_redirects:
        p = dict(params)
        p["redirect_uri"] = evil
        test_url = f"{auth_url}?{urllib.parse.urlencode(p)}"
        try:
            req = urllib.request.Request(test_url)
            req.add_header("User-Agent", "OAuthAuditor/1.0")
            # We don't follow redirects — capture the raw 302 location
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs): return None
            opener = urllib.request.build_opener(NoRedirect)
            with opener.open(req, timeout=10) as resp:
                location = resp.headers.get("Location", "")
                redirect_tests.append({
                    "evil_redirect": evil[:80],
                    "result": "ACCEPTED" if evil in location else "REJECTED",
                    "location": location[:100],
                })
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location", "") if e.headers else ""
            accepted = urllib.parse.quote(evil, safe="") in urllib.parse.quote(location, safe="")
            redirect_tests.append({
                "evil_redirect": evil[:80],
                "result": "ACCEPTED (via redirect)" if accepted else f"REJECTED ({e.code})",
            })
        except Exception as ex:
            redirect_tests.append({"evil_redirect": evil[:80], "error": str(ex)})
    results["redirect_uri_tests"] = redirect_tests

    # 3. Test missing state (CSRF)
    no_state_params = {k: v for k, v in params.items() if k != "state"}
    no_state_url    = f"{auth_url}?{urllib.parse.urlencode(no_state_params)}"
    results["missing_state_url"] = no_state_url
    results["note_csrf"] = "If server accepts auth request without 'state', it may be CSRF-vulnerable"

    # 4. Test implicit flow token exposure
    implicit_params = dict(params)
    implicit_params["response_type"] = "token"
    results["implicit_flow_url"] = f"{auth_url}?{urllib.parse.urlencode(implicit_params)}"
    results["note_implicit"] = "If server allows response_type=token, tokens may leak via Referer/history"

    return results

def fetch_oidc_discovery(issuer: str) -> dict:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}

def audit_discovery(cfg: dict) -> list[dict]:
    findings = []
    if cfg.get("response_types_supported") and "token" in cfg["response_types_supported"]:
        findings.append({"severity": "Medium", "issue": "Implicit flow (response_type=token) is supported",
                         "detail": "Tokens may leak via browser history, Referer header"})
    if cfg.get("grant_types_supported") and "password" in cfg.get("grant_types_supported", []):
        findings.append({"severity": "Medium", "issue": "Resource Owner Password Credentials grant supported",
                         "detail": "ROPC bypasses MFA; should be disabled"})
    if not cfg.get("code_challenge_methods_supported"):
        findings.append({"severity": "Medium", "issue": "PKCE not advertised in discovery document",
                         "detail": "Public clients may be vulnerable to code interception"})
    if cfg.get("token_endpoint_auth_methods_supported") == ["none"]:
        findings.append({"severity": "High", "issue": "Token endpoint accepts unauthenticated clients",
                         "detail": "No client authentication enforced"})
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="OAuth Auditor — OAuth 2.0 Security Testing (Authorized use only)",
    )
    subparsers = parser.add_subparsers(dest="cmd")

    disc_p = subparsers.add_parser("discover", help="Audit OIDC discovery document")
    disc_p.add_argument("issuer",   help="OIDC issuer URL (e.g., https://accounts.google.com)")
    disc_p.add_argument("--out",    help="Output JSON file")

    probe_p = subparsers.add_parser("probe", help="Probe authorization endpoint")
    probe_p.add_argument("auth_url",     help="Authorization endpoint URL")
    probe_p.add_argument("--client-id",  required=True)
    probe_p.add_argument("--redirect",   required=True, help="Registered redirect_uri")
    probe_p.add_argument("--out",        help="Output JSON file")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    if args.cmd == "discover":
        print(f"[*] Fetching OIDC discovery: {args.issuer}")
        cfg      = fetch_oidc_discovery(args.issuer)
        findings = audit_discovery(cfg)
        print(f"[+] Discovery fetched. Findings: {len(findings)}")
        for f in findings:
            print(f"  [{f['severity']}] {f['issue']}")
            print(f"         {f['detail']}")
        result = {"issuer": args.issuer, "discovery": cfg, "findings": findings}
        if args.out:
            with open(args.out, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[*] → {args.out}")

    elif args.cmd == "probe":
        print(f"[*] Probing authorization endpoint: {args.auth_url}")
        result = check_auth_endpoint(args.auth_url, args.client_id, args.redirect)
        print("[+] Redirect URI tests:")
        for t in result.get("redirect_uri_tests", []):
            flag = "  [!!!]" if "ACCEPTED" in t.get("result", "") else "  [OK] "
            print(f"{flag} {t.get('evil_redirect','')[:60]:60s}  → {t.get('result','')}")
        if args.out:
            with open(args.out, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[*] → {args.out}")

if __name__ == "__main__":
    main()
