#!/usr/bin/env python3
"""Offline OAuth/OIDC configuration checks and bounded OIDC discovery."""

import argparse
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_METADATA_BYTES = 1_048_576
REQUEST_TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 3
ENDPOINT_FIELDS = (
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "end_session_endpoint",
)
REQUIRED_METADATA_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
)


def _is_loopback(hostname):
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_http_url(value, label, allow_loopback_http=True, allow_query=False):
    if not isinstance(value, str) or not value:
        raise ValueError("{} must be a non-empty URL".format(label))
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("{} must not contain control characters".format(label))
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("{} is not a valid URL: {}".format(label, exc))
    if parsed.scheme != "https" and not (
        allow_loopback_http and parsed.scheme == "http" and _is_loopback(hostname)
    ):
        raise ValueError("{} must use HTTPS (HTTP is allowed only for loopback)".format(label))
    if not hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("{} must have a host and must not contain credentials".format(label))
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("{} has an invalid hostname".format(label))
        labels = ascii_hostname.rstrip(".").split(".")
        label_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
        if (
            not ascii_hostname
            or len(ascii_hostname.rstrip(".")) > 253
            or any(not label_pattern.fullmatch(part) for part in labels)
        ):
            raise ValueError("{} has an invalid hostname".format(label))
    if (("?" in value) and not allow_query) or "#" in value:
        raise ValueError("{} has a disallowed query or fragment".format(label))
    return parsed


def _validate_redirect_uri(value):
    if not isinstance(value, str) or not value:
        raise ValueError("redirect URI must be a non-empty absolute URI")
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme in ("https", "http"):
            _validate_http_url(value, "redirect URI", allow_query=True)
        elif parsed.scheme and parsed.scheme not in (
            "javascript", "data", "file", "ftp", "mailto", "blob", "vbscript"
        ):
            if not parsed.path and not parsed.netloc:
                raise ValueError("redirect URI must identify an absolute URI")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("redirect URI must not contain credentials")
        else:
            raise ValueError("redirect URI must use HTTPS, loopback HTTP, or a native-app scheme")
    except ValueError as exc:
        raise ValueError("invalid redirect URI: {}".format(exc))
    if parsed.fragment or "#" in value:
        raise ValueError("redirect URI must not contain a fragment")
    return parsed


def _validate_metadata(cfg):
    if not isinstance(cfg, dict):
        raise ValueError("OIDC metadata must be a JSON object")
    missing = [field for field in REQUIRED_METADATA_FIELDS if field not in cfg]
    if missing:
        raise ValueError("OIDC metadata is missing required field(s): {}".format(", ".join(missing)))
    if not isinstance(cfg["issuer"], str) or not cfg["issuer"]:
        raise ValueError("metadata issuer must be a non-empty string")
    _validate_http_url(cfg["issuer"], "metadata issuer", allow_loopback_http=True)
    for field in ENDPOINT_FIELDS:
        if field in cfg:
            _validate_http_url(
                cfg[field], "metadata {}".format(field),
                allow_loopback_http=True, allow_query=True
            )
    for field in (
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ):
        value = cfg[field]
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ValueError("metadata {} must be an array of non-empty strings".format(field))
    for field in ("grant_types_supported", "code_challenge_methods_supported",
                  "token_endpoint_auth_methods_supported"):
        if field in cfg and (
            not isinstance(cfg[field], list)
            or not all(isinstance(item, str) and item for item in cfg[field])
        ):
            raise ValueError("metadata {} must be an array of non-empty strings".format(field))
    return cfg


def audit_discovery(cfg, expected_issuer=None):
    """Return evidence-backed risks and unverified assumptions for OIDC metadata."""
    _validate_metadata(cfg)
    findings = []
    assumptions = []

    if expected_issuer is not None:
        _validate_http_url(expected_issuer, "expected issuer")
        if cfg["issuer"] != expected_issuer:
            findings.append({
                "severity": "High",
                "issue": "Discovery issuer does not match the requested issuer",
                "evidence": {"expected": expected_issuer, "metadata": cfg["issuer"]},
            })

    implicit_response_types = [
        value for value in cfg["response_types_supported"]
        if "token" in value.split() or "id_token" in value.split()
    ]
    if implicit_response_types:
        findings.append({
            "severity": "Medium",
            "issue": "Discovery metadata advertises an implicit response type",
            "evidence": {"response_types_supported": implicit_response_types},
            "detail": "This documents advertised capability; it does not prove a client uses it.",
        })

    if "password" in cfg.get("grant_types_supported", []):
        findings.append({
            "severity": "Medium",
            "issue": "Discovery metadata advertises the Resource Owner Password Credentials grant",
            "evidence": {"grant_type": "password"},
            "detail": "This documents advertised capability; it does not prove the grant is enabled for a client.",
        })

    if "code" in cfg["response_types_supported"] and not cfg.get("code_challenge_methods_supported"):
        assumptions.append({
            "issue": "PKCE support is not advertised in discovery metadata",
            "detail": "Absence of this optional metadata does not establish that the authorization server rejects PKCE.",
        })
    if cfg.get("token_endpoint_auth_methods_supported") == ["none"]:
        assumptions.append({
            "issue": "Only the public-client token endpoint auth method is advertised",
            "detail": "The none method is valid for public clients and is not, by itself, a security vulnerability.",
        })

    return {"findings": findings, "assumptions": assumptions}


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        super().__init__()
        self.origin = origin
        self.redirect_count = 0

    def redirect_request(self, request, response, code, message, headers, new_url):
        self.redirect_count += 1
        if self.redirect_count > MAX_REDIRECTS:
            raise urllib.error.HTTPError(new_url, code, "too many redirects", headers, response)
        target = urllib.parse.urlsplit(new_url)
        if (target.scheme, target.netloc) != self.origin:
            raise urllib.error.HTTPError(new_url, code, "cross-origin redirect refused", headers, response)
        return super().redirect_request(request, response, code, message, headers, new_url)


def fetch_oidc_discovery(issuer):
    parsed = _validate_http_url(issuer, "issuer")
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    origin = (parsed.scheme, parsed.netloc)
    opener = urllib.request.build_opener(_SameOriginRedirectHandler(origin))
    request = urllib.request.Request(
        discovery_url,
        headers={"Accept": "application/json", "User-Agent": "OAuthAuditor/2.0"},
    )
    with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        body = response.read(MAX_METADATA_BYTES + 1)
    if len(body) > MAX_METADATA_BYTES:
        raise ValueError("discovery response exceeds the {} byte limit".format(MAX_METADATA_BYTES))
    try:
        cfg = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("discovery response is not valid UTF-8 JSON: {}".format(exc))
    return _validate_metadata(cfg)


def check_auth_endpoint(auth_url, redirect_uri):
    """Validate URL syntax only; registration and server behavior cannot be tested offline."""
    _validate_http_url(auth_url, "authorization endpoint", allow_query=True)
    _validate_redirect_uri(redirect_uri)
    return {
        "authorization_endpoint": auth_url,
        "redirect_uri": redirect_uri,
        "findings": [],
        "assumptions": [{
            "issue": "Redirect URI registration and matching behavior were not verified",
            "detail": "This offline check validates URI syntax only; it sends no authorization request.",
        }],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline OAuth/OIDC configuration checks and bounded OIDC discovery."
    )
    subparsers = parser.add_subparsers(dest="cmd")

    disc_p = subparsers.add_parser("discover", help="Fetch and audit a bounded OIDC discovery document")
    disc_p.add_argument("issuer", help="HTTPS issuer URL (loopback HTTP is allowed for local testing)")
    disc_p.add_argument("--out", help="Output JSON file")

    audit_p = subparsers.add_parser("audit", help="Audit a local OIDC discovery JSON file")
    audit_p.add_argument("metadata", help="Path to a local OIDC discovery JSON file")
    audit_p.add_argument("--issuer", help="Expected issuer identifier")
    audit_p.add_argument("--out", help="Output JSON file")

    probe_p = subparsers.add_parser(
        "probe", help="Offline URL validation only; no authorization requests are sent"
    )
    probe_p.add_argument("auth_url", help="Authorization endpoint URL")
    probe_p.add_argument("--redirect", required=True, help="Client redirect URI")
    probe_p.add_argument("--out", help="Output JSON file")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 2

    try:
        if args.cmd == "discover":
            cfg = fetch_oidc_discovery(args.issuer)
            result = {
                "issuer": args.issuer,
                "discovery": cfg,
                **audit_discovery(cfg, expected_issuer=args.issuer),
            }
        elif args.cmd == "audit":
            with open(args.metadata, "rb") as metadata_file:
                body = metadata_file.read(MAX_METADATA_BYTES + 1)
            if len(body) > MAX_METADATA_BYTES:
                raise ValueError("metadata file exceeds the {} byte limit".format(MAX_METADATA_BYTES))
            try:
                cfg = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("metadata file is not valid UTF-8 JSON: {}".format(exc))
            result = {
                "issuer": args.issuer or (cfg.get("issuer", "") if isinstance(cfg, dict) else ""),
                "discovery": cfg,
                **audit_discovery(cfg, expected_issuer=args.issuer),
            }
        else:
            result = check_auth_endpoint(args.auth_url, args.redirect)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return 2

    output = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as output_file:
            output_file.write(output + "\n")
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
