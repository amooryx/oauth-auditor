import json
import threading
import urllib.error
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import oauth_auditor


def metadata(issuer):
    return {
        "issuer": issuer,
        "authorization_endpoint": issuer + "/authorize",
        "jwks_uri": issuer + "/keys",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


class DiscoveryHandler(BaseHTTPRequestHandler):
    body = b"{}"
    redirect = None
    seen_paths = []

    def do_GET(self):
        type(self).seen_paths.append(self.path)
        if type(self).redirect:
            self.send_response(302)
            self.send_header("Location", type(self).redirect)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *_args):
        pass


class OAuthAuditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DiscoveryHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.issuer = "http://127.0.0.1:{}".format(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        DiscoveryHandler.body = json.dumps(metadata(self.issuer)).encode()
        DiscoveryHandler.redirect = None
        DiscoveryHandler.seen_paths = []

    def test_valid_local_discovery_is_fetched_and_audited(self):
        cfg = oauth_auditor.fetch_oidc_discovery(self.issuer)
        self.assertEqual(cfg["issuer"], self.issuer)
        self.assertEqual(
            DiscoveryHandler.seen_paths,
            ["/.well-known/openid-configuration"],
        )
        result = oauth_auditor.audit_discovery(cfg, expected_issuer=self.issuer)
        self.assertEqual(result, {"findings": [], "assumptions": []})

    def test_discovery_rejects_cross_origin_redirect(self):
        DiscoveryHandler.redirect = "http://127.0.0.1:1/metadata"
        with self.assertRaisesRegex(urllib.error.HTTPError, "cross-origin redirect refused"):
            oauth_auditor.fetch_oidc_discovery(self.issuer)

    def test_http_response_is_limited(self):
        original_limit = oauth_auditor.MAX_METADATA_BYTES
        oauth_auditor.MAX_METADATA_BYTES = 16
        DiscoveryHandler.body = b"x" * 17
        try:
            with self.assertRaisesRegex(ValueError, "byte limit"):
                oauth_auditor.fetch_oidc_discovery(self.issuer)
        finally:
            oauth_auditor.MAX_METADATA_BYTES = original_limit

    def test_fetch_uses_a_finite_timeout(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def read(self, limit):
                self.read_limit = limit
                return json.dumps(metadata(OAuthAuditorTests.issuer)).encode()

        class FakeOpener:
            def open(self, _request, timeout):
                self.timeout = timeout
                self.response = FakeResponse()
                return self.response

        fake_opener = FakeOpener()

        with mock.patch.object(
            oauth_auditor.urllib.request, "build_opener", return_value=fake_opener
        ):
            oauth_auditor.fetch_oidc_discovery(self.issuer)
        self.assertEqual(fake_opener.timeout, oauth_auditor.REQUEST_TIMEOUT_SECONDS)
        self.assertEqual(fake_opener.response.read_limit, oauth_auditor.MAX_METADATA_BYTES + 1)

    def test_metadata_reports_advertisements_not_unverified_behavior(self):
        cfg = metadata(self.issuer)
        cfg["response_types_supported"] = ["code", "token"]
        cfg["grant_types_supported"] = ["authorization_code", "password"]
        cfg["token_endpoint_auth_methods_supported"] = ["none"]
        result = oauth_auditor.audit_discovery(cfg)
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(len(result["assumptions"]), 1)
        self.assertTrue(all("evidence" in finding for finding in result["findings"]))
        self.assertIn("valid for public clients", result["assumptions"][0]["detail"])

    def test_issuer_mismatch_is_evidence_backed(self):
        result = oauth_auditor.audit_discovery(
            metadata(self.issuer), expected_issuer=self.issuer + "/different"
        )
        self.assertEqual(result["findings"][0]["severity"], "High")
        self.assertEqual(result["findings"][0]["evidence"]["metadata"], self.issuer)

    def test_invalid_metadata_inputs_are_rejected(self):
        for issuer in ("javascript:alert(1)", "https://user:pass@example.test", "https://example.test?x=1"):
            with self.subTest(issuer=issuer), self.assertRaises(ValueError):
                oauth_auditor.fetch_oidc_discovery(issuer)
        invalid = metadata(self.issuer)
        invalid["jwks_uri"] = "javascript:alert(1)"
        with self.assertRaises(ValueError):
            oauth_auditor.audit_discovery(invalid)
        with self.assertRaisesRegex(ValueError, "missing required"):
            oauth_auditor.audit_discovery({})

    def test_wildcard_issuer_host_is_rejected(self):
        issuer = "https://" + chr(42) + ".example.test"
        with self.assertRaisesRegex(ValueError, "invalid hostname"):
            oauth_auditor.fetch_oidc_discovery(issuer)

    def test_redirect_validation_is_offline_and_accepts_supported_uri_forms(self):
        result = oauth_auditor.check_auth_endpoint(
            "https://issuer.example/authorize?tenant=demo",
            "com.example.app:/oauth/callback",
        )
        self.assertEqual(result["findings"], [])
        self.assertIn("not verified", result["assumptions"][0]["issue"])
        for redirect in (
            "javascript:alert(1)",
            "ftp://app.test/callback",
            "http://example.test/callback",
            "https://app.test/callback#token",
            "https://app.test/callback#",
        ):
            with self.subTest(redirect=redirect), self.assertRaises(ValueError):
                oauth_auditor.check_auth_endpoint(
                    "https://issuer.example/authorize", redirect
                )


if __name__ == "__main__":
    unittest.main()
