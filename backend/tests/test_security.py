"""Security regression tests for the production hotfix."""

import asyncio
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

TEST_DB = Path(tempfile.gettempdir()) / f"factscope-security-{uuid.uuid4().hex}.db"
os.environ["ENVIRONMENT"] = "production"
os.environ["SESSION_SIGNING_SECRET"] = "factscope-test-session-signing-secret-32-bytes"
os.environ["FACTSCOPE_DB_PATH"] = str(TEST_DB)
os.environ["TURSO_DATABASE_URL"] = ""
os.environ["TURSO_AUTH_TOKEN"] = ""

from safe_fetch import (  # noqa: E402
    ResponseTooLargeError,
    UnsafeURLError,
    safe_get,
    validate_public_url,
)
import main  # noqa: E402
import db  # noqa: E402


def tearDownModule():
    for suffix in ("", "-shm", "-wal"):
        try:
            Path(f"{TEST_DB}{suffix}").unlink(missing_ok=True)
        except PermissionError:
            pass


class FakeSocket:
    def __init__(self, address="93.184.216.34"):
        self.address = address

    def getpeername(self):
        return (self.address, 443)


class FakeRaw:
    def __init__(self, address="93.184.216.34"):
        self._connection = type("Connection", (), {"sock": FakeSocket(address)})()


class FakeResponse:
    is_redirect = False
    is_permanent_redirect = False
    status_code = 200

    def __init__(self, headers=None, chunks=None, peer="93.184.216.34"):
        self.raw = FakeRaw(peer)
        self.headers = headers or {"content-type": "image/png"}
        self._chunks = chunks or []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=65536):
        del chunk_size
        yield from self._chunks


class FakeSession:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, *_args, **_kwargs):
        return self.response


class SafeFetchTests(unittest.TestCase):
    def test_rejects_loopback_private_and_credential_urls(self):
        for url in (
            "http://127.0.0.1/admin",
            "http://10.1.2.3/internal",
            "http://[::1]/",
            "http://user:password@example.com/",
            "file:///etc/passwd",
        ):
            with self.subTest(url=url), self.assertRaises(UnsafeURLError):
                validate_public_url(url)

    def test_accepts_public_resolution(self):
        public_answer = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        with patch("safe_fetch.socket.getaddrinfo", return_value=public_answer):
            self.assertEqual(validate_public_url("https://example.com/a"), "https://example.com/a")

    def test_rejects_declared_and_streamed_oversize_responses(self):
        public_answer = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        declared = FakeResponse(headers={"content-type": "image/png", "content-length": "20"})
        streamed = FakeResponse(chunks=[b"123456", b"789012"])
        with patch("safe_fetch.socket.getaddrinfo", return_value=public_answer):
            with patch("safe_fetch.requests.Session", return_value=FakeSession(declared)):
                with self.assertRaises(ResponseTooLargeError):
                    safe_get("https://example.com/a", max_bytes=10)
            with patch("safe_fetch.requests.Session", return_value=FakeSession(streamed)):
                with self.assertRaises(ResponseTooLargeError):
                    safe_get("https://example.com/a", max_bytes=10)

    def test_rejects_private_connected_peer_after_public_dns_resolution(self):
        public_answer = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        rebound = FakeResponse(peer="127.0.0.1")
        with patch("safe_fetch.socket.getaddrinfo", return_value=public_answer):
            with patch("safe_fetch.requests.Session", return_value=FakeSession(rebound)):
                with self.assertRaises(UnsafeURLError):
                    safe_get("https://example.com/a", max_bytes=100)


class ProductionBoundaryTests(unittest.TestCase):
    def test_development_routes_are_absent_in_production(self):
        paths = {getattr(route, "path", None) for route in main.app.router.routes}
        self.assertNotIn("/debug/db-status", paths)
        self.assertNotIn("/models/info", paths)
        self.assertNotIn("/analyze/url", paths)
        self.assertNotIn("/openapi.json", paths)

    def test_chunked_request_body_limit_returns_413(self):
        sent = []
        messages = iter([
            {"type": "http.request", "body": b"123456", "more_body": True},
            {"type": "http.request", "body": b"789012", "more_body": False},
        ])

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        async def body_reader(_scope, inner_receive, _send):
            while True:
                message = await inner_receive()
                if not message.get("more_body"):
                    break

        middleware = main.RequestBodyLimitMiddleware(body_reader, max_bytes=10)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/share",
            "headers": [],
        }
        asyncio.run(middleware(scope, receive, send))
        statuses = [
            message.get("status") for message in sent
            if message["type"] == "http.response.start"
        ]
        self.assertEqual(statuses, [413])

    def test_legacy_unverified_shares_are_not_served(self):
        conn = db._get_conn()
        conn.execute(
            """INSERT INTO shared_results
               (id, result_type, score, verdict, explanation, evidence,
                server_verified, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "legacy01",
                "page",
                99,
                "authentic",
                "Client supplied legacy result",
                "[]",
                0,
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
        self.assertIsNone(db.get_shared_result("legacy01"))

        verified_id = db.store_shared_result({
            "fingerprint": "b" * 64, "score": 42, "verdict": "uncertain",
        })
        self.assertIsNotNone(db.get_shared_result(verified_id))

    def test_share_uses_stored_result_not_client_fields(self):
        fingerprint = "a" * 64
        request = main.ShareRequest.model_validate({
            "fingerprint": fingerprint,
            "score": 1,
            "verdict": "authentic",
            "explanation": "forged",
        })
        captured = {}

        def capture_share(data):
            captured.update(data)
            return "share123"

        stored = {
            "trust_score": 27,
            "verdict": "suspicious",
            "explanation": "Stored server result",
            "evidence": ["Stored evidence"],
            "url": "https://example.com/report",
        }
        token, _ = main.issue_installation_session()
        http_request = main.Request({
            "type": "http",
            "headers": [(b"authorization", f"Bearer {token}".encode("ascii"))],
        })
        with patch.object(main, "find_by_fingerprint", return_value=stored):
            with patch.object(main, "store_shared_result", side_effect=capture_share):
                asyncio.run(main.create_share(request, http_request))

        self.assertEqual(captured["score"], 27)
        self.assertEqual(captured["verdict"], "suspicious")
        self.assertEqual(captured["explanation"], "Stored server result")

    def test_share_html_escapes_text_and_rejects_javascript_urls(self):
        html = main._render_share_page({
            "score": 50,
            "verdict": "uncertain",
            "explanation": "<script>alert(1)</script>",
            "evidence": ["<img src=x onerror=alert(1)>"],
            "scanned_url": "javascript:alert(1)",
            "og_image": "javascript:alert(2)",
        })
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("javascript:alert", html)
        self.assertIn("&lt;script&gt;", html)


class ChunkTwoProtectionTests(unittest.TestCase):
    @staticmethod
    def _request(token: str | None = None):
        headers = []
        if token:
            headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
        return main.Request({"type": "http", "headers": headers})

    def setUp(self):
        main._api_burst_limiter.clear()
        main._analysis_burst_limiter.clear()
        main._session_mint_limiter.clear()

    def test_session_token_is_hashed_and_tampering_fails(self):
        token, context = main.issue_installation_session()
        stored = db.get_installation_session(context.token_hash)
        self.assertIsNotNone(stored)
        self.assertNotIn(token, str(stored))
        self.assertEqual(
            main.authenticate_installation_token(token).subject_id,
            context.subject_id,
        )
        with self.assertRaises(main.SessionAuthError):
            main.authenticate_installation_token(token[:-1] + ("A" if token[-1] != "A" else "B"))

    def test_direct_unauthenticated_analysis_is_rejected(self):
        payload = main.AnalyzeRequest(text="A checkable claim")
        with self.assertRaises(main.HTTPException) as caught:
            asyncio.run(main.analyze_page.__wrapped__(payload, self._request()))
        self.assertEqual(caught.exception.status_code, 401)

    def test_client_user_id_cannot_choose_vote_identity(self):
        token, context = main.issue_installation_session()
        payload = main.VoteRequest(
            fingerprint="f" * 64,
            user_id="forged-client-identity",
            vote=1,
        )
        with patch.object(main, "store_vote", return_value=True) as store_vote:
            with patch.object(main, "get_vote_stats", return_value={"likes": 1, "dislikes": 0}):
                asyncio.run(main.vote_on_result(payload, self._request(token)))
        self.assertEqual(store_vote.call_args.args[1], context.subject_id)

    def test_sliding_window_limiter_returns_retry_after(self):
        limiter = main.SlidingWindowLimiter()
        self.assertEqual(limiter.hit("key", 2, 60, now=100), (True, 0))
        self.assertEqual(limiter.hit("key", 2, 60, now=101), (True, 0))
        allowed, retry_after = limiter.hit("key", 2, 60, now=102)
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 58)


    def test_ip_identity_uses_proxy_appended_value(self):
        request = main.Request({
            "type": "http",
            "headers": [(b"x-forwarded-for", b"198.51.100.7, 203.0.113.9")],
        })
        self.assertEqual(main.client_ip_hash(request), main.hash_network_identity("203.0.113.9"))

    def test_spend_circuit_breaker_never_exceeds_limit(self):
        metric = f"test-llm-{uuid.uuid4().hex}"
        day = "2026-07-29"
        self.assertEqual(db.reserve_service_usage(metric, day, 2), (True, 1))
        self.assertEqual(db.reserve_service_usage(metric, day, 2), (True, 2))
        self.assertEqual(db.reserve_service_usage(metric, day, 2), (False, 2))

    def test_provider_failure_is_neutral_and_safe(self):
        import llm_utils
        with patch.object(llm_utils, "_call_llm", side_effect=RuntimeError("secret provider detail")):
            result = llm_utils.get_structured_analysis("claim")
        self.assertEqual(result["trust_score"], 50)
        self.assertEqual(result["verdict"], "unknown")
        self.assertNotIn("secret provider detail", result["explanation"])

    def test_structured_error_contains_request_id(self):
        request = self._request()
        request.state.request_id = "request-123"
        exc = main.HTTPException(status_code=401, detail={"error": "authentication_required"})
        response = asyncio.run(main.structured_http_error(request, exc))
        self.assertEqual(response.status_code, 401)
        self.assertIn(b'"request_id":"request-123"', response.body)


if __name__ == "__main__":
    unittest.main()
