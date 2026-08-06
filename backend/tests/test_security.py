"""Security regression tests for the production hotfix."""

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
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
import llm_utils  # noqa: E402
import db  # noqa: E402
import fingerprinting  # noqa: E402


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
            "scanned_title": "Stored report title",
            "og_image": "https://example.com/report.jpg",
            "source_info": {"site_name": "Example News"},
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
        self.assertEqual(captured["scanned_title"], "Stored report title")
        self.assertEqual(captured["og_image"], "https://example.com/report.jpg")
        self.assertEqual(captured["source_info"]["site_name"], "Example News")

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


    def test_gemini_retries_transient_503_and_returns_success(self):
        unavailable = Mock(status_code=503)
        success = Mock(status_code=200)
        success.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}]
        }

        with patch("requests.post", side_effect=[unavailable, success]) as post, patch("time.sleep"):
            result = llm_utils._call_gemini(
                "system", "content", None, None, 100,
                model_override="gemma-4-31b-it",
            )

        self.assertEqual(result, "ok")
        self.assertEqual(post.call_count, 2)


class ChunkThreePrivacyTests(unittest.TestCase):
    def test_telemetry_accepts_only_allowlisted_event_names(self):
        subject = f"telemetry-{uuid.uuid4().hex}"
        self.assertTrue(db.store_telemetry_event(subject, "page_scan_completed"))
        self.assertFalse(db.store_telemetry_event(subject, "https://example.com/private"))
        conn = db._get_conn()
        rows = conn.execute(
            "SELECT event_name FROM telemetry_events WHERE subject_id = ?",
            (subject,),
        ).fetchall()
        self.assertEqual([row["event_name"] for row in rows], ["page_scan_completed"])
        conn.execute("DELETE FROM telemetry_events WHERE subject_id = ?", (subject,))
        conn.commit()

    def test_retention_cleanup_deletes_only_expired_raw_records(self):
        marker = uuid.uuid4().hex
        old_time = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        new_time = datetime.now(timezone.utc).isoformat()
        conn = db._get_conn()
        conn.execute(
            "INSERT INTO scans (doc_type, source, user_id, timestamp) VALUES (?, ?, ?, ?)",
            ("test", f"old-{marker}", marker, old_time),
        )
        conn.execute(
            "INSERT INTO scans (doc_type, source, user_id, timestamp) VALUES (?, ?, ?, ?)",
            ("test", f"new-{marker}", marker, new_time),
        )
        conn.execute(
            """INSERT INTO image_scans (image_url, url_hash, user_id, timestamp)
               VALUES (?, ?, ?, ?)""",
            (f"https://example.com/{marker}.png", f"old-{marker}", marker, old_time),
        )
        conn.execute(
            "INSERT INTO telemetry_events (subject_id, event_name, created_at) VALUES (?, ?, ?)",
            (marker, "scan_failed", old_time),
        )
        expired_subject = f"expired-{marker}"
        conn.execute(
            """INSERT INTO installation_sessions
               (token_hash, subject_id, created_at, last_seen, expires_at, revoked)
               VALUES (?, ?, ?, ?, ?, 0)""",
            (f"token-{marker}", expired_subject, old_time, old_time, old_time),
        )
        conn.execute(
            "INSERT INTO scans (doc_type, source, user_id, timestamp) VALUES (?, ?, ?, ?)",
            ("test", f"session-{marker}", expired_subject, new_time),
        )
        conn.commit()

        deleted = db.purge_expired_data(30, 30)
        self.assertGreaterEqual(deleted["expired_installations"], 1)
        self.assertGreaterEqual(deleted["scans"], 1)
        self.assertGreaterEqual(deleted["image_scans"], 1)
        self.assertGreaterEqual(deleted["telemetry_events"], 1)
        remaining = conn.execute(
            "SELECT source FROM scans WHERE user_id = ?", (marker,)
        ).fetchall()
        self.assertEqual([row["source"] for row in remaining], [f"new-{marker}"])
        expired_rows = conn.execute(
            "SELECT COUNT(*) AS cnt FROM scans WHERE user_id = ?",
            (expired_subject,),
        ).fetchone()["cnt"]
        self.assertEqual(expired_rows, 0)
        conn.execute("DELETE FROM scans WHERE user_id = ?", (marker,))
        conn.commit()

    def test_installation_deletion_removes_linked_data_and_session(self):
        token, context = main.issue_installation_session()
        subject = context.subject_id
        fingerprint = uuid.uuid4().hex * 2
        db.store_scan(
            "page_scan", "selected content", {"trust_score": 50, "verdict": "unknown"},
            fingerprint=fingerprint, url="https://example.com/report", user_id=subject,
        )
        db.store_image_scan(
            "https://example.com/image.png",
            {"authenticity_score": 50, "verdict": "uncertain", "evidence": []},
            user_id=subject,
        )
        db.add_community_flag(
            fingerprint, subject, "other",
            "A sufficiently detailed test justification for deletion coverage.",
        )
        db.store_vote(fingerprint, subject, 1)
        db.record_scan_access(fingerprint, subject, "page")
        db.store_telemetry_event(subject, "scan_failed")
        db.increment_daily_scan(subject, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        share_id = db.store_shared_result({
            "fingerprint": fingerprint,
            "score": 50,
            "verdict": "uncertain",
            "owner_subject_id": subject,
        })

        deleted = db.delete_installation_data(subject)
        self.assertGreaterEqual(deleted["sessions"], 1)
        self.assertIsNone(db.get_shared_result(share_id))
        with self.assertRaises(main.SessionAuthError):
            main.authenticate_installation_token(token)

        conn = db._get_conn()
        checks = (
            ("scans", "user_id"),
            ("image_scans", "user_id"),
            ("community_flags", "user_id"),
            ("response_votes", "user_id"),
            ("scan_accesses", "user_id"),
            ("telemetry_events", "subject_id"),
            ("user_scans", "user_id"),
            ("installation_sessions", "subject_id"),
        )
        for table, column in checks:
            with self.subTest(table=table):
                count = conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM {table} WHERE {column} = ?",
                    (subject,),
                ).fetchone()["cnt"]
                self.assertEqual(count, 0)

    def test_user_requested_deletion_preserves_session_and_daily_quota(self):
        token, context = main.issue_installation_session()
        subject = context.subject_id
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db.increment_daily_scan(subject, today)
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        db.increment_daily_scan(subject, yesterday)

        deleted = db.delete_installation_data(
            subject,
            preserve_security_records=True,
        )

        self.assertEqual(deleted["quota_history"], 1)
        self.assertEqual(deleted["sessions"], 0)
        self.assertEqual(db.get_daily_scan_count(subject, today), 1)
        self.assertEqual(db.get_daily_scan_count(subject, yesterday), 0)
        self.assertEqual(main.authenticate_installation_token(token).subject_id, subject)

    def test_privacy_routes_are_publicly_defined_but_authenticated(self):
        paths = {getattr(route, "path", None) for route in main.app.router.routes}
        self.assertIn("/v1/telemetry", paths)
        self.assertIn("/v1/data", paths)
        request = main.Request({"type": "http", "headers": []})
        with self.assertRaises(main.HTTPException) as caught:
            asyncio.run(main.delete_server_data(request))
        self.assertEqual(caught.exception.status_code, 401)


    def test_completed_empty_claims_are_not_reported_as_pending(self):
        request = main.Request({"type": "http", "headers": []})
        with patch.object(main, "_require_session"), patch.object(
            main, "get_scan_claims", return_value="[]"
        ):
            result = asyncio.run(main.get_claims("a" * 64, request))

        self.assertFalse(result["pending"])
        self.assertEqual(result["fact_checks"], [])


class ChunkFourFoundationTests(unittest.TestCase):
    @staticmethod
    def _request():
        request = main.Request({"type": "http", "headers": []})
        request.state.request_id = "chunk4-test-request"
        return request

    def setUp(self):
        main._cache_hit_limiter.clear()
        with main._inflight_guard:
            main._inflight_page_analyses.clear()

    def test_versioned_fingerprint_ignores_tracking_and_dynamic_boilerplate(self):
        first = fingerprinting.compute_analysis_fingerprint(
            "Updated 5 minutes ago\nA detailed report says the monument has developed a black crust.",
            url="https://example.com/report?utm_source=test&ref=home",
            analysis_version="4a-1",
        )
        second = fingerprinting.compute_analysis_fingerprint(
            "Updated 9 minutes ago\nA detailed report says the monument has developed a black crust.",
            url="https://example.com/report",
            analysis_version="4a-1",
        )
        changed = fingerprinting.compute_analysis_fingerprint(
            "Updated 9 minutes ago\nA detailed report says the monument has developed a white crust.",
            url="https://example.com/report",
            analysis_version="4a-1",
        )
        new_version = fingerprinting.compute_analysis_fingerprint(
            "Updated 9 minutes ago\nA detailed report says the monument has developed a black crust.",
            url="https://example.com/report",
            analysis_version="4a-2",
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)
        self.assertNotEqual(first, new_version)

    def test_cache_lookup_requires_current_version_and_round_trips_share_metadata(self):
        fingerprint = uuid.uuid4().hex * 2
        subject = f"cache-{uuid.uuid4().hex}"
        db.store_scan(
            "page_scan", "stable article text",
            {"trust_score": 71, "verdict": "uncertain", "evidence": ["Evidence"]},
            fingerprint=fingerprint, url="https://example.com/report", user_id=subject,
            analysis_version="4a-test", scanned_title="Stored title",
            canonical_url="https://example.com/report",
            source_info={"site_name": "Example", "author": "Reporter"},
            og_image="https://cdn.example.com/report.jpg",
        )
        cached = db.find_cached_scan(fingerprint, "4a-test", 24)
        self.assertEqual(cached["scanned_title"], "Stored title")
        self.assertEqual(cached["source_info"]["author"], "Reporter")
        self.assertIsNone(db.find_cached_scan(fingerprint, "different-version", 24))
        stored = db.find_by_fingerprint(fingerprint)
        self.assertEqual(stored["source_info"]["site_name"], "Example")
        conn = db._get_conn()
        conn.execute("DELETE FROM scans WHERE fingerprint = ?", (fingerprint,))
        conn.commit()

    def test_scan_accesses_count_distinct_installations_without_content(self):
        fingerprint = uuid.uuid4().hex * 2
        first = f"access-{uuid.uuid4().hex}"
        second = f"access-{uuid.uuid4().hex}"
        self.assertTrue(db.record_scan_access(fingerprint, first, "page"))
        self.assertTrue(db.record_scan_access(fingerprint, first, "page"))
        self.assertTrue(db.record_scan_access(fingerprint, second, "page"))
        self.assertEqual(db.count_scans_for_fingerprint(fingerprint), 2)
        conn = db._get_conn()
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(scan_accesses)").fetchall()
        }
        self.assertNotIn("text", columns)
        self.assertNotIn("title", columns)
        self.assertNotIn("url", columns)
        conn.execute("DELETE FROM scan_accesses WHERE fingerprint = ?", (fingerprint,))
        conn.commit()
    def test_cached_article_is_available_without_quota_or_provider_charge(self):
        payload = main.AnalyzeRequest(
            text="A sufficiently long stable article body that can be fingerprinted for this cache test."
        )
        cached = {
            "trust_score": 68, "verdict": "uncertain", "explanation": "Stored",
            "evidence": ["Stored evidence"], "judgement": "[]",
            "source_info": {"site_name": "Example"},
        }
        auth = Mock(subject_id="cached-subject")
        with patch.object(main, "_require_session", return_value=auth), \
             patch.object(main, "_record_scan_access_async"), \
             patch.object(main, "find_cached_scan", return_value=cached), \
             patch.object(main, "_enforce_cache_hit_limit"), \
             patch.object(main, "_remaining_scans", return_value=0), \
             patch.object(main, "get_flag_count", return_value=0), \
             patch.object(main, "get_community_notes", return_value=[]), \
             patch.object(main, "get_vote_stats", return_value={"likes": 0, "dislikes": 0}), \
             patch.object(main, "_check_rate_limit", side_effect=AssertionError("quota checked on hit")), \
             patch.object(main, "_reserve_llm_call", side_effect=AssertionError("provider reserved on hit")), \
             patch.object(main, "_increment_and_get_remaining", side_effect=AssertionError("quota charged on hit")), \
             patch.object(main, "_enforce_analysis_burst", side_effect=AssertionError("costly burst applied on hit")):
            result = asyncio.run(main.analyze_page.__wrapped__(payload, self._request()))
        self.assertTrue(result.cached)
        self.assertEqual(result.cache_status, "hit")
        self.assertEqual(result.scans_remaining, 0)
        self.assertEqual(result.fact_checks, [])

    def test_cached_image_is_available_without_quota_or_provider_charge(self):
        payload = main.ImageVerifyRequest(image_url="https://example.com/image.jpg")
        cached = {
            "authenticity_score": 72, "verdict": "authentic",
            "explanation": "Stored image result", "evidence": [],
            "claim_analysis": None,
        }
        auth = Mock(subject_id="cached-image-subject")
        with patch.object(main, "_require_session", return_value=auth), \
             patch.object(main, "_record_scan_access_async"), \
             patch.object(main, "find_image_scan", return_value=cached), \
             patch.object(main, "_enforce_cache_hit_limit"), \
             patch.object(main, "_remaining_scans", return_value=0), \
             patch.object(main, "get_flag_count", return_value=0), \
             patch.object(main, "get_community_notes", return_value=[]), \
             patch.object(main, "get_vote_stats", return_value={"likes": 0, "dislikes": 0}), \
             patch.object(main, "_check_rate_limit", side_effect=AssertionError("quota checked on hit")), \
             patch.object(main, "_reserve_llm_call", side_effect=AssertionError("provider reserved on hit")), \
             patch.object(main, "_increment_and_get_remaining", side_effect=AssertionError("quota charged on hit")), \
             patch.object(main, "_enforce_analysis_burst", side_effect=AssertionError("costly burst applied on hit")):
            result = asyncio.run(main.verify_image.__wrapped__(payload, self._request()))
        self.assertTrue(result.cached)
        self.assertEqual(result.cache_status, "hit")
        self.assertEqual(result.scans_remaining, 0)
    def test_fresh_article_charges_once_when_provider_work_starts(self):
        payload = main.AnalyzeRequest(
            text="A sufficiently long stable article body containing a factual report for provider work."
        )
        auth = Mock(subject_id="fresh-subject")
        llm_result = {
            "trust_score": 60, "verdict": "uncertain",
            "explanation": "Analysis", "evidence": [],
        }
        with patch.object(main, "_require_session", return_value=auth), \
             patch.object(main, "_record_scan_access_async"), \
             patch.object(main, "find_cached_scan", return_value=None), \
             patch.object(main, "_enforce_analysis_burst"), \
             patch.object(main, "_check_rate_limit", return_value=None), \
             patch.object(main, "_reserve_llm_call") as reserve, \
             patch.object(main, "_increment_and_get_remaining", return_value=9) as charge, \
             patch.object(main, "get_structured_analysis", return_value=llm_result), \
             patch.object(main, "factcheck_available", return_value=False), \
             patch.object(main, "compute_structural_score", return_value=(50, [])), \
             patch.object(main, "store_analysis_result"), \
             patch.object(main, "get_flag_count", return_value=0), \
             patch.object(main, "count_scans_for_fingerprint", return_value=1), \
             patch.object(main, "get_community_notes", return_value=[]), \
             patch.object(main, "get_vote_stats", return_value={"likes": 0, "dislikes": 0}):
            result = asyncio.run(main.analyze_page.__wrapped__(payload, self._request()))
        self.assertFalse(result.cached)
        self.assertEqual(result.cache_status, "miss")
        self.assertEqual(result.scans_remaining, 9)
        reserve.assert_called_once()
        charge.assert_called_once_with("fresh-subject")
        self.assertEqual(main._inflight_page_analyses, {})

    def test_concurrent_identical_articles_share_one_provider_pipeline(self):
        payload = main.AnalyzeRequest(
            text="A sufficiently long stable article body used for concurrent provider deduplication."
        )
        auth = Mock(subject_id="coalesced-subject")
        llm_result = {
            "trust_score": 60, "verdict": "uncertain",
            "explanation": "Analysis", "evidence": [],
        }

        def slow_provider(_content):
            time.sleep(0.05)
            return llm_result

        async def run_both():
            return await asyncio.gather(
                main.analyze_page.__wrapped__(payload, self._request()),
                main.analyze_page.__wrapped__(payload, self._request()),
            )

        with patch.object(main, "_require_session", return_value=auth), \
             patch.object(main, "_record_scan_access_async"), \
             patch.object(main, "find_cached_scan", return_value=None), \
             patch.object(main, "_enforce_analysis_burst"), \
             patch.object(main, "_check_rate_limit", return_value=None), \
             patch.object(main, "_reserve_llm_call") as reserve, \
             patch.object(main, "_increment_and_get_remaining", return_value=9) as charge, \
             patch.object(main, "_remaining_scans", return_value=9), \
             patch.object(main, "get_structured_analysis", side_effect=slow_provider) as provider, \
             patch.object(main, "factcheck_available", return_value=False), \
             patch.object(main, "compute_structural_score", return_value=(50, [])), \
             patch.object(main, "store_analysis_result"), \
             patch.object(main, "get_flag_count", return_value=0), \
             patch.object(main, "count_scans_for_fingerprint", return_value=1), \
             patch.object(main, "get_community_notes", return_value=[]), \
             patch.object(main, "get_vote_stats", return_value={"likes": 0, "dislikes": 0}):
            results = asyncio.run(run_both())

        self.assertEqual(provider.call_count, 1)
        reserve.assert_called_once()
        charge.assert_called_once_with("coalesced-subject")
        self.assertEqual({result.cache_status for result in results}, {"miss", "coalesced"})
        self.assertEqual(main._inflight_page_analyses, {})

    def test_anonymous_community_data_has_no_automatic_analysis_path(self):
        source = Path(main.__file__).read_text(encoding="utf-8")
        self.assertNotIn("graduate_flags_to_fact(request.fingerprint)", source)
        self.assertNotIn("should_invalidate_cache(fingerprint)", source)
        self.assertNotIn("Community-verified facts relevant to this content", source)
        self.assertNotIn("previously_flagged", source)
    def test_sharing_again_does_not_erase_existing_title_or_image(self):
        fingerprint = uuid.uuid4().hex * 2
        owner = f"owner-{uuid.uuid4().hex}"
        share_id = db.store_shared_result({
            "fingerprint": fingerprint, "owner_subject_id": owner,
            "score": 50, "verdict": "uncertain", "scanned_title": "Original title",
            "og_image": "https://example.com/original.jpg",
        })
        same_id = db.store_shared_result({
            "fingerprint": fingerprint, "owner_subject_id": owner,
            "score": 55, "verdict": "uncertain", "scanned_title": "", "og_image": "",
        })
        stored = db.get_shared_result(share_id)
        self.assertEqual(same_id, share_id)
        self.assertEqual(stored["scanned_title"], "Original title")
        self.assertEqual(stored["og_image"], "https://example.com/original.jpg")
        conn = db._get_conn()
        conn.execute("DELETE FROM shared_results WHERE id = ?", (share_id,))
        conn.commit()

    def test_share_page_collapses_to_meaningful_single_column_without_image(self):
        html = main._render_share_page({
            "score": 50, "verdict": "uncertain", "explanation": "Analysis",
            "scanned_title": "Stored article", "scanned_url": "https://example.com/report",
            "domain": "example.com", "og_image": "",
        })
        self.assertIn('class="main no-preview-image"', html)
        self.assertIn("Stored article", html)
        self.assertIn("Page scanned", html)

if __name__ == "__main__":
    unittest.main()
