"""Regression tests for the versioned offline evaluation corpus."""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault(
    "FACTSCOPE_DB_PATH",
    str(Path(tempfile.gettempdir()) / f"factscope-eval-test-{uuid.uuid4().hex}.db"),
)
os.environ.setdefault("TURSO_DATABASE_URL", "")
os.environ.setdefault("TURSO_AUTH_TOKEN", "")

from evaluation import build_corpus, runner  # noqa: E402


class EvaluationCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.manifest = runner.load_cases()

    def test_corpus_size_balance_and_unique_ids(self):
        counts = Counter(case["modality"] for case in self.cases)
        self.assertGreaterEqual(len(self.cases), 150)
        self.assertGreaterEqual(counts["article"], 100)
        self.assertGreaterEqual(counts["image"], 30)
        self.assertEqual(len({case["case_id"] for case in self.cases}), len(self.cases))

    def test_checked_in_corpus_matches_deterministic_builder(self):
        expected = build_corpus.serialize_cases(build_corpus.generate_cases())
        actual = build_corpus.CASES_PATH.read_text(encoding="utf-8")
        self.assertEqual(actual, expected)

    def test_required_risk_categories_are_represented(self):
        categories = {case["category"] for case in self.cases}
        self.assertTrue(set(build_corpus.ARTICLE_SCENARIOS).issubset(categories))
        self.assertTrue(set(build_corpus.IMAGE_SCENARIOS).issubset(categories))
        origins = {case["origin"] for case in self.cases}
        self.assertEqual(origins, {"synthetic_policy_fixture"})

    def test_policy_evaluation_meets_safety_thresholds(self):
        report = runner.evaluate(self.cases, self.manifest)
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(report["status_accuracy"], 1.0)
        self.assertEqual(report["confidence_within_limit_rate"], 1.0)
        self.assertLess(report["unsupported_confident_rate"], 0.05)
        self.assertEqual(report["live_link_resolution_rate"], None)
        self.assertEqual(report["manual_source_relevance_rate"], None)


if __name__ == "__main__":
    unittest.main()