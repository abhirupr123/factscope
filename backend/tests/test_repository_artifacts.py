"""Tests for tracked-artifact policy helpers."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.check_tracked_artifacts import forbidden_paths  # noqa: E402


class RepositoryArtifactTests(unittest.TestCase):
    def test_rejects_secret_and_database_artifacts(self):
        rejected = forbidden_paths([
            "backend/factscope.db",
            "backend/secrets.env",
            "backend/gcp-service-account.json",
            "backend/.env.example",
            "frontend/manifest.json",
        ])
        self.assertEqual(rejected, [
            "backend/factscope.db",
            "backend/gcp-service-account.json",
            "backend/secrets.env",
        ])
