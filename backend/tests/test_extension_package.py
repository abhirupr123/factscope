"""Tests for the production Chrome extension package boundary."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts import package_extension  # noqa: E402


class ExtensionPackageTests(unittest.TestCase):
    def test_package_contains_only_runtime_roots(self):
        files = package_extension.package_files()
        names = {path.relative_to(package_extension.FRONTEND).as_posix() for path in files}
        self.assertIn("manifest.json", names)
        self.assertIn("background/service_worker.js", names)
        self.assertTrue(any(name.startswith("content/") for name in names))
        self.assertTrue(any(name.startswith("popup/") for name in names))
        self.assertFalse(any(name.startswith("tests/") for name in names))
        self.assertFalse(any(name.startswith("site/") for name in names))
        self.assertNotIn("background/evaluation_capture.js", names)

    def test_archive_is_rooted_at_manifest_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.zip"
            second = Path(directory) / "second.zip"
            package_extension.build_archive(first)
            package_extension.build_archive(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertIn("manifest.json", archive.namelist())
                self.assertFalse(any(name.startswith("frontend/") for name in archive.namelist()))


if __name__ == "__main__":
    unittest.main()
