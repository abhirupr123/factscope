"""Validate and create the production Chrome extension archive."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import zipfile


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
INCLUDED_ROOTS = ("background", "content", "icons", "popup")
INCLUDED_FILES = ("manifest.json",)
ALLOWED_PERMISSIONS = {"storage", "scripting", "activeTab", "contextMenus"}
PRODUCTION_HOSTS = {"https://factscope-api.onrender.com/*"}
TEXT_SUFFIXES = {".css", ".html", ".js", ".json", ".svg", ".txt"}
FORBIDDEN_FILE_PARTS = {
    ".env", "secrets.env", "gcp-service-account.json", "factscope.db",
    "node_modules", "tests", "site", "__pycache__",
}
EXCLUDED_RUNTIME_FILES = {"background/evaluation_capture.js"}
FORBIDDEN_TEXT = (
    re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?", re.I),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r'"private_key"\s*:'),
)
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_INPUT_BYTES = 20 * 1024 * 1024


class PackageValidationError(ValueError):
    """Raised when the production extension package is unsafe or incomplete."""


def _manifest() -> dict:
    path = FRONTEND / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackageValidationError("frontend/manifest.json is missing or invalid.") from exc

    if manifest.get("manifest_version") != 3:
        raise PackageValidationError("Only a Manifest V3 production package is allowed.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(manifest.get("version") or "")):
        raise PackageValidationError("The extension version must use x.y.z format.")
    permissions = set(manifest.get("permissions") or [])
    if not permissions.issubset(ALLOWED_PERMISSIONS):
        raise PackageValidationError(
            f"Unexpected extension permissions: {sorted(permissions - ALLOWED_PERMISSIONS)}"
        )
    hosts = set(manifest.get("host_permissions") or [])
    if hosts != PRODUCTION_HOSTS:
        raise PackageValidationError("Production host permissions must contain only the API host.")

    required_paths = [
        manifest.get("background", {}).get("service_worker"),
        manifest.get("action", {}).get("default_popup"),
        *(manifest.get("icons") or {}).values(),
    ]
    for relative in required_paths:
        if not relative or not (FRONTEND / relative).is_file():
            raise PackageValidationError(f"Manifest resource is missing: {relative!r}")
    return manifest


def package_files() -> list[Path]:
    _manifest()
    paths = [FRONTEND / name for name in INCLUDED_FILES]
    for directory in INCLUDED_ROOTS:
        root = FRONTEND / directory
        if not root.is_dir():
            raise PackageValidationError(f"Required extension directory is missing: {directory}")
        paths.extend(path for path in root.rglob("*") if path.is_file())

    selected: list[Path] = []
    total_bytes = 0
    for path in sorted(set(paths), key=lambda item: item.as_posix().lower()):
        if path.is_symlink():
            raise PackageValidationError(f"Symlinks are not allowed in the package: {path}")
        relative = path.relative_to(FRONTEND)
        if relative.as_posix() in EXCLUDED_RUNTIME_FILES:
            continue
        lowered_parts = {part.lower() for part in relative.parts}
        if lowered_parts & FORBIDDEN_FILE_PARTS or path.suffix.lower() == ".map":
            raise PackageValidationError(f"Forbidden production package file: {relative}")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise PackageValidationError(f"Extension file exceeds 5 MiB: {relative}")
        total_bytes += size
        if total_bytes > MAX_ARCHIVE_INPUT_BYTES:
            raise PackageValidationError("Extension package input exceeds 20 MiB.")
        if path.suffix.lower() in TEXT_SUFFIXES:
            content = path.read_text(encoding="utf-8")
            for pattern in FORBIDDEN_TEXT:
                if pattern.search(content):
                    raise PackageValidationError(
                        f"Forbidden development endpoint or credential material in {relative}"
                    )
        selected.append(path)
    return selected


def build_archive(output: Path) -> dict:
    files = package_files()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            relative = path.relative_to(FRONTEND).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    return {
        "output": str(output),
        "files": len(files),
        "bytes": output.stat().st_size,
    }


def main_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(build_archive(args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
