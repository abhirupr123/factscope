"""Fail when local databases or credential artifacts are tracked by Git."""
from __future__ import annotations

from pathlib import PurePosixPath
import subprocess


FORBIDDEN_NAMES = {
    ".env", ".env.local", "secrets.env", "gcp-service-account.json",
}
FORBIDDEN_SUFFIXES = (".db", ".db-shm", ".db-wal", ".pem", ".key")


def tracked_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [path for path in result.stdout.split("\0") if path]


def forbidden_paths(paths: list[str]) -> list[str]:
    rejected = []
    for raw_path in paths:
        path = PurePosixPath(raw_path)
        name = path.name.lower()
        if name in FORBIDDEN_NAMES or name.endswith(FORBIDDEN_SUFFIXES):
            rejected.append(raw_path)
        elif "service-account" in name and name.endswith(".json"):
            rejected.append(raw_path)
    return sorted(rejected)


def main() -> int:
    rejected = forbidden_paths(tracked_paths())
    if rejected:
        print("Forbidden local or credential artifacts are tracked:")
        for path in rejected:
            print(f"- {path}")
        return 1
    print("No forbidden local or credential artifacts are tracked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
