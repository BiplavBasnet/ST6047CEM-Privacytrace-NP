"""Fail CI when tracked files contain high-confidence secret material.

Synthetic detection fixtures are exempted only by explicit sentinel, never by
directory or filetype. A live-looking credential in tests/ or evaluation_data/
must still fail.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SK_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")
GH_PATTERN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
PEM_BEGIN = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
PEM_END = re.compile(r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
SYNTHETIC_SK = re.compile(r"\bsk-(?:testnpfake|synthetic-)[A-Za-z0-9_-]*")
EXACT_SYNTHETIC_TOKENS = ("sk-abcdefghijklmnopqrstuvwxyz123456",)
TEXT_SUFFIXES = {
    ".env",
    ".ini",
    ".json",
    ".js",
    ".md",
    ".ps1",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}


def _tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
    )
    return [
        PROJECT_ROOT / entry.decode("utf-8")
        for entry in result.stdout.split(b"\0")
        if entry
    ]


def _strip_allowed_synthetics(content: str) -> str:
    for token in EXACT_SYNTHETIC_TOKENS:
        content = content.replace(token, "")
    return SYNTHETIC_SK.sub("", content)


def scan_text(relative: str, content: str) -> list[str]:
    """Return violation messages for one file. Never includes matched secret values."""
    violations: list[str] = []
    remainder = _strip_allowed_synthetics(content)
    if PEM_BEGIN.search(remainder) and PEM_END.search(remainder):
        violations.append(f"{relative}: matches secret pattern PEM private key")
    if SK_PATTERN.search(remainder):
        violations.append(f"{relative}: matches secret pattern sk- token")
    if GH_PATTERN.search(remainder):
        violations.append(f"{relative}: matches secret pattern GitHub token")
    return violations


def scan_path(path: Path, relative: str) -> list[str]:
    if path.name == ".env":
        return [f"{relative}: tracked .env file"]
    if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
        return [f"{relative}: tracked private-key file type"]
    if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
        return []
    content = path.read_text(encoding="utf-8", errors="ignore")
    return scan_text(relative, content)


def main() -> int:
    violations: list[str] = []
    for path in _tracked_files():
        relative = path.relative_to(PROJECT_ROOT).as_posix()
        violations.extend(scan_path(path, relative))

    if violations:
        print("Tracked secret check failed:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1

    print("Tracked secret check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
