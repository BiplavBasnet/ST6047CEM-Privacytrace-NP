"""Run focused and full backend tests against dedicated PostgreSQL."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.test.yml"
COMPOSE_PROJECT = "privacytrace-np-test"
COMPOSE_DATABASE_URL = (
    "postgresql://privacytrace:privacytrace_test@127.0.0.1:55432/privacytrace_np_test"
)
FOCUSED_TESTS = (
    "app/tests/test_test_database_safety.py",
    "app/tests/test_phase1_phase2_service_repairs.py",
    "app/tests/test_phase3_5_backend_regressions.py",
    "app/tests/test_evidence_provenance_domain.py",
    "app/tests/test_alert_operations.py",
    "app/tests/test_integrity_ledger_domain.py",
    "app/tests/test_restricted_aml_policy.py",
    "app/tests/test_phase8_review_audit.py",
    "app/tests/test_phase8_review_hardening.py",
    "app/tests/test_phase9_fix_verification.py",
    "app/tests/test_phase10_reports_metrics.py",
    "app/tests/test_phase8_10_authenticated_e2e.py",
    "app/tests/test_stabilisation_workflow_e2e.py",
    "app/tests/test_phase11_6_auth_access.py",
    "app/tests/test_auth_registration.py",
    "app/tests/test_auth_registration_e2e.py",
)


@dataclass(frozen=True)
class TestCounts:
    passed: int = 0
    failed: int = 0
    skipped: int = 0

    def __add__(self, other: "TestCounts") -> "TestCounts":
        return TestCounts(
            passed=self.passed + other.passed,
            failed=self.failed + other.failed,
            skipped=self.skipped + other.skipped,
        )


@dataclass(frozen=True)
class TestRun:
    label: str
    returncode: int
    counts: TestCounts


def _validate_test_database_url(database_url: str) -> None:
    parsed = urlparse(database_url)
    database_name = parsed.path.lstrip("/")
    if parsed.scheme not in {"postgresql", "postgresql+psycopg2"}:
        raise SystemExit("Test DATABASE_URL must use PostgreSQL.")
    if not database_name.lower().endswith("_test"):
        raise SystemExit("Test database name must end with '_test'.")


def _compose_command(*arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "-p",
        COMPOSE_PROJECT,
        *arguments,
    ]


def _run(
    command: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
) -> None:
    print("+", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def _compose(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _compose_command(*arguments),
        cwd=PROJECT_ROOT,
        check=check,
        text=True,
        capture_output=not check,
    )


def _wait_for_compose_postgres() -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = _compose(
            "exec",
            "-T",
            "postgres_test",
            "pg_isready",
            "-U",
            "privacytrace",
            "-d",
            "privacytrace_np_test",
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(2)
    raise SystemExit("Test PostgreSQL did not become ready within 90 seconds.")


def _compose_cleanup_mode() -> str | None:
    running = _compose("ps", "-q", "postgres_test", check=False).stdout.strip()
    if running:
        print("Reusing the already-running dedicated Compose PostgreSQL.")
        return None

    existing = _compose("ps", "-a", "-q", "postgres_test", check=False).stdout.strip()
    return "stop" if existing else "down"


def _start_compose_database(cleanup_mode: str | None) -> None:
    if cleanup_mode:
        _run(_compose_command("up", "-d", "--wait", "postgres_test"))
    _wait_for_compose_postgres()


def _cleanup_compose_database(cleanup_mode: str | None) -> None:
    if cleanup_mode == "stop":
        _compose("stop", "postgres_test", check=False)
    elif cleanup_mode == "down":
        _compose("down", "-v", check=False)


def _backend_python() -> str:
    candidates = (
        BACKEND_ROOT / ".venv" / "Scripts" / "python.exe",
        BACKEND_ROOT / ".venv" / "bin" / "python",
    )
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


def _read_junit_counts(path: Path) -> TestCounts:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag.endswith("testsuite") else list(root)
    tests = failures = errors = skipped = 0
    for suite in suites:
        tests += int(suite.attrib.get("tests", 0))
        failures += int(suite.attrib.get("failures", 0))
        errors += int(suite.attrib.get("errors", 0))
        skipped += int(suite.attrib.get("skipped", 0))
    failed = failures + errors
    return TestCounts(passed=max(0, tests - failed - skipped), failed=failed, skipped=skipped)


def _run_pytest(
    python: str,
    *,
    label: str,
    targets: list[str],
    pytest_args: list[str],
    report_dir: Path,
    env: dict[str, str],
) -> TestRun:
    report = report_dir / f".privacytrace-{os.getpid()}-{label}.xml"
    command = [
        python,
        "-m",
        "pytest",
        *pytest_args,
        *targets,
        f"--junitxml={report}",
    ]
    print("+", subprocess.list2cmdline(command), flush=True)
    result = subprocess.run(command, cwd=BACKEND_ROOT, env=env, check=False)
    counts = _read_junit_counts(report) if report.exists() else TestCounts(failed=1)
    print(
        f"{label}: passed={counts.passed} failed={counts.failed} "
        f"skipped={counts.skipped} exit={result.returncode}"
    )
    return TestRun(label=label, returncode=result.returncode, counts=counts)


def _print_summary(runs: list[TestRun]) -> None:
    total = TestCounts()
    print("\nBackend test summary:")
    for run in runs:
        total += run.counts
        print(
            f"  {run.label}: passed={run.counts.passed} "
            f"failed={run.counts.failed} skipped={run.counts.skipped}"
        )
    print(
        f"  executions total: passed={total.passed} "
        f"failed={total.failed} skipped={total.skipped}"
    )


def _finalize_reports(report_dir: Path, *, passed: bool) -> None:
    reports = [
        report_dir / f".privacytrace-{os.getpid()}-{label}.xml"
        for label in ("focused", "critical_db", "full")
    ]
    if passed:
        for report in reports:
            report.unlink(missing_ok=True)
        return

    destination = (
        PROJECT_ROOT
        / ".pytest_cache"
        / "privacytrace-test-results"
        / str(os.getpid())
    )
    destination.mkdir(parents=True, exist_ok=True)
    print("Preserved JUnit reports:", file=sys.stderr)
    for report in reports:
        if report.exists():
            retained = destination / report.name
            report.replace(retained)
            print(f"  {retained}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Keep a Compose database started by this runner.",
    )
    args, pytest_args = parser.parse_known_args()

    external_database_url = os.getenv("TEST_DATABASE_URL")
    database_url = external_database_url or COMPOSE_DATABASE_URL
    _validate_test_database_url(database_url)

    env = os.environ.copy()
    env.update(
        {
            "APP_ENV": "test",
            "DATABASE_URL": database_url,
            "REQUIRE_TEST_POSTGRES": "1",
        }
    )
    python = _backend_python()
    cleanup_mode: str | None = None

    try:
        if external_database_url:
            print("Using TEST_DATABASE_URL; Docker Compose will not be invoked.")
        else:
            cleanup_mode = _compose_cleanup_mode()
            _start_compose_database(cleanup_mode)

        _run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND_ROOT, env=env)
        report_dir = PROJECT_ROOT
        passed = False
        try:
            runs = [
                _run_pytest(
                    python,
                    label="focused",
                    targets=list(FOCUSED_TESTS),
                    pytest_args=pytest_args,
                    report_dir=report_dir,
                    env=env,
                ),
                _run_pytest(
                    python,
                    label="critical_db",
                    targets=["app/tests", "-m", "critical_db"],
                    pytest_args=pytest_args,
                    report_dir=report_dir,
                    env=env,
                ),
                _run_pytest(
                    python,
                    label="full",
                    targets=["app/tests"],
                    pytest_args=pytest_args,
                    report_dir=report_dir,
                    env=env,
                ),
            ]

            _print_summary(runs)
            critical = next(run for run in runs if run.label == "critical_db")
            critical_skipped = (
                env["REQUIRE_TEST_POSTGRES"] == "1"
                and critical.counts.skipped > 0
            )
            passed = not critical_skipped and all(
                run.returncode == 0 for run in runs
            )
            if critical_skipped:
                print(
                    "ERROR: critical_db tests skipped while "
                    "REQUIRE_TEST_POSTGRES=1.",
                    file=sys.stderr,
                )
            return 0 if passed else 1
        finally:
            _finalize_reports(report_dir, passed=passed)
    except subprocess.CalledProcessError as exc:
        return exc.returncode
    finally:
        if cleanup_mode and not args.keep:
            _cleanup_compose_database(cleanup_mode)


if __name__ == "__main__":
    raise SystemExit(main())
