"""Copy the backend detector allowlist into privacytrace_runtime at build/import.

Detector regexes, taxonomy, and YAML stay authoritative in backend/app.
This rewrites import prefixes only so the wheel does not occupy top-level `app`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ALLOWLIST = (
    "masking_service.py",
    "sensitive_candidate_detection_service.py",
    "sensitive_data_taxonomy_service.py",
    "sensitive_detection_confidence_service.py",
    "sensitive_exposure_engine.py",
    "sensitive_exposure_policy_service.py",
    "sensitive_fingerprint_service.py",
    "sensitive_value_validation_service.py",
    "taxonomy_validator_service.py",
)
RULES = (
    "exposure_policy_rules.yaml",
    "masking_rules.yaml",
    "sensitive_data_rules.yaml",
)


def backend_root() -> Path:
    starts = [Path(__file__).resolve().parent, Path.cwd()]
    seen: set[Path] = set()
    for start in starts:
        for parent in [start, *start.parents]:
            if parent in seen:
                continue
            seen.add(parent)
            candidate = parent / "backend"
            if (candidate / "app" / "services" / "sensitive_exposure_engine.py").is_file():
                return candidate
    raise FileNotFoundError("PrivacyTrace backend detector sources not found")


def rewrite(text: str) -> str:
    return (
        text.replace("from app.config", "from privacytrace_runtime.config")
        .replace("from app.models.enums", "from privacytrace_runtime.models.enums")
        .replace("from app.services", "from privacytrace_runtime.services")
    )


def copy_into(dest_pkg: Path) -> None:
    backend = backend_root()
    services_src = backend / "app" / "services"
    rules_src = backend / "app" / "rules"
    services_dst = dest_pkg / "services"
    rules_dst = dest_pkg / "rules"
    services_dst.mkdir(parents=True, exist_ok=True)
    rules_dst.mkdir(parents=True, exist_ok=True)
    init = services_dst / "__init__.py"
    if not init.exists():
        init.write_text("", encoding="utf-8")
    for name in ALLOWLIST:
        text = rewrite((services_src / name).read_text(encoding="utf-8"))
        if "from app." in text or "import app." in text:
            raise RuntimeError(f"{name} still imports top-level app after rewrite")
        (services_dst / name).write_text(text, encoding="utf-8")
    for name in RULES:
        shutil.copyfile(rules_src / name, rules_dst / name)


if __name__ == "__main__":
    copy_into(Path(__file__).resolve().parent / "src" / "privacytrace_runtime")
