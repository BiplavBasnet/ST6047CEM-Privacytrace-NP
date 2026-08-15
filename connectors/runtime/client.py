"""PrivacyTrace runtime connector (C1). Re-export of the installable client.

In-repo tests import from this module. The installable package lives in
`privacytrace_runtime` and must not be pip-installed into the PrivacyTrace
server virtualenv.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ._bundle_privacy import copy_into

_RUNTIME = Path(__file__).resolve().parent
_SRC = _RUNTIME / "src"
copy_into(_SRC / "privacytrace_runtime")
if str(_SRC) not in sys.path:
    sys.path.append(str(_SRC))

from privacytrace_runtime.client import (  # noqa: E402
    PrivacyTraceLogHandler,
    RuntimeConnector,
    sanitize_data,
    VERSION,
    urlopen,
)

__all__ = [
    "PrivacyTraceLogHandler",
    "RuntimeConnector",
    "sanitize_data",
    "VERSION",
    "urlopen",
]
