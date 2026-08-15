from pathlib import Path
import sys

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

_ROOT = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()
sys.path.insert(0, str(_ROOT))

from _bundle_privacy import copy_into  # noqa: E402


class build_py(_build_py):
    def run(self) -> None:
        super().run()
        dest = Path(self.build_lib) / "privacytrace_runtime"
        try:
            copy_into(dest)
        except FileNotFoundError:
            engine = dest / "services" / "sensitive_exposure_engine.py"
            if not engine.is_file():
                raise RuntimeError(
                    "privacytrace_runtime detector modules missing from the wheel"
                ) from None


setup(cmdclass={"build_py": build_py})
