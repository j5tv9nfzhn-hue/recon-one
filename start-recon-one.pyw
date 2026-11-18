"""Launcher for the recon-one web console.

Double-click runs `pythonw.exe` because of the global .pyw association, which would hide
the pairing token. So this file re-launches itself under `python.exe` in a console window
rather than running in-process. If you launched it from a terminal already, it just runs.
"""
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    sys.path.insert(0, PROJECT_ROOT)
    # pythonw.exe sets sys.executable to pythonw.exe; relaunch under the console build so
    # the operator can actually read the one-time token.
    if os.path.basename(sys.executable).lower().startswith("pythonw"):
        console = os.path.join(os.path.dirname(sys.executable), "python.exe")
        if os.path.isfile(console):
            subprocess.Popen([console, "-m", "reconone.web"], cwd=PROJECT_ROOT,
                             creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
            return 0
    from reconone.web import serve
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
