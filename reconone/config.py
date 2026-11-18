"""Version, scan profiles, limits and rule loading."""
from __future__ import annotations

import json
import os
from typing import Any

VERSION = "1.0.0"
SCHEMA_ID = "recon-one/1"
DEFAULT_UA = "recon-one/1.0 (authorized security assessment)"

# Authorised-use notice. It lives in config (not in a doc) because it has to reach three
# places that a doc cannot: the console banner, the report's `meta.authorization`, and the
# human-readable report header. One definition, no drift between them.
AUTHORIZED_USE_VERSION = "1"
AUTHORIZED_USE = (
    "本工具只允许对**你拥有或已获得明确书面授权**的目标使用。运行前必须确认："
    "(1) 目标所有者已书面同意本次侦察的范围与时间窗口；"
    "(2) 你已了解本地法律对未授权访问的规定（例如《中华人民共和国刑法》第 285 条、"
    "美国 CFAA 18 U.S.C. § 1030、英国 Computer Misuse Act 1990）；"
    "(3) 你会在授权范围变化时立即停止。"
    "工具不发送攻击载荷、不爆破口令、不做业务逻辑验证，但它产生的数据（端点、密钥线索、"
    "历史路径）本身即为敏感信息，须按授权范围保管。"
)
AUTHORIZED_USE_SHORT = "仅限已获书面授权的目标；未授权使用可能构成犯罪。"

# What the operator must have before a scan is legitimate. Recorded verbatim in the report so
# an auditor can see which premises the run rested on, rather than taking it on trust.
AUTHORIZED_USE_PREMISES = (
    "written authorization from the target owner covering scope and time window",
    "awareness of applicable computer-misuse law in the operator's jurisdiction",
    "a stop condition if authorization changes or is withdrawn",
)
# Every limit is explicit so a scan can be budgeted before it starts.
PROFILES: dict[str, dict[str, Any]] = {
    "fast": {
        "max_pages": 8,
        "max_depth": 1,
        "max_scripts": 12,
        "max_js_bytes": 512_000,
        "max_total_js_bytes": 4_000_000,
        "max_total_bytes": 16_000_000,
        "timeout": 8.0,
        "concurrency": 6,
        "budget_seconds": 90,
        "include_subdomains": False,
    },
    "default": {
        "max_pages": 40,
        "max_depth": 2,
        "max_scripts": 60,
        "max_js_bytes": 1_500_000,
        "max_total_js_bytes": 12_000_000,
        "max_total_bytes": 40_000_000,
        "timeout": 12.0,
        "concurrency": 8,
        "budget_seconds": 300,
        "include_subdomains": False,
    },
    "deep": {
        "max_pages": 150,
        "max_depth": 3,
        "max_scripts": 200,
        "max_js_bytes": 3_000_000,
        "max_total_js_bytes": 40_000_000,
        "max_total_bytes": 120_000_000,
        "timeout": 15.0,
        "concurrency": 10,
        "budget_seconds": 900,
        "include_subdomains": True,
    },
}

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")

# ---------------------------------------------------------------------------
# Output location
# ---------------------------------------------------------------------------
# Reports must not depend on the process working directory: double-clicking the GUI,
# running from a shortcut with a different "Start in", or invoking the CLI from another
# folder would otherwise scatter runs/ wherever the shell happened to be.
#
# Resolution order for the default output root:
#   1. RECONONE_OUTPUT_DIR (absolute, or ~/… — lets an operator keep reports outside a
#      synced/read-only project dir, or on a bigger disk)
#   2. <project root>/runs   (stable, independent of CWD)
FALLBACK_OUTPUT_ROOT = os.path.join(PROJECT_ROOT, "runs")

# Directory names that the report package itself owns. A run directory may never take one
# of these names, otherwise <runs>/<name> collides with <runs>/<domain>/<name> and the
# package silently flattens into the runs root.
RESERVED_RUN_NAMES = frozenset({"raw", "report"})

_MAX_RUN_NAME = 120


def output_root() -> str:
    """Absolute directory that holds one subdirectory per scanned target."""
    raw = os.environ.get("RECONONE_OUTPUT_DIR", "").strip()
    if not raw:
        return FALLBACK_OUTPUT_ROOT
    return os.path.abspath(os.path.expandvars(os.path.expanduser(raw)))


def run_dir_name(domain: str) -> str:
    """Filesystem-safe *host* directory name for a target.

    Only the host part is used: upstream callers sometimes pass a full URL, and
    "https_x.com" is a worse directory name than "x.com".
    """
    from .util import safe_name, host_of          # local import: avoid an import cycle
    value = (domain or "").strip()
    if "://" in value:
        value = host_of(value) or value
    elif "/" in value:
        value = value.split("/", 1)[0]
    name = safe_name(value, limit=_MAX_RUN_NAME)
    # A target whose sanitised name lands on a package directory name gets a prefix, so
    # `runs/raw` can only ever be the target "raw", never the artefact folder.
    if name.lower() in RESERVED_RUN_NAMES:
        name = "host_" + name
    return name


def default_out_dir(domain: str) -> str:
    """Absolute default run directory for one target: <root>/<host>."""
    return os.path.join(output_root(), run_dir_name(domain or "target"))


def find_existing_run(domain: str) -> str:
    """Return an existing run directory for `domain`, or "" if there is none.

    Matching is case-insensitive and tolerant of the older layout that included the port,
    so a report written before this naming rule was introduced is still found instead of
    silently duplicated under a new name.
    """
    root = output_root()
    if not os.path.isdir(root):
        return ""
    wanted = run_dir_name(domain).lower()
    legacy = wanted.replace("_", ":")            # 127.0.0.1_8080 -> 127.0.0.1:8080
    for entry in sorted(os.listdir(root)):
        full = os.path.join(root, entry)
        if not os.path.isdir(full):
            continue
        low = entry.lower()
        if low == wanted or low == legacy:
            return full
        if low.startswith(wanted + "_") or low.startswith(wanted + "-"):
            if not any(os.path.isdir(os.path.join(full, sub)) for sub in RESERVED_RUN_NAMES):
                return full
    return ""


def ensure_out_dir(domain: str, requested: str = "") -> str:
    """Create and return the run directory, enforcing the per-domain layout.

    Two defensive rules, both learned from real damage:

    1. `requested` may not point at the runs root itself. Passing the root used to make
       report/ and raw/ land directly in runs/, mixing several targets in one folder.
    2. It also may not end in a reserved package name; such a path is re-rooted under
       <root>/<host> instead of being rejected, so a stale Default value still scans.
    """
    from .util import ensure_dir
    root = os.path.abspath(output_root())
    if not requested:
        target = os.path.join(root, run_dir_name(domain))
    else:
        target = os.path.abspath(os.path.expandvars(os.path.expanduser(requested)))
        if os.path.normcase(target) == os.path.normcase(root):
            # The caller pointed at the shared root: give the target its own level.
            target = os.path.join(root, run_dir_name(domain))
        elif os.path.basename(target).lower() in RESERVED_RUN_NAMES:
            target = os.path.join(os.path.dirname(target), run_dir_name(domain))
    ensure_dir(target)
    return target

_CACHE: dict[str, Any] = {}


def load_rule(name: str, default=None):
    if name in _CACHE:
        return _CACHE[name]
    path = os.path.join(RULES_DIR, f"{name}.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = default if default is not None else {}
    _CACHE[name] = data
    return data


def profile(name: str) -> dict[str, Any]:
    if name not in PROFILES:
        raise SystemExit(f"unknown profile '{name}' (choose from {', '.join(PROFILES)})")
    return dict(PROFILES[name])
