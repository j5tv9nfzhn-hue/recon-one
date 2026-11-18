"""First-run pairing and password storage.

Design constraints that drove this file:

* The token is single-use and dies the moment a password is set.
* Nothing is written outside the run directory. Not `%APPDATA%`, not `/var`, not the
  temporary directory. If somebody copies the folder to another disk, the credential
  state travels with it or not at all.
* Passwords are stored as PBKDF2-HMAC-SHA256 with a per-install random salt and a
  constant-time comparison. No plaintext, no reversible encoding.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

PBKDF2_ROUNDS = 240_000
MIN_PASSWORD_LEN = 10


class AuthError(Exception):
    """Raised when a request cannot be authenticated."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class Store:
    """All mutable state lives in one directory, by construction."""

    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        self.state_dir = os.path.join(self.root, "state")
        self.state_file = os.path.join(self.state_dir, "auth.json")
        os.makedirs(self.state_dir, exist_ok=True)

    # ------------------------------------------------------------------ persistence
    def load(self) -> dict:
        try:
            with open(self.state_file, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def save(self, data: dict) -> None:
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, self.state_file)
        try:
            os.chmod(self.state_file, 0o600)
        except OSError:
            pass


REMEMBER_DAYS = 30
SESSION_TTL = REMEMBER_DAYS * 24 * 3600
MAX_SESSIONS = 24


def _sid_key(sid: str) -> str:
    """Sessions are stored by hash: a leaked state/sessions.json is not a login token."""
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


class Auth:
    """Token pairing on first run, password login afterwards.

    The session list is persisted next to the credential so a browser that already logged
    in keeps working after the console process is restarted — the operator sets the
    password once, not once per launch.
    """

    def __init__(self, root: str) -> None:
        self.store = Store(root)
        self.data = self.store.load()
        self.session_file = os.path.join(self.store.state_dir, "sessions.json")
        self.failures: list[float] = []
        self.sessions: dict[str, float] = self._load_sessions()
        self.session_ttl = SESSION_TTL

    # ------------------------------------------------------------------ sessions storage
    def _load_sessions(self) -> dict[str, float]:
        try:
            with open(self.session_file, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return {}
        now = time.time()
        live = {str(k): float(v) for k, v in raw.items() if isinstance(v, (int, float)) and v > now}
        return live

    def _save_sessions(self) -> None:
        tmp = self.session_file + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.sessions, fh, indent=0, sort_keys=True)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.session_file)
        except OSError:
            pass          # a read-only state dir must not break login itself

    def _prune(self) -> None:
        now = time.time()
        self.sessions = {k: v for k, v in self.sessions.items() if v > now}
        if len(self.sessions) <= MAX_SESSIONS:
            return
        keep = sorted(self.sessions.items(), key=lambda kv: kv[1], reverse=True)[:MAX_SESSIONS]
        self.sessions = dict(keep)

    # ------------------------------------------------------------------ first run
    @property
    def configured(self) -> bool:
        return bool(self.data.get("phc"))

    def issue_token(self) -> str:
        """Create (or reuse) the one-time pairing token and return it.

        Reusing the same token across restarts of an unconfigured instance keeps the
        console output stable, so a user who restarts does not chase a stale code.
        """
        if self.configured:
            raise AuthError("已经设置过密码，不再下发一次性令牌")
        token = self.data.get("token")
        if not token:
            token = "TKN-" + "-".join(
                secrets.token_hex(2).upper() for _ in range(3)
            )
            self.data["token"] = token
            self.data["token_issued_at"] = int(time.time())
            self.store.save(self.data)
        return token

    def claim(self, token: str, password: str) -> None:
        """Consume the token and set the password. The token stops working here."""
        if self.configured:
            raise AuthError("已经完成初始化")
        expected = self.data.get("token") or ""
        if not expected or not hmac.compare_digest(str(token).strip(), expected):
            raise AuthError("令牌不正确")
        self.validate_password(password)
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
        self.data = {
            "phc": _b64(digest),
            "salt": _b64(salt),
            "rounds": PBKDF2_ROUNDS,
            "created_at": int(time.time()),
        }
        # The token is dropped from disk, not just invalidated in memory.
        self.store.save(self.data)
        self.data = self.store.load()
        # Setting a password invalidates any session issued before it existed.
        self.forget_all_sessions()

    @staticmethod
    def validate_password(password: str) -> None:
        if len(password or "") < MIN_PASSWORD_LEN:
            raise AuthError(f"密码至少 {MIN_PASSWORD_LEN} 位")
        if password.isdigit() or password.isalpha():
            raise AuthError("密码不能只用数字或只用字母")
        if password.lower() in {"password12", "12345678910", "qwertyuiop1"}:
            raise AuthError("这个密码太常见了")

    # ------------------------------------------------------------------ login
    def check_password(self, password: str) -> bool:
        if not self.configured:
            return False
        expected = _unb64(self.data["phc"])
        salt = _unb64(self.data["salt"])
        rounds = int(self.data.get("rounds", PBKDF2_ROUNDS))
        got = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, rounds)
        return hmac.compare_digest(got, expected)

    def _throttle(self) -> None:
        """Five failures per minute, sliding. Cheap, and enough to stop a script."""
        now = time.time()
        self.failures = [t for t in self.failures if now - t < 60]
        if len(self.failures) >= 5:
            wait = int(60 - (now - self.failures[0])) + 1
            raise AuthError(f"尝试次数过多，请等待 {wait} 秒")

    def login(self, password: str) -> str:
        self._throttle()
        if not self.check_password(password):
            self.failures.append(time.time())
            raise AuthError("密码不正确")
        sid = secrets.token_urlsafe(32)
        self.sessions[_sid_key(sid)] = time.time() + self.session_ttl
        self._prune()
        self._save_sessions()
        return sid

    # ------------------------------------------------------------------ sessions
    def session_valid(self, sid: str | None) -> bool:
        if not sid:
            return False
        key = _sid_key(sid)
        exp = self.sessions.get(key)
        if not exp or exp < time.time():
            if key in self.sessions:
                self.sessions.pop(key, None)
                self._save_sessions()
            return False
        return True

    def logout(self, sid: str | None) -> None:
        if sid:
            self.sessions.pop(_sid_key(sid), None)
            self._save_sessions()

    def forget_all_sessions(self) -> None:
        """Drop every remembered browser (used when the password is (re)set)."""
        self.sessions.clear()
        self._save_sessions()
