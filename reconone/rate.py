"""Per-host pacing: a token interval plus throttle backoff.

Two different problems, one limiter:

* **Pacing** — `--rate N` means "at most N requests per second *per host*". One busy host must
  not slow down another, so the state is keyed by host, not global.
* **Backoff** — when a host answers 429/503 it is telling us something: slow down. The limiter
  honours `Retry-After` when present and otherwise doubles the delay per consecutive throttle
  (0.5s → 1s → 2s → 4s → 8s cap). The delay is applied to the *next* request to that host; the
  current response is still returned to the caller, because a 429 is a finding, not an error.

Nothing here decides policy for the operator: rate limiting off by default (`--rate 0`), the
caps are explicit, and every wait is counted so the report can say how much time pacing cost.
"""
from __future__ import annotations

import time

THROTTLE_STATUS = (429, 503)


class Limiter:
    """Per-host pacing + throttle backoff. Injectable clock/sleep for deterministic tests."""

    def __init__(self, rate: float = 0.0, base_backoff: float = 0.5, max_backoff: float = 8.0,
                 max_wait: float = 5.0, clock=time.monotonic, sleep=time.sleep):
        self.rate = max(0.0, float(rate or 0.0))
        self.interval = (1.0 / self.rate) if self.rate > 0 else 0.0
        self.base_backoff = max(0.0, float(base_backoff))
        self.max_backoff = max(self.base_backoff, float(max_backoff))
        # A single wait is capped so a hostile Retry-After cannot stall a scan indefinitely.
        self.max_wait = max(0.0, float(max_wait))
        self.clock = clock
        self.sleep = sleep
        self.hosts: dict[str, dict] = {}
        self.waits = 0
        self.slept = 0.0
        self.throttled = 0
        self.max_backoff_seen = 0.0

    # -- state -----------------------------------------------------------------
    def _state(self, host: str) -> dict:
        return self.hosts.setdefault(
            str(host or "").lower(),
            {"next": 0.0, "block_until": 0.0, "strikes": 0, "requests": 0, "throttles": 0})

    # -- before/after ----------------------------------------------------------
    def before(self, host: str, deadline: float | None = None) -> float:
        """Sleep if this host is not ready. Returns seconds actually slept."""
        state = self._state(host)
        if self.interval <= 0 and state["block_until"] <= self.clock():
            return 0.0
        now = self.clock()
        target = max(state["next"], state["block_until"])
        wait = target - now
        if wait <= 0:
            if self.interval > 0:
                state["next"] = max(now, state["next"]) + self.interval
            return 0.0
        wait = min(wait, self.max_wait)
        if deadline is not None:
            left = deadline - now
            if left <= 0:
                return 0.0
            wait = min(wait, left)
        self.sleep(wait)
        self.slept += wait
        self.waits += 1
        now = self.clock()
        if self.interval > 0:
            state["next"] = max(now, state["next"]) + self.interval
        return wait

    def after(self, host: str, status: int, headers: dict | None = None) -> None:
        """Update state from a response: throttles push the next request out, success resets."""
        state = self._state(host)
        state["requests"] += 1
        if status not in THROTTLE_STATUS:
            state["strikes"] = 0
            return
        state["throttles"] += 1
        self.throttled += 1
        delay = self._retry_after(headers)
        if delay is None:
            state["strikes"] += 1
            delay = min(self.max_backoff, self.base_backoff * (2 ** (state["strikes"] - 1)))
        else:
            state["strikes"] = max(1, state["strikes"])
        delay = min(delay, self.max_backoff)
        self.max_backoff_seen = max(self.max_backoff_seen, delay)
        state["block_until"] = max(state["block_until"], self.clock() + delay)

    @staticmethod
    def _retry_after(headers: dict | None) -> float | None:
        if not isinstance(headers, dict):
            return None
        value = headers.get("retry-after") or headers.get("Retry-After")
        if value is None or str(value).strip() == "":
            return None
        try:
            return max(0.0, float(str(value).strip()))
        except ValueError:
            return None                        # HTTP-date form is recognised, not parsed

    # -- reporting -------------------------------------------------------------
    def stats(self) -> dict:
        hosts = {name: {"requests": state["requests"], "throttles": state["throttles"],
                        "strikes": state["strikes"]}
                 for name, state in sorted(self.hosts.items()) if state["requests"]}
        return {
            "rate_per_s": self.rate,
            "interval_ms": round(self.interval * 1000, 1),
            "waits": self.waits,
            "slept_s": round(self.slept, 2),
            "throttled": self.throttled,
            "max_backoff_s": round(self.max_backoff_seen, 2),
            "hosts": hosts,
            "note": ("速率按 host 独立计算；429/503 会按 Retry-After 或指数退避推后该 host 的下一次请求，"
                     "等待时长有上限，不会无限停滞。"),
        }
