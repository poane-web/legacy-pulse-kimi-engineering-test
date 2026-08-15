"""Simple in-memory rate limiter for login (per email + IP)."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock

_lock = Lock()
_attempts: dict[str, list[datetime]] = defaultdict(list)


def is_rate_limited(key: str, max_attempts: int, window_seconds: int) -> bool:
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    with _lock:
        times = [t for t in _attempts[key] if t > cutoff]
        _attempts[key] = times
        return len(times) >= max_attempts


def record_attempt(key: str) -> None:
    with _lock:
        _attempts[key].append(datetime.utcnow())


def clear_attempts(key: str) -> None:
    with _lock:
        _attempts.pop(key, None)
