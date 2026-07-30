"""In-process burst and concurrency controls for the public API."""

from collections import defaultdict, deque
import hashlib
import hmac
import threading
import time

from config import SESSION_SIGNING_SECRET


class SlidingWindowLimiter:
    def __init__(self):
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(
        self, key: str, limit: int, window_seconds: float, now: float | None = None
    ) -> tuple[bool, int]:
        """Record an attempt and return (allowed, retry_after_seconds)."""
        now = time.monotonic() if now is None else now
        cutoff = now - window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(window_seconds - (now - events[0])) + 1)
                return False, retry_after
            events.append(now)
            return True, 0

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


def hash_network_identity(value: str) -> str:
    """Create a stable, non-reversible identifier suitable for operational logs."""
    return hmac.new(
        SESSION_SIGNING_SECRET.encode("utf-8"),
        value.encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()


def client_ip_hash(request) -> str:
    # Render supplies X-Forwarded-For. Use the right-most value added by the
    # nearest proxy so a caller cannot bypass limits with a spoofed first value.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        address = forwarded.rsplit(",", 1)[-1].strip()
    elif request.client:
        address = request.client.host
    else:
        address = "unknown"
    return hash_network_identity(address)
