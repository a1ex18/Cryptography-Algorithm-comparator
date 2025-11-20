"""Security utilities for cryptographic benchmarks.

Provides a central source of randomness, constant-time comparisons,
and lightweight run-guarding to mitigate replayed progress events.
"""
from __future__ import annotations

import hmac
import secrets
import threading
from typing import Optional


class SecureRandom:
    """Wrap OS-backed randomness to centralize key/message generation."""

    @staticmethod
    def bytes(length: int) -> bytes:
        if length <= 0:
            raise ValueError("length must be positive")
        return secrets.token_bytes(length)

    @staticmethod
    def token() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def bits(bit_count: int) -> int:
        if bit_count <= 0:
            raise ValueError("bit_count must be positive")
        return secrets.randbits(bit_count)


RNG = SecureRandom()


def secure_compare(left: bytes, right: bytes) -> bool:
    """Constant-time comparison helper for sensitive values."""
    if not isinstance(left, (bytes, bytearray)) or not isinstance(right, (bytes, bytearray)):
        raise TypeError("secure_compare expects bytes-like inputs")
    return hmac.compare_digest(left, right)


class RunGuard:
    """Track the current benchmark run to dampen replayed progress events."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: Optional[str] = None

    def start(self, run_id: Optional[str] = None) -> str:
        """Register a new active run, replacing any existing run identifier."""
        new_id = run_id or secrets.token_hex(16)
        with self._lock:
            self._active = new_id
        return new_id

    def is_active(self, run_id: str) -> bool:
        with self._lock:
            return self._active == run_id

    def current(self) -> Optional[str]:
        with self._lock:
            return self._active

    def stop(self, run_id: str) -> None:
        with self._lock:
            if self._active == run_id:
                self._active = None


run_guard = RunGuard()
