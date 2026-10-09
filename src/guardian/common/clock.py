"""Clock abstractions for injectable, deterministic time in GUARDIAN.

This module provides the abstract base class `Clock`, real system clock `RealClock`,
and deterministic simulation clock `SimClock`. Business logic and pipelines must
never invoke `time.time()` directly; they must always query the injected `Clock`.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod


class Clock(ABC):
    """Abstract interface for time retrieval and time waiting."""

    @abstractmethod
    def now(self) -> float:
        """Return current Unix timestamp in seconds."""
        raise NotImplementedError

    @abstractmethod
    def sleep_until(self, ts: float) -> None:
        """Wait until the specified Unix timestamp.

        Args:
            ts: The target timestamp in seconds. If ts <= now(), returns immediately.
        """
        raise NotImplementedError


class RealClock(Clock):
    """Real system clock implementation using system wall time."""

    def now(self) -> float:
        """Return current real epoch timestamp."""
        return time.time()

    def sleep_until(self, ts: float) -> None:
        """Sleep until the given real timestamp."""
        delay = ts - time.time()
        if delay > 0:
            time.sleep(delay)


class SimClock(Clock):
    """Deterministic simulation clock for repeatable offline evaluations.

    SimClock advances time strictly monotonically through simulation events or
    explicit calls to `advance()` / `advance_to()`. Time never flows backwards.
    """

    def __init__(self, start_time: float = 0.0) -> None:
        if start_time < 0.0:
            raise ValueError(f"start_time cannot be negative: {start_time}")
        self._current_time: float = float(start_time)

    def now(self) -> float:
        """Return the current simulation timestamp."""
        return self._current_time

    def advance(self, dt: float) -> None:
        """Advance simulation time forward by dt seconds.

        Args:
            dt: Non-negative elapsed seconds to advance.

        Raises:
            ValueError: If dt is negative.
        """
        if dt < 0:
            raise ValueError(f"Simulation clock cannot advance backwards (dt={dt})")
        self._current_time += dt

    def advance_to(self, ts: float) -> None:
        """Advance simulation time forward to target timestamp ts.

        Args:
            ts: Target timestamp, must be >= current time.

        Raises:
            ValueError: If ts is in the past relative to current simulation time.
        """
        if ts < self._current_time:
            raise ValueError(
                f"Simulation clock cannot advance backwards: current={self._current_time}, target={ts}"
            )
        self._current_time = float(ts)

    def sleep_until(self, ts: float) -> None:
        """Advance simulation time to target timestamp if it lies in the future.

        In a discrete-event simulation, sleeping until a future timestamp
        simply steps the simulation clock forward to that point.
        """
        if ts > self._current_time:
            self._current_time = float(ts)
