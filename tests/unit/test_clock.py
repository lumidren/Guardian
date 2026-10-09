"""Unit tests for Clock interface and implementations (RealClock and SimClock)."""

import pytest

from guardian.common.clock import Clock, RealClock, SimClock


def test_clock_abc_cannot_be_instantiated() -> None:
    """Clock is an abstract interface and cannot be directly instantiated."""
    with pytest.raises(TypeError):
        Clock()  # type: ignore[abstract]


def test_real_clock_now_and_sleep() -> None:
    """RealClock tracks real system epoch time and handles sleep_until."""
    clock = RealClock()
    t1 = clock.now()
    assert isinstance(t1, float)
    assert t1 > 0

    # sleep_until in the past should return immediately
    clock.sleep_until(t1 - 10.0)
    t2 = clock.now()
    assert t2 >= t1

    # sleep_until a tiny fraction ahead
    target = clock.now() + 0.01
    clock.sleep_until(target)
    assert clock.now() >= target - 0.005  # allowing timer resolution tolerance


def test_sim_clock_initial_and_monotonicity() -> None:
    """SimClock starts at given timestamp and respects monotonicity."""
    sim = SimClock(start_time=1000.0)
    assert sim.now() == 1000.0

    # Advance time
    sim.advance(5.5)
    assert sim.now() == 1005.5

    # advance_to
    sim.advance_to(1010.0)
    assert sim.now() == 1010.0

    # Cannot advance backwards
    with pytest.raises(ValueError, match="cannot advance backwards"):
        sim.advance(-1.0)

    with pytest.raises(ValueError, match="cannot advance backwards"):
        sim.advance_to(1005.0)


def test_sim_clock_sleep_until() -> None:
    """SimClock sleep_until advances simulation time deterministically."""
    sim = SimClock(start_time=500.0)
    # Sleep until future
    sim.sleep_until(550.0)
    assert sim.now() == 550.0

    # Sleep until past does not move backwards
    sim.sleep_until(520.0)
    assert sim.now() == 550.0
