"""
tests/test_scheduler.py — Tests for AgentScheduler.

Validates:
  - Job registration
  - Interval firing (with a tiny sleep)
  - Manual dispatch
  - Context factory injection
  - Multiple job coexistence
  - Graceful start/stop
"""
from __future__ import annotations

import threading
import time

import pytest

from core.scheduler import AgentScheduler


@pytest.fixture
def scheduler():
    sched = AgentScheduler()
    yield sched
    # Ensure scheduler is stopped even if test fails
    try:
        sched.stop()
    except Exception:
        pass


class TestJobRegistration:
    def test_register_single_job(self, scheduler):
        scheduler.register("job1", lambda ctx: None, interval_seconds=60)
        assert "job1" in scheduler.job_names

    def test_register_multiple_jobs(self, scheduler):
        for name in ["a", "b", "c"]:
            scheduler.register(name, lambda ctx: None, interval_seconds=60)
        assert set(scheduler.job_names) == {"a", "b", "c"}

    def test_replace_existing_job(self, scheduler):
        scheduler.register("job1", lambda ctx: "v1", interval_seconds=60)
        scheduler.register("job1", lambda ctx: "v2", interval_seconds=120)
        assert "job1" in scheduler.job_names
        assert len(scheduler.job_names) == 1


class TestContextFactory:
    def test_context_factory_called_on_dispatch(self, scheduler):
        call_log = []
        scheduler.set_context_factory(lambda: {"injected": True})
        scheduler.register("job", lambda ctx: call_log.append(ctx), interval_seconds=999)
        scheduler.dispatch("job")
        assert call_log[-1]["injected"] is True

    def test_dispatch_with_explicit_context(self, scheduler):
        received = []
        scheduler.register("j", lambda ctx: received.append(ctx), interval_seconds=999)
        scheduler.dispatch("j", context={"explicit": "yes"})
        assert received[-1]["explicit"] == "yes"


class TestDispatch:
    def test_dispatch_unknown_job_raises(self, scheduler):
        with pytest.raises(KeyError):
            scheduler.dispatch("nonexistent")

    def test_dispatch_returns_result(self, scheduler):
        scheduler.register("sum_job", lambda ctx: 42, interval_seconds=999)
        result = scheduler.dispatch("sum_job")
        assert result == 42

    def test_dispatch_exception_propagates(self, scheduler):
        def boom(ctx):
            raise ValueError("test error")
        scheduler.register("boom_job", boom, interval_seconds=999)
        with pytest.raises(ValueError, match="test error"):
            scheduler.dispatch("boom_job")


class TestSchedulerLifecycle:
    def test_start_and_stop(self, scheduler):
        scheduler.register("noop", lambda ctx: None, interval_seconds=999)
        scheduler.start()
        time.sleep(0.1)
        scheduler.stop()  # Should not raise

    def test_job_fires_on_interval(self):
        """Verify a job fires within a 2-second interval window."""
        sched = AgentScheduler()
        fired = threading.Event()

        def job(ctx):
            fired.set()

        sched.register("fast_job", job, interval_seconds=1)
        sched.start()
        fired.wait(timeout=3.0)
        sched.stop()
        assert fired.is_set(), "Job did not fire within 3 seconds"

    def test_run_immediately_option(self):
        """With run_immediately=True, job should fire without waiting."""
        sched = AgentScheduler()
        fired = threading.Event()
        sched.register(
            "imm_job", lambda ctx: fired.set(), interval_seconds=999, run_immediately=True
        )
        fired.wait(timeout=2.0)
        sched.stop()
        assert fired.is_set()
