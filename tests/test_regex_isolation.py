"""Regression tests for issues #30 (F-21) and #21 (F-08).

LLM-authored regex used to run in the main process behind a daemon
thread and join(timeout). A timeout abandoned the thread but did not
kill the match, so a catastrophic pattern kept consuming CPU. These
tests require the isolated worker: on timeout the worker is killed,
joined, and contributes nothing.

The canary is deliberately NOT expected to catch every catastrophic
pattern: ``(a+)+$`` passes the canary input (no long run of ``a``s)
and is only stopped at runtime by the worker timeout. That separation
is the point -- validation is one control, isolation is another.
"""

import multiprocessing
import re
import time

import agents.pattern_learner as pl

CATASTROPHIC = "(a+)+$"
CATASTROPHIC_INPUT = "a" * 30 + "!"


def test_catastrophic_pattern_returns_within_wall_clock_bound():
    start = time.time()
    result = pl._safe_search_with_timeout(
        re.compile(CATASTROPHIC, re.IGNORECASE), CATASTROPHIC_INPUT, timeout=1.0
    )
    elapsed = time.time() - start
    assert result is False
    # Full timeout is expected (the match really does hang), but the
    # call must return promptly after it, not minutes later.
    assert elapsed >= 0.9
    assert elapsed < 5.0


def test_timed_out_execution_is_terminated_and_leaves_no_worker():
    start = time.time()
    result = pl._run_learned(CATASTROPHIC_INPUT, "learned_0", [CATASTROPHIC])
    elapsed = time.time() - start
    assert result == []
    assert elapsed >= 1.9
    assert elapsed < 5.0
    # The killed worker must be joined, not left as a zombie/orphan.
    assert multiprocessing.active_children() == []
    # The worker slot must have been released: a normal pattern works
    # immediately afterwards, in the same process.
    assert pl._run_learned(
        "contract X { function f() external { state sync; } }",
        "learned_0",
        ["state\\s+sync"],
    )


def test_timeout_never_returns_a_partial_match():
    code = "good match\n" + CATASTROPHIC_INPUT
    # The first line matches "good" quickly; the second line hangs.
    # A timeout must discard the whole pattern, not keep the first hit.
    result = pl._run_learned(code, "learned_0", ["(good)|(a+)+$"])
    assert result == []
    assert multiprocessing.active_children() == []


def test_global_concurrency_budget_is_enforced():
    acquired = []
    try:
        for _ in range(pl.MAX_REGEX_WORKERS):
            assert pl._REGEX_WORKER_SEMAPHORE.acquire(blocking=False)
            acquired.append(True)
        start = time.time()
        # No worker slot is free, so no worker may be spawned at all:
        # both entry points must fail fast instead of queueing.
        assert pl._safe_search_with_timeout(
            re.compile("state\\s+sync", re.IGNORECASE), "state sync", timeout=1.0
        ) is False
        assert pl._run_learned("state sync", "learned_0", ["state\\s+sync"]) == []
        assert time.time() - start < 2.0
    finally:
        for _ in acquired:
            pl._REGEX_WORKER_SEMAPHORE.release()
    # After release, normal work resumes.
    assert pl._safe_search_with_timeout(
        re.compile("state\\s+sync", re.IGNORECASE), "state sync", timeout=1.0
    ) is True


def test_worker_resource_limits_are_applied_on_posix():
    try:
        import resource
    except ImportError:
        import pytest

        pytest.skip("resource limits are POSIX-only")
        return

    def _check(queue):
        try:
            pl._apply_worker_limits(1.0)
            queue.put((
                resource.getrlimit(resource.RLIMIT_AS),
                resource.getrlimit(resource.RLIMIT_CPU),
            ))
        except Exception as exc:  # pragma: no cover - child plumbing
            queue.put(("error", str(exc)))

    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    proc = ctx.Process(target=_check, args=(queue,))
    proc.start()
    limits = queue.get(timeout=10)
    proc.join(timeout=10)
    assert limits[0] == (
        pl._REGEX_WORKER_MAX_MEMORY_BYTES,
        pl._REGEX_WORKER_MAX_MEMORY_BYTES,
    )
    assert limits[1] == (3, 3)


def test_invalid_and_oversized_patterns_remain_rejected():
    assert pl._validate_candidate_pattern("[unclosed") is False
    assert pl._validate_candidate_pattern("") is False
    assert pl._validate_candidate_pattern("a" * 501) is False
    assert pl._validate_candidate_pattern(None) is False


def test_normal_pattern_still_matches():
    assert pl._safe_search_with_timeout(
        re.compile("state\\s+sync", re.IGNORECASE), "state sync here", timeout=1.0
    ) is True
    matches = pl._run_learned(
        "contract X { function f() external { state sync; } }",
        "learned_0",
        ["state\\s+sync"],
    )
    assert len(matches) == 1
    assert matches[0]["line"] == 1
    assert matches[0]["class"] == "learned_0"


def test_multiline_scan_still_reports_multiline_matches():
    code = "line1\nline2\nline3"
    matches = pl._run_learned(code, "learned_0", ["line1\\nline2"])
    assert len(matches) == 1
    assert matches[0]["line"] == 1
    assert "line1" in matches[0]["content"]


def test_isolated_runner_reports_error_for_invalid_pattern():
    status, payload = pl._run_regex_isolated(
        "[unclosed", "some text", "search", timeout=1.0
    )
    assert status == "error"
    assert payload == "invalid pattern"
