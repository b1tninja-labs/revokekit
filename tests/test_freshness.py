"""RFC 9919 sec. 5: time based freshness, clock injected. Nothing here reads a clock."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta, timezone

import pytest

from revokekit import freshest
from revokekit.freshest import Reason, is_fresh

THIS = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NEXT = THIS + timedelta(days=4)
NOW = THIS + timedelta(days=1)


def test_a_response_inside_its_interval_is_fresh():
    verdict = is_fresh(THIS, NEXT, now=NOW)
    assert verdict.fresh
    assert verdict.reason is Reason.FRESH
    assert bool(verdict)


def test_missing_nextupdate_is_rejected():
    verdict = is_fresh(THIS, None, now=NOW)
    assert not verdict.fresh
    assert verdict.reason is Reason.NO_NEXT_UPDATE


def test_expired_nextupdate_is_rejected():
    verdict = is_fresh(THIS, NEXT, now=NEXT + timedelta(seconds=1))
    assert (verdict.fresh, verdict.reason) == (False, Reason.STALE)


def test_nextupdate_boundary_is_accepting():
    assert is_fresh(THIS, NEXT, now=NEXT).fresh
    assert is_fresh(THIS, NEXT, now=THIS).fresh


def test_tolerance_applies_after_nextupdate_only_and_inclusively():
    grace = timedelta(minutes=5)
    assert is_fresh(THIS, NEXT, now=NEXT + grace, tolerance=grace).fresh
    assert not is_fresh(THIS, NEXT, now=NEXT + grace + timedelta(seconds=1), tolerance=grace).fresh
    assert not is_fresh(THIS, NEXT, now=THIS - timedelta(seconds=1), tolerance=grace).fresh


def test_thisupdate_in_the_future_is_rejected_by_default():
    verdict = is_fresh(THIS, NEXT, now=THIS - timedelta(seconds=1))
    assert (verdict.fresh, verdict.reason) == (False, Reason.NOT_YET_VALID)


def test_early_tolerance_is_explicit_and_inclusive():
    skew = timedelta(minutes=5)
    assert is_fresh(THIS, NEXT, now=THIS - skew, early_tolerance=skew).fresh
    late = THIS - skew - timedelta(seconds=1)
    assert not is_fresh(THIS, NEXT, now=late, early_tolerance=skew).fresh


def test_interval_that_ends_before_it_starts_is_rejected():
    verdict = is_fresh(NEXT, THIS, now=NOW)
    assert verdict.reason is Reason.BAD_INTERVAL


def test_max_age_is_policy_and_off_by_default():
    assert is_fresh(THIS, NEXT, now=THIS + timedelta(days=3)).fresh
    verdict = is_fresh(THIS, NEXT, now=THIS + timedelta(days=3), max_age=timedelta(days=2))
    assert (verdict.fresh, verdict.reason) == (False, Reason.TOO_OLD)
    assert is_fresh(THIS, NEXT, now=THIS + timedelta(days=2), max_age=timedelta(days=2)).fresh


def test_naive_datetime_refused():
    naive = datetime(2026, 11, 2, 12, 0)
    for this, nxt, now in ((naive, NEXT, NOW), (THIS, naive, NOW), (THIS, NEXT, naive)):
        with pytest.raises(ValueError, match="timezone-aware"):
            is_fresh(this, nxt, now=now)


def test_offsets_are_compared_as_instants():
    plus_nine = timezone(timedelta(hours=9))
    assert is_fresh(THIS.astimezone(plus_nine), NEXT.astimezone(plus_nine), now=NOW).fresh


def test_negative_tolerances_refused():
    for name in ("tolerance", "early_tolerance", "max_age"):
        with pytest.raises(ValueError, match="negative"):
            is_fresh(THIS, NEXT, now=NOW, **{name: timedelta(-1)})


def test_a_matching_nonce_cannot_excuse_a_stale_response():
    """RFC 9919 sec. 5 makes the time check mandatory, so is_fresh takes no nonce at all."""
    assert "nonce" not in " ".join(inspect.signature(is_fresh).parameters)
    assert not is_fresh(THIS, NEXT, now=NEXT + timedelta(days=30)).fresh


def test_module_never_reads_the_clock():
    source = inspect.getsource(freshest)
    assert "now()" not in source
    assert "utcnow" not in source
    assert "time.time" not in source


def test_single_response_times_feed_is_fresh():
    """The times come from a parsed SingleResponse; producedAt plays no part (RFC 9919 sec. 5)."""
    from pki_helpers import DAY, HOUR, NOW, make_ca, make_leaf, ocsp_response, single_response

    from revokekit import response

    ca = make_ca()
    leaf = make_leaf(ca)
    # The builder stamps producedAt with the real clock (after the interval); only the single's own
    # interval counts.
    raw = ocsp_response(
        ca,
        [single_response(leaf, ca, this_update=NOW - 3 * DAY, next_update=NOW - HOUR)],
    )
    basic = response.parse(raw).basic
    assert basic is not None
    single = response.match(basic, leaf.parsed, ca.parsed)
    assert basic.produced_at >= single.this_update
    verdict = is_fresh(single.this_update, single.next_update, now=NOW)
    assert not verdict
    assert verdict.reason is Reason.STALE
    assert is_fresh(single.this_update, single.next_update, now=NOW - 2 * DAY)
