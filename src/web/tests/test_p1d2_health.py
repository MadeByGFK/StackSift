"""Regression tests for P1-D2: Clearer messaging for timestamp-parse failures.

When timeline is empty, distinguish "Timestamps Not Recognized" (events exist
but no timestamps parsed) from "Health Undetermined" (insufficient data).
"""
import sys
sys.path.insert(0, 'src/web')

from app.vendor.insights import determine_health


def test_timestamps_not_recognized():
    """Events exist but none have timestamps → specific message."""
    label, color = determine_health(
        {"INFO": 100, "ERROR": 5},
        bucket_totals=[],
        events_total=105,
        timestamped_total=0,
    )
    assert label == "Timestamps Not Recognized", f"Got: {label}"
    assert color == "gray"
    print("✓ Timestamps Not Recognized when events lack timestamps")


def test_health_undetermined_no_events():
    """No events at all → generic Undetermined (not a parsing issue)."""
    label, _ = determine_health(
        {}, bucket_totals=[], events_total=0, timestamped_total=0
    )
    assert label == "Health Undetermined", f"Got: {label}"
    print("✓ Health Undetermined when no events")


def test_health_undetermined_sparse_data():
    """Sparse data (few buckets) still returns Undetermined."""
    label, _ = determine_health(
        {"INFO": 5}, bucket_totals=[2, 1], events_total=5, timestamped_total=5
    )
    assert label == "Health Undetermined", f"Got: {label}"
    print("✓ Health Undetermined for sparse data")


def test_timestamps_present_normal_flow():
    """When timestamps exist, normal health classification applies."""
    # Sufficient data, flat timeline → No Escalation
    label, _ = determine_health(
        {"INFO": 50},
        bucket_totals=[10, 10, 10, 10, 10],
        events_total=50,
        timestamped_total=50,
    )
    assert label == "No Escalation Detected", f"Got: {label}"
    print("✓ Normal flow unaffected when timestamps present")


def test_backwards_compatible_defaults():
    """Old callers without new params get previous behavior."""
    label, _ = determine_health({"INFO": 10}, bucket_totals=[])
    assert label == "Health Undetermined", f"Got: {label}"
    print("✓ Backwards compatible (no new params)")


def test_critical_still_takes_precedence():
    """CRITICAL events still return Critical even with no timestamps."""
    label, color = determine_health(
        {"CRITICAL": 1}, bucket_totals=[],
        events_total=1, timestamped_total=0
    )
    assert label == "Critical", f"Got: {label}"
    assert color == "red"
    print("✓ CRITICAL takes precedence over timestamp message")


if __name__ == "__main__":
    test_timestamps_not_recognized()
    test_health_undetermined_no_events()
    test_health_undetermined_sparse_data()
    test_timestamps_present_normal_flow()
    test_backwards_compatible_defaults()
    test_critical_still_takes_precedence()
    print("\n✅ All P1-D2 regression tests passed!")
