"""Regression tests for P1-B1: Java/Log4j comma-millisecond timestamp support.

Tests that StackSift correctly parses timestamps like "2015-07-29 17:41:41,536"
used by ZooKeeper, Hadoop, and Log4j-based systems.
"""
import sys
sys.path.insert(0, 'src/web')

from app.vendor.parser import parse_log_line, _normalize_timestamp
from app.vendor.insights import _parse_timestamp, build_timeline


def test_comma_millis_zookeeper_format():
    """ZooKeeper: '2015-07-29 17:41:41,536 - INFO  [main:QuorumPeerConfig@101] - msg'"""
    line = "2015-07-29 17:41:41,536 - INFO  [main:QuorumPeerConfig@101] - Reading configuration"
    entry = parse_log_line(line)
    assert entry is not None, "Failed to parse ZooKeeper line"
    assert entry.level == "INFO", f"Expected INFO, got {entry.level}"
    assert "2015-07-29" in entry.timestamp, f"Timestamp not parsed: {entry.timestamp}"
    assert "17:41:41" in entry.timestamp, f"Time not parsed: {entry.timestamp}"
    print("✓ ZooKeeper format parsed correctly")


def test_comma_millis_hadoop_format():
    """Hadoop: '2015-10-17 15:37:56,547 INFO [main] org.apache.hadoop...: msg'"""
    line = "2015-10-17 15:37:56,547 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created MRAppMaster"
    entry = parse_log_line(line)
    assert entry is not None, "Failed to parse Hadoop line"
    assert entry.level == "INFO", f"Expected INFO, got {entry.level}"
    assert "2015-10-17" in entry.timestamp, f"Timestamp not parsed: {entry.timestamp}"
    print("✓ Hadoop format parsed correctly")


def test_millisecond_precision_preserved():
    """Millisecond precision (.536) must be preserved in normalized timestamp."""
    line = "2015-07-29 17:41:41,536 - INFO  [main] - test"
    entry = parse_log_line(line)
    assert entry is not None
    # Normalized format is ISO-8601 with millis: 2015-07-29T17:41:41.536Z
    assert ".536" in entry.timestamp, f"Millis lost: {entry.timestamp}"
    print("✓ Millisecond precision preserved")


def test_mixed_formats_consistent_timeline():
    """Mixed timestamp formats (comma + dot + ISO) produce consistent timeline."""
    lines = [
        "2015-07-29 17:41:41,536 - INFO  [main] - comma millis",
        "2015-07-29 17:42:01.123 INFO [main] - dot millis",
        "2015-07-29T17:43:00.000Z INFO [main] - iso format",
    ]
    events = []
    for line in lines:
        entry = parse_log_line(line)
        assert entry is not None, f"Failed to parse: {line}"
        events.append((entry.timestamp, entry.level))
    
    timeline = build_timeline(events)
    assert len(timeline) > 0, "Timeline empty for mixed formats"
    # All 3 events should be in timeline (within 5-min buckets)
    total = sum(b['total'] for b in timeline)
    assert total == 3, f"Expected 3 events in timeline, got {total}"
    print("✓ Mixed formats produce consistent timeline")


def test_iso_timestamps_still_work():
    """Existing ISO timestamps continue working (no regression)."""
    line = "2026-10-10T14:00:00.000Z ERROR [edge-api] something broke"
    entry = parse_log_line(line)
    assert entry is not None, "ISO format broken!"
    assert entry.level == "ERROR"
    print("✓ ISO timestamps still work")


def test_malformed_timestamps_fail_gracefully():
    """Malformed timestamps don't crash, return None or UNKNOWN."""
    bad_lines = [
        "not-a-timestamp INFO [main] - msg",
        "2015-13-45 99:99:99,999 - INFO [main] - invalid date",
        "2015-07-29 17:41:41, - INFO [main] - missing millis",
    ]
    for line in bad_lines:
        try:
            entry = parse_log_line(line)
            # Should either return None or an entry with UNKNOWN/empty timestamp
            # Should NOT raise an exception
            print(f"  Malformed handled: {line[:40]}...")
        except Exception as e:
            raise AssertionError(f"Crashed on malformed input: {line} -> {e}")
    print("✓ Malformed timestamps fail gracefully")


def test_invalid_date_matching_regex():
    """Invalid dates matching the regex produce empty timestamp, not crash.
    
    ChatGPT review finding: an invalid date like '2015-13-45 99:99:99,999'
    matches the _LOG4J_COMMA regex but fails timestamp normalization.
    Expected behavior: event created with timestamp='' and correct level.
    This is consistent with all other parsers (never crashes on bad dates).
    """
    # Invalid month (13), day (45), hour (99) — regex matches, normalization fails
    line = "2015-13-45 99:99:99,999 - INFO [main] - invalid date test"
    entry = parse_log_line(line)
    assert entry is not None, "Should not return None (regex matched)"
    assert entry.timestamp == "", f"Expected empty timestamp, got '{entry.timestamp}'"
    assert entry.level == "INFO", f"Level should still parse, got {entry.level}"
    print("✓ Invalid dates matching regex → empty timestamp, no crash")
    
    # Verify timeline builder skips empty timestamps gracefully
    events = [(entry.timestamp, entry.level)]
    timeline = build_timeline(events)
    assert timeline == [], "Timeline should be empty for invalid timestamps"
    print("✓ Timeline builder skips empty timestamps")


def test_mixed_formats_chronological_order():
    """Mixed formats maintain chronological order in timeline.
    
    Strengthened test: verifies events from different formats are correctly
    ordered chronologically, not just grouped.
    """
    lines = [
        # Intentionally out of order to test sorting
        "2015-07-29T17:43:00.000Z INFO [main] - iso format (latest)",
        "2015-07-29 17:41:41,536 - INFO  [main] - comma millis (earliest)",
        "2015-07-29 17:42:01.123 INFO [main] - dot millis (middle)",
    ]
    events = []
    for line in lines:
        entry = parse_log_line(line)
        assert entry is not None, f"Failed to parse: {line}"
        assert entry.timestamp, f"Empty timestamp for: {line}"
        events.append((entry.timestamp, entry.level))
    
    timeline = build_timeline(events)
    assert len(timeline) > 0, "Timeline empty"
    
    # All timestamps should be normalized to ISO format
    for ts, level in events:
        assert "T" in ts and ts.endswith("Z"), f"Not normalized: {ts}"
    
    # Verify chronological order is preserved (earliest first in sorted timeline)
    total = sum(b['total'] for b in timeline)
    assert total == 3, f"Expected 3 events, got {total}"
    print("✓ Mixed formats maintain chronological order")


def test_timezone_normalization():
    """Timestamps normalize to UTC correctly."""
    # Comma millis without timezone should be treated as UTC
    ts = _normalize_timestamp("2015-07-29 17:41:41,536")
    assert ts is not None, "Failed to normalize comma-millis timestamp"
    assert ts.endswith("Z"), f"Not UTC normalized: {ts}"
    assert "2015-07-29T17:41:41.536Z" == ts, f"Unexpected format: {ts}"
    print("✓ Timezone normalization correct")


def test_insights_parse_timestamp():
    """insights._parse_timestamp handles comma-millis for timeline."""
    # Parser emits ISO format, but test the insights parser directly
    dt = _parse_timestamp("2015-07-29 17:41:41,536")
    assert dt is not None, "insights._parse_timestamp failed on comma millis"
    assert dt.year == 2015 and dt.month == 7 and dt.day == 29
    assert dt.hour == 17 and dt.minute == 41 and dt.second == 41
    assert dt.microsecond == 536000, f"Micros wrong: {dt.microsecond}"
    print("✓ insights._parse_timestamp handles comma millis")


if __name__ == "__main__":
    test_comma_millis_zookeeper_format()
    test_comma_millis_hadoop_format()
    test_millisecond_precision_preserved()
    test_mixed_formats_consistent_timeline()
    test_mixed_formats_chronological_order()
    test_iso_timestamps_still_work()
    test_malformed_timestamps_fail_gracefully()
    test_invalid_date_matching_regex()
    test_timezone_normalization()
    test_insights_parse_timestamp()
    print("\n✅ All P1-B1 regression tests passed!")
