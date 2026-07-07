from stacksift.parser import parse_log_line


def test_parse_valid_log_line():
    line = "2026-07-07 09:17:44 ERROR Failed to connect to payment service"

    entry = parse_log_line(line)

    assert entry is not None
    assert entry.timestamp == "2026-07-07 09:17:44"
    assert entry.level == "ERROR"
    assert entry.message == "Failed to connect to payment service"


def test_parse_invalid_log_line():
    line = "This is not a valid log line"

    entry = parse_log_line(line)

    assert entry is None