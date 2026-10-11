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


def test_parse_iso_timestamp_with_service():
    line = "2026-10-10T14:08:08.258Z ERROR [edge-api] http_request method=POST status=500"

    entry = parse_log_line(line)

    assert entry is not None
    assert entry.timestamp == "2026-10-10T14:08:08.258Z"
    assert entry.level == "ERROR"
    assert entry.service == "edge-api"
    assert entry.message == "[edge-api] http_request method=POST status=500"


def test_parse_iso_timestamp_without_service():
    line = "2026-10-10T14:00:00Z INFO server started"

    entry = parse_log_line(line)

    assert entry is not None
    assert entry.level == "INFO"
    assert entry.service is None


def test_debug_folds_to_info():
    entry = parse_log_line("2026-10-10T14:00:00.000Z DEBUG [api] cache_lookup key=x")
    assert entry is not None
    assert entry.level == "INFO"


def test_fatal_folds_to_critical():
    entry = parse_log_line("2026-10-10 09:17:44 FATAL out of memory")
    assert entry is not None
    assert entry.level == "CRITICAL"
