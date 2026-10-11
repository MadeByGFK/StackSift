from stacksift.parser import parse_log_line


def test_parse_valid_log_line():
    line = "2026-07-07 09:17:44 ERROR Failed to connect to payment service"

    entry = parse_log_line(line)

    assert entry is not None
    assert entry.timestamp == "2026-07-07T09:17:44.000Z"
    assert entry.level == "ERROR"
    assert entry.message == "Failed to connect to payment service"


def test_parse_invalid_log_line():
    # Unstructured lines are no longer "invalid" — they're UNKNOWN notes.
    line = "This is not a valid log line"

    entry = parse_log_line(line)

    assert entry is not None
    assert entry.level == "UNKNOWN"
    assert entry.timestamp == ""


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


def test_parse_json_format():
    line = '{"timestamp":"2026-10-11T12:00:00.000Z","level":"ERROR","service":"api-gateway","event":"request_failed","message":"Checkout failed"}'
    entry = parse_log_line(line)
    assert entry is not None
    assert entry.timestamp == "2026-10-11T12:00:00.000Z"
    assert entry.level == "ERROR"
    assert entry.service == "api-gateway"
    assert "event=request_failed" in entry.message


def test_parse_python_format():
    line = "2026-10-11 12:00:00,432 - order_service - INFO - Order done | service=order-service event=order_done"
    entry = parse_log_line(line)
    assert entry is not None
    assert entry.timestamp == "2026-10-11T12:00:00.432Z"
    assert entry.level == "INFO"
    assert entry.service == "order-service"


def test_parse_logfmt_format():
    line = 'time=2026-10-11T12:00:00.648Z level=WARN service=payment-service event=slow_op msg="slow"'
    entry = parse_log_line(line)
    assert entry is not None
    assert entry.timestamp == "2026-10-11T12:00:00.648Z"
    assert entry.level == "WARN"
    assert entry.service == "payment-service"


def test_parse_java_format():
    line = "2026-10-11 12:00:01.512 INFO com.example.OrderService - Done | service=order-service event=done"
    entry = parse_log_line(line)
    assert entry is not None
    assert entry.timestamp == "2026-10-11T12:00:01.512Z"
    assert entry.level == "INFO"


def test_parse_python_warning_maps_to_warn():
    line = "2026-10-11 12:00:00,432 - svc - WARNING - something | service=svc"
    entry = parse_log_line(line)
    assert entry.level == "WARN"


def test_parse_java_fatal_maps_to_critical():
    line = "2026-10-11 12:00:01.512 FATAL com.example.Svc - boom | service=svc"
    entry = parse_log_line(line)
    assert entry.level == "CRITICAL"


def test_parse_timezone_normalization():
    # +02:00 offset normalizes to UTC.
    line = '{"timestamp":"2026-10-11T14:00:01.728+02:00","level":"INFO","service":"s","event":"e"}'
    entry = parse_log_line(line)
    assert entry.timestamp == "2026-10-11T12:00:01.728Z"


def test_parse_unstructured_no_timestamp():
    line = "Maintenance note: retry policy unchanged. service=operations-console"
    entry = parse_log_line(line)
    assert entry.level == "UNKNOWN"
    assert entry.timestamp == ""
    assert entry.service == "operations-console"


def test_parse_timestamped_note_no_level():
    line = "2026-10-11T12:00:03.240Z Inventory report copied. service=operations-console"
    entry = parse_log_line(line)
    assert entry.level == "UNKNOWN"
    assert entry.timestamp == "2026-10-11T12:00:03.240Z"
