"""Unit tests for structured export serializers."""

import csv
import io
import json
import math

import pytest

from app.structured_export import StructuredExportError, payload_to_csv, payload_to_json


def _base_payload():
    return {
        "filename": "app.log",
        "results": {
            "issues": {
                "Error connecting to DB": {
                    "level": "ERROR",
                    "count": 3,
                    "services": ["api", "db"],
                    "first_seen": "2026-01-01T00:00:00Z",
                    "last_seen": "2026-01-01T00:05:00Z",
                },
                "Worker restarted": {
                    "level": "WARN",
                    "count": 1,
                    "services": [],
                    "first_seen": None,
                    "last_seen": None,
                },
            }
        },
        "sorted_issues": [
            ["Error connecting to DB", {"level": "ERROR", "count": 3}],
            ["Worker restarted", {"level": "WARN", "count": 1}],
        ],
    }


def test_payload_to_csv_exact_header_and_rows():
    payload = _base_payload()

    actual = payload_to_csv(payload)

    assert actual == (
        b"template,level,count,services,first_seen,last_seen\r\n"
        b'Error connecting to DB,ERROR,3,"[""api"",""db""]",2026-01-01T00:00:00Z,2026-01-01T00:05:00Z\r\n'
        b'Worker restarted,WARN,1,[],,\r\n'
    )


def test_payload_to_csv_services_missing_vs_empty_and_null_timestamps():
    payload = {
        "results": {
            "issues": {
                "missing services": {
                    "level": "INFO",
                    "count": 1,
                    "first_seen": None,
                    "last_seen": None,
                },
                "empty services": {
                    "level": "WARN",
                    "count": 2,
                    "services": [],
                    "first_seen": "2026-01-01",
                    "last_seen": None,
                },
            }
        },
        "sorted_issues": [
            ["missing services", {"level": "INFO", "count": 1}],
            ["empty services", {"level": "WARN", "count": 2}],
        ],
    }

    rows = list(csv.DictReader(io.StringIO(payload_to_csv(payload).decode("utf-8"))))

    assert rows[0]["services"] == ""
    assert rows[0]["first_seen"] == ""
    assert rows[0]["last_seen"] == ""
    assert rows[1]["services"] == "[]"
    assert rows[1]["first_seen"] == "2026-01-01"
    assert rows[1]["last_seen"] == ""


def test_payload_to_csv_template_special_characters_round_trip():
    template = 'Service "api", failed\n原因'
    payload = {
        "results": {
            "issues": {
                template: {
                    "level": "ERROR",
                    "count": 4,
                    "services": ["api"],
                    "first_seen": "a",
                    "last_seen": "b",
                }
            }
        },
        "sorted_issues": [[template, {"level": "ERROR", "count": 4}]],
    }

    rows = list(csv.DictReader(io.StringIO(payload_to_csv(payload).decode("utf-8"))))

    assert rows[0]["template"] == template


def test_payload_to_csv_zero_issues_header_only():
    payload = {"results": {"issues": {}}, "sorted_issues": []}

    actual = payload_to_csv(payload)

    assert actual == b"template,level,count,services,first_seen,last_seen\r\n"


def test_payload_to_csv_legacy_fallback_lexicographic_order():
    payload = {
        "results": {
            "issues": {
                "z-last": {"level": "WARN", "count": 1, "services": []},
                "a-first": {"level": "ERROR", "count": 2, "services": []},
            }
        }
    }

    rows = list(csv.DictReader(io.StringIO(payload_to_csv(payload).decode("utf-8"))))

    assert [r["template"] for r in rows] == ["a-first", "z-last"]


def test_payload_to_csv_raises_on_sorted_issue_contradiction():
    payload = {
        "results": {
            "issues": {
                "A": {"level": "ERROR", "count": 3, "services": []},
            }
        },
        "sorted_issues": [["A", {"level": "WARN", "count": 3}]],
    }

    with pytest.raises(StructuredExportError):
        payload_to_csv(payload)


def test_payload_to_csv_raises_on_sorted_issue_missing_template():
    payload = {
        "results": {"issues": {"A": {"level": "ERROR", "count": 3, "services": []}}},
        "sorted_issues": [],
    }

    with pytest.raises(StructuredExportError):
        payload_to_csv(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "results": {"issues": {"A": {"level": 1, "count": 2, "services": []}}},
            "sorted_issues": [["A", {"level": 1, "count": 2}]],
        },
        {
            "results": {"issues": {"A": {"level": "ERROR", "count": "2", "services": []}}},
            "sorted_issues": [["A", {"level": "ERROR", "count": "2"}]],
        },
        {
            "results": {"issues": {"A": {"level": "ERROR", "count": 2, "services": "api"}}},
            "sorted_issues": [["A", {"level": "ERROR", "count": 2}]],
        },
    ],
)
def test_payload_to_csv_raises_on_invalid_level_count_or_services(payload):
    with pytest.raises(StructuredExportError):
        payload_to_csv(payload)


def test_payload_to_json_round_trip_nested_payload():
    payload = {
        "filename": "日本語.log",
        "results": {
            "issues": {
                "α": {
                    "level": "INFO",
                    "count": 1,
                    "services": ["api"],
                    "first_seen": None,
                    "last_seen": "2026-01-01T00:00:00Z",
                }
            },
            "extra": {"nested": [1, {"ok": True}, "✓"]},
        },
        "sorted_issues": [["α", {"level": "INFO", "count": 1}]],
    }

    exported = payload_to_json(payload)

    assert exported.endswith(b"\n")
    assert json.loads(exported) == payload


def test_payload_to_json_rejects_nan():
    payload = {
        "results": {
            "issues": {
                "A": {
                    "level": "ERROR",
                    "count": 1,
                    "services": [],
                    "first_seen": None,
                    "last_seen": None,
                }
            },
            "metric": math.nan,
        },
        "sorted_issues": [["A", {"level": "ERROR", "count": 1}]],
    }

    with pytest.raises(StructuredExportError):
        payload_to_json(payload)
