"""OpenStack compatibility regressions; run from the repository root."""
import sys
import unittest

sys.path.insert(0, "src/web")

from app.vendor.parser import parse_log_line
from app.vendor.insights import build_timeline
from app.service import analyze_upload


class OpenStackTests(unittest.TestCase):
    prefix = "nova-api.log.2017-05-14_21:27:04 "
    body = ('2017-05-14 19:39:01.445 25746 INFO '
            'nova.osapi_compute.wsgi.server [req-example user project] '
            '10.11.10.1 "GET /v2" status: 200')

    def test_prefixed_entry_uses_event_time(self):
        entry = parse_log_line(self.prefix + self.body)
        self.assertEqual(entry.timestamp, "2017-05-14T19:39:01.445Z")
        self.assertEqual(entry.level, "INFO")
        self.assertEqual(entry.service, "nova.osapi_compute.wsgi.server")

    def test_unprefixed_entry_and_request_context(self):
        entry = parse_log_line(self.body)
        self.assertEqual(entry, parse_log_line(self.prefix + self.body))
        self.assertEqual(entry.message,
                         '[req-example user project] 10.11.10.1 "GET /v2" status: 200')

    def test_filename_variants(self):
        for prefix in ("nova-compute.log ", "/logs/nova-api.log.2017-05-14_21:27:04 "):
            with self.subTest(prefix=prefix):
                self.assertEqual(parse_log_line(prefix + self.body), parse_log_line(self.body))

    def test_levels_and_aliases(self):
        for raw, expected in (("ERROR", "ERROR"), ("WARN", "WARN"),
                              ("WARNING", "WARN"), ("DEBUG", "INFO"),
                              ("CRITICAL", "CRITICAL"), ("FATAL", "CRITICAL")):
            with self.subTest(level=raw):
                entry = parse_log_line(self.prefix + self.body.replace(" INFO ", f" {raw} "))
                self.assertEqual(entry.level, expected)
                self.assertTrue(entry.timestamp)

    def test_spacing_no_request_context_and_service_override(self):
        entry = parse_log_line("2017-05-14 19:39:01.445\t123  ERROR  nova.compute "
                               "failed | service=compute reason=timeout")
        self.assertEqual(entry.level, "ERROR")
        self.assertEqual(entry.service, "compute")
        self.assertEqual(entry.message, "failed | service=compute reason=timeout")

    def test_invalid_date_has_no_timeline(self):
        entry = parse_log_line(self.prefix + self.body.replace("2017-05-14", "2017-13-45"))
        self.assertEqual(entry.timestamp, "")
        self.assertEqual(entry.level, "INFO")
        self.assertEqual(build_timeline([(entry.timestamp, entry.level)]), [])

    def test_near_misses_remain_unstructured(self):
        for line in (self.prefix + self.body.replace("25746", "pid"),
                     self.prefix + self.body.replace(" INFO ", " MADEUP "),
                     "arbitrary-prefix " + self.body,
                     "Traceback (most recent call last):"):
            with self.subTest(line=line):
                entry = parse_log_line(line)
                self.assertEqual((entry.timestamp, entry.level), ("", "UNKNOWN"))
                self.assertEqual(entry.message, line)

    def test_mixed_timeline_order_and_counts(self):
        lines = [self.prefix + self.body.replace("19:39:01.445", "19:51:01.445"),
                 "2017-05-14T19:41:00.000Z ERROR earlier",
                 "2017-05-14 19:47:00,123 - INFO [main] - middle"]
        entries = [parse_log_line(line) for line in lines]
        buckets = build_timeline([(e.timestamp, e.level) for e in entries])
        self.assertEqual([b["label"] for b in buckets], ["19:40", "19:45", "19:50"])
        self.assertEqual([b["total"] for b in buckets], [1, 1, 1])

    def test_upload_populates_timestamps_and_severity(self):
        lines = [self.prefix + self.body,
                 self.prefix + self.body.replace(" INFO ", " ERROR "),
                 self.prefix + self.body.replace(" INFO ", " WARNING ")]
        result = analyze_upload("openstack.log", "\n".join(lines).encode())
        self.assertNotIn("error", result)
        self.assertEqual(result["results"]["parsed_lines"], 3)
        self.assertTrue(all(ts for ts, _ in result["results"]["events"]))
        self.assertEqual(result["results"]["level_counts"]["ERROR"], 1)
        self.assertEqual(result["results"]["level_counts"]["WARN"], 1)
        self.assertEqual(sum(b["total"] for b in result["timeline"]), 3)
        self.assertNotEqual(result["health"]["label"], "Timestamps Not Recognized")


if __name__ == "__main__":
    unittest.main()
