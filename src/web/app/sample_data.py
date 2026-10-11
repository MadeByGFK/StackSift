"""Canned sample log for the /demo route.

A realistic checkout-api incident: normal traffic, rising latency, database
timeouts, a critical payment-upstream outage, then recovery. Includes a fake
Stripe test key to demonstrate secret redaction in the report.
"""

SAMPLE_FILENAME = "sample-incident.log"

SAMPLE_LOG = """\
2026-10-11 08:00:01 INFO checkout-api starting up (v2.4.1)
2026-10-11 08:00:02 INFO loaded config (api_key=demo_7f3a9c2e8b1d4f6a5c3e)
2026-10-11 08:00:03 INFO connected to postgres primary (10.0.4.21:5432)
2026-10-11 08:00:05 INFO listening on :8080
2026-10-11 08:04:12 INFO order #88412 completed in 212ms
2026-10-11 08:09:47 INFO order #88419 completed in 188ms
2026-10-11 08:14:03 INFO order #88423 completed in 240ms
2026-10-11 08:19:55 INFO order #88431 completed in 201ms
2026-10-11 08:24:36 INFO order #88438 completed in 225ms
2026-10-11 08:29:11 INFO order #88444 completed in 233ms
2026-10-11 08:31:07 WARN request latency p99 above 2000ms (10.0.4.21)
2026-10-11 08:31:52 WARN connection pool exhausted, waiting for slot
2026-10-11 08:32:15 ERROR Database connection timeout after 5000ms
2026-10-11 08:32:18 ERROR Database connection timeout after 5000ms
2026-10-11 08:32:24 ERROR Database connection timeout after 5000ms
2026-10-11 08:32:31 ERROR Database connection timeout after 5000ms
2026-10-11 08:32:40 WARN retrying with backoff (attempt 2/5)
2026-10-11 08:33:02 ERROR Database connection timeout after 5000ms
2026-10-11 08:33:19 ERROR Database connection timeout after 5000ms
2026-10-11 08:33:44 INFO order #88451 completed in 1980ms
2026-10-11 08:34:10 ERROR order #88452 failed: payment upstream unavailable
2026-10-11 08:34:15 ERROR order #88453 failed: payment upstream unavailable
2026-10-11 08:34:22 ERROR order #88455 failed: payment upstream unavailable
2026-10-11 08:35:44 CRITICAL payment upstream unavailable - circuit breaker open
2026-10-11 08:35:47 ERROR order #88457 failed: payment upstream unavailable
2026-10-11 08:36:02 ERROR order #88458 failed: payment upstream rejected api_key=demo_9b2e7a4c1f8d3e6a
2026-10-11 08:36:20 WARN queue depth 1,204 messages and growing
2026-10-11 08:37:11 ERROR order #88461 failed: payment upstream unavailable
2026-10-11 08:38:05 INFO failover initiated: promoting postgres replica
2026-10-11 08:39:52 INFO failover to postgres replica complete (10.0.4.22:5432)
2026-10-11 08:40:15 INFO payment upstream health check passing
2026-10-11 08:40:18 INFO circuit breaker half-open, probing
2026-10-11 08:41:19 INFO order #88467 completed in 340ms
2026-10-11 08:42:03 INFO order #88468 completed in 295ms
2026-10-11 08:42:47 INFO circuit breaker closed, traffic restored
2026-10-11 08:44:12 INFO order #88471 completed in 210ms
2026-10-11 08:49:30 INFO queue drained, depth 0
2026-10-11 08:55:01 INFO order #88479 completed in 205ms
"""
