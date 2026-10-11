"""Secret redaction for StackSift.

Scans log text for common secret formats (API keys, tokens, passwords,
private keys) and replaces them with [REDACTED] before analysis. This runs
on the raw text first, so redacted values never reach the analyzer, the
report, or any stored artifact.

Conservative by design: patterns target well-known secret formats and
explicitly labeled credentials. Unlabeled random strings are left alone to
avoid mangling legitimate log content.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# Each entry: (compiled pattern, replacement). Patterns with a "label" group
# keep the label (e.g. "api_key=[REDACTED]"); bare secrets are fully replaced.
_PATTERNS: list[tuple[re.Pattern, str]] = []


def _add(pattern: str, replacement: str, flags: int = 0) -> None:
    _PATTERNS.append((re.compile(pattern, flags), replacement))


# --- Well-known token formats (replaced wholesale) ---
_add(r"AKIA[0-9A-Z]{16}", REDACTED)                                  # AWS access key
_add(r"ghp_[A-Za-z0-9]{20,}", REDACTED)                               # GitHub personal token
_add(r"gho_[A-Za-z0-9]{20,}", REDACTED)                               # GitHub OAuth token
_add(r"github_pat_[A-Za-z0-9_]{20,}", REDACTED)                      # GitHub fine-grained PAT
_add(r"sk_(live|test)_[A-Za-z0-9]{16,}", REDACTED)                   # Stripe secret key
_add(r"rk_(live|test)_[A-Za-z0-9]{16,}", REDACTED)                   # Stripe restricted key
_add(r"xox[baprs]-[A-Za-z0-9-]{10,}", REDACTED)                      # Slack token
_add(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
     REDACTED)                                                        # PEM private key block
_add(r"Bearer\s+[A-Za-z0-9\-._~+/=]{16,}", f"Bearer {REDACTED}")     # Bearer tokens

# --- Labeled credentials (label kept, value redacted) ---
# Matches: api_key=abc123, "password": "hunter2", auth-token: xyz ...
_LABELED = (
    r"(?P<label>(?:api[_-]?key|apikey|auth[_-]?token|access[_-]?token|"
    r"client[_-]?secret|aws[_-]?secret|secret[_-]?key|"
    r"password|passwd|pwd|db[_-]?password))"
    r"\s*[:=]\s*[\"']?(?P<secret>[^\"'\s,})]+)[\"']?"
)


def _labeled_repl(match: re.Match) -> str:
    return f"{match.group('label')}={REDACTED}"


_PATTERNS.append((re.compile(_LABELED, re.IGNORECASE), _labeled_repl))


def redact_secrets(text: str) -> str:
    """Return *text* with detected secrets replaced by [REDACTED]."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
