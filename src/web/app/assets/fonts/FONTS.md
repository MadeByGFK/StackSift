# Vendored brand fonts — provenance (issue #160, amendment A1 P3-6)

These files are pinned: the build never downloads fonts at runtime, and
`pdf_export.py` resolves them relative to its own module, never the CWD.
Each file's SHA-256 is recorded here and asserted by
`tests/test_issue160_designed_reports.py`; if a file changes, its hash
here must change in the same commit, with the new source noted.

All four files are the static instances served by Google Fonts
(fonts.gstatic.com) — DM Sans v17, IBM Plex Mono v20 — retrieved
2026-11-06. They are used unmodified.

| File | Family / style | Source (fonts.gstatic.com) | Bytes | SHA-256 |
|---|---|---|---|---|
| `DMSans-Regular.ttf` | DM Sans, Regular 400 | `https://fonts.gstatic.com/s/dmsans/v17/rP2tp2ywxg089UriI5-g4vlH9VoD8CmcqZG40F9JadbnoEwAopxhTg.ttf` | 48280 | `b0ae3e89a7d3ef2b1838bb4b1ceb0b17cc3435af061eee809d76aa623ff116e9` |
| `DMSans-Bold.ttf` | DM Sans, Bold 700 | `https://fonts.gstatic.com/s/dmsans/v17/rP2tp2ywxg089UriI5-g4vlH9VoD8CmcqZG40F9JadbnoEwARZthTg.ttf` | 48200 | `2a8e7f713ee79fbccdef3cef5c787aff47580299f7da60144961e7db2ec08211` |
| `DMSans-Italic.ttf` | DM Sans, Italic 400 (real italic face) | `https://fonts.gstatic.com/s/dmsans/v17/rP2rp2ywxg089UriCZaSExd86J3t9jz86Mvy4qCRAL19DksVat-JDW3z.ttf` | 51144 | `cb30796ef338a70498e301f2c333f00d4fc23bacfa267be09673fdac43356a96` |
| `IBMPlexMono-Regular.ttf` | IBM Plex Mono, Regular 400 | `https://fonts.gstatic.com/s/ibmplexmono/v20/-F63fjptAgt5VM-kVkqdyU8n5ig.ttf` | 128812 | `a7fdc993f9f0387caedba4e42521136fa97e4c0837ae6239bf0413ccf8af00c2` |

## Licenses (each family's own notice, retained alongside the fonts)

- DM Sans: `OFL-DMSans.txt` — Copyright 2014 The DM Sans Project
  Authors; SIL Open Font License 1.1.
- IBM Plex Mono: `OFL-IBMPlexMono.txt` — Copyright © 2017 IBM Corp.
  with Reserved Font Name "Plex"; SIL Open Font License 1.1.

## Glyph coverage (probed on these exact binaries, 2026-11-06)

- DM Sans (all three faces, 403 glyphs each): Latin + Latin Extended
  (accented letters, combining marks), common punctuation (—, ‘ ’ “ ”,
  •, …), → and ×. NOT covered: Greek, Cyrillic, CJK, emoji, ✓.
- IBM Plex Mono (930 glyphs): everything DM Sans covers, plus Cyrillic
  and ✓. NOT covered: Greek, CJK, emoji.

Characters outside the rendering font's coverage are never silently
dropped or replaced: the PDF design layer substitutes the explicit
visible token `[unsupported character U+XXXX]` (amendment A1 P1-1).
