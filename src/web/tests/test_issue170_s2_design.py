"""Issue #170 S2: Analyze-surface design-alignment port.

Spec v1 Decision 4/5 + the Analyze port plan, as amended by spec v2
amendments A2 ("50 MB free" rejected outright; no price text on the
entry cards — Compare/Batch dollars are #164 Phase B, not landed),
A7 (surface-scoped styles + nonported-surface check) and A8 (teeth
discipline).

Mapping built here (presentation only):
  index.html   <- remake index composition: eyebrow + h1 + sub hero,
                  drop zone restyled, NEW Compare/Batch entry cards
                  under the form linking to the existing /compare
                  and /batch routes, the five live info cards (the
                  Privacy notice + the four .card panels) retained
                  with copy byte-identical and restyled as panels,
                  small-print / privacy-note rows in live copy only.
                  The staged multi-file list is NOT ported
                  (Decision 5 — that is Batch's one job).
  compare.html / batch.html <- shared panel styling only (their
                  <section> gains .s2-panel); no structural, form,
                  route, or flow change.
  Header/nav   <- verified against Decision 4: S1 shipped no header
                  change on staging and the "Pricing" label is staged
                  to S5 (Decision 11), so the header is left exactly
                  as the base ships it (canonical lowercase
                  stacksift. + gold period, mobile toggle +
                  nav_script behaviour preserved).

Teeth discipline (A8): tests asserting the NEW structure (eyebrow,
entry cards, .s2- CSS block, panel opt-in on compare/batch) FAIL on
the base tree (9ef2897f) for structural reasons and pass on the built
tree. Tests pinning pre-existing behaviour verbatim (form/field/JS
parity, info-card copy, no-"50 MB"/no-price exclusions, header/nav,
no-charging) are regression gates — they pass on both trees and are
labelled as such; a gate is not teeth.
"""

import re
from pathlib import Path

from app import auth
from app.main import templates
from app.models import Consent, CreditLedger, Operation, User

APP = Path(__file__).resolve().parents[1] / "app"
CSS = (APP / "static" / "style.css").read_text()
INDEX = (APP / "templates" / "index.html").read_text()
COMPARE = (APP / "templates" / "compare.html").read_text()
BATCH = (APP / "templates" / "batch.html").read_text()


def _render_index(**overrides):
    ctx = {"current_user": None, "csrf_token": "csrf-test",
           "remaining": 7, "error": None, "buy_credits": False}
    ctx.update(overrides)
    return templates.env.get_template("index.html").render(**ctx)


def _render(name, **ctx):
    base = {"current_user": None, "csrf_token": "csrf-test",
            "error": None, "buy_credits": False}
    base.update(ctx)
    return templates.env.get_template(name).render(**base)


# --- New Analyze structure (TEETH) ------------------------------------------


def test_s2_hero_eyebrow_and_dropzone_composition():
    html = _render_index()
    assert '<section class="hero s2-hero">' in html
    assert '<p class="s2-eyebrow">Analyze</p>' in html
    # PREMISE CHANGED (fidelity S2-G1, founder ruling 2026-11-10):
    # the design hero copy replaces the retained live copy verbatim.
    assert html.index('class="s2-eyebrow"') < html.index(
        "<h1>Analyze a log file</h1>")
    assert "<h1>Analyze a log file</h1>" in html
    assert "Drop in a log file and get a severity-ranked incident " \
        "summary — what failed first, what it affected, and what " \
        "to check next." in html
    assert '<label class="dropzone s2-dropzone" id="dropzone"' in html


def test_s2_entry_cards_link_existing_routes_without_price_text():
    html = _render_index()
    # Cards sit under the single-file form.
    assert html.index('id="upload-form"') < html.index(
        'data-s2-entry="compare"')
    assert html.index('data-s2-entry="compare"') < html.index(
        'data-s2-entry="batch"')
    assert '<a class="s2-entry-card" href="/compare"' in html
    assert '<a class="s2-entry-card" href="/batch"' in html
    seg = html[html.index('class="s2-entry-grid"'):]
    seg = seg[:seg.index("privacy-notice")]
    assert "Compare two logs" in seg and "Batch analysis" in seg
    # A2 / Decision 5 gate-in-teeth: no price text, no dollar amounts,
    # no staged multi-file list on the Analyze surface.
    assert "$" not in seg
    assert "staged" not in seg.lower()
    # Codex round-1 remediation (PR #176): pin the COMPLETE approved
    # card copy, so a price/size/retention claim cannot be appended
    # without failing here (the $ / staged checks alone let e.g.
    # "Costs 3 credits; up to 100 MB; retained for 30 days." pass).
    card_text = re.findall(
        r'<span class="s2-entry-(?:title|sub|link)">([^<]+)</span>', seg)
    assert card_text == [
        "Compare two logs",
        "Upload a before and an after log and see what changed "
        "between them.",
        "Compare logs →",
        "Batch analysis",
        "Upload 2 to 5 log files and get one combined report, in "
        "upload order.",
        "Start a batch →",
    ], card_text
    assert not re.search(
        r"credit|\$|\bMB\b|\bGB\b|retained|retention|\bcosts?\b|"
        r"\bprice|\bfree\b", seg, re.IGNORECASE), seg
    assert 'data-s2-entry="compare"' in html
    assert html.count('type="file"') == 1  # single-file form only


def test_s2_info_cards_restyled_as_panels():
    html = _render_index()
    assert '<div class="info-grid s2-panels">' in html
    assert html.count('class="card s2-panel"') == 4
    assert '<div class="privacy-notice s2-panel">' in html


def test_s2_css_block_is_analyze_scoped():
    """A7 teeth: the S2 block exists in style.css and every selector
    in it is .s2- scoped (no shared selector is restyled)."""
    marker = "Issue #170 S2"
    assert marker in CSS
    # Bounded slice: the S2 block sits before the S4 block in
    # style.css (so the S4 test's own marker-to-EOF slice stays
    # purely S4); this slice ends at the next slice's marker.
    block = CSS[CSS.index(marker):CSS.index("Issue #170 S4")]
    # The marker sits inside the block's header comment: drop that
    # comment's tail, then strip any remaining comments, so comment
    # text (which contains commas) cannot satisfy or break a
    # selector check.
    block = block.split("*/", 1)[1]
    block = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
    selectors = re.findall(r"([^{}]+)\{", block)
    assert selectors, "no rules in the S2 block"
    for group in selectors:
        if group.strip().startswith("@media"):
            continue  # the media wrapper; its inner rule is checked too
        # Codex round-1 remediation (PR #176): validate EACH selector
        # in a comma list independently, against the actual .s2-
        # class prefix — a list like ".s2-entry-card:hover, body"
        # must fail, not pass on the strength of its first member.
        for sel in group.split(","):
            sel = sel.strip()
            assert re.search(r"\.s2-", sel), \
                f"unscoped selector in S2 block: {sel!r}"
    assert ".s2-entry-card" in block and ".s2-panel" in block
    assert "var(--accent)" in block and "var(--panel)" in block


def test_s2_compare_batch_panels_only():
    """Teeth for the opt-in + gates for parity: compare/batch gain
    the shared panel class and nothing else changes."""
    for src, name in ((COMPARE, "compare.html"), (BATCH, "batch.html")):
        assert '<section class="s2-panel">' in src, name
    chtml = _render("compare.html")
    assert '<section class="s2-panel">' in chtml
    assert 'action="/compare"' in chtml
    assert 'name="file_a"' in chtml and 'name="file_b"' in chtml
    assert 'accept=".log,.txt,.text"' in chtml
    bhtml = _render("batch.html")
    assert '<section class="s2-panel">' in bhtml
    assert 'action="/batch"' in bhtml
    assert 'name="files"' in bhtml and "multiple" in bhtml
    assert 'name="csrf_token"' in bhtml


# --- Parity: form / fields / JS hooks / copy (regression gates) -------------


def test_s2_form_fields_and_js_hooks_verbatim():
    html = _render_index()
    assert 'id="upload-form" action="/analyze" method="post"' in html
    assert 'enctype="multipart/form-data"' in html
    assert 'name="request_id"' in html
    assert '<input type="file" id="file-input" name="file" ' \
           'accept=".log,.txt,.text" class="visually-hidden">' in html
    assert 'name="output" value="html"' in html
    assert 'name="output" value="txt"' in html
    assert 'id="loading"' in html and 'id="filename"' in html
    # Drop / drag JS hooks byte-identical in behaviour.
    for hook in ("getElementById('dropzone')", "getElementById('file-input')",
                 "getElementById('filename')", "'dragenter','dragover'",
                 "dz.classList.add('dragover')",
                 "fi.files = ev.dataTransfer.files"):
        assert hook in html, hook
    assert "form.dataset.submitting" in html  # duplicate-submit guard


def test_s2_script_blocks_byte_identical_to_base():
    """Codex round-1 remediation (PR #176): hook-presence checks
    cannot establish script parity (deleting e.preventDefault();
    return; from the duplicate-submit guard passed them all). Pin
    the complete inline script blocks of index.html by digest. The
    digest is identical on the base tree (9ef2897f) and the built
    tree — S2 touched no script — so this is a regression gate: any
    future edit to either block fails it."""
    import hashlib
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", INDEX, re.S)
    assert len(blocks) == 2
    digest = hashlib.sha256("\n".join(blocks).encode()).hexdigest()
    assert digest == \
        "b8ae7de2f265ce3bf9d5ae715982166cbb57c63de308966b315e799353d35260"
    assert "e.preventDefault();" in blocks[0]  # duplicate-submit guard


def test_s2_live_copy_verbatim_and_rejected_framings_absent():
    """Decision 5/9 + A2 gates: every live copy string on the surface
    survives byte-identical; the remake's rejected framings never
    appear in any form."""
    html = _render_index()
    for copy in (
        "Drag &amp; drop your log file here",
        "or click to browse — .log or .txt, up to 10 MB",
        "Signed in? Larger files (up to 100 MB / 500,000 lines) "
        "run with 3 credits.",
        "Analyze my logs", "Download .txt report",
        "No log handy?", "Try with sample logs →",
        "See a sample Investigation Report →",
        "of 10 analyses left this hour · No signup needed · "
        "Temporary processing",
        "Uploads may be temporarily written to disk before redaction",
        "Redaction may miss sensitive data. Review your log before "
        "uploading.",
        "Supported formats", "Private by design",
        "Recognized secret patterns are <strong>redacted</strong> "
        "before analysis; other sensitive data may appear in reports.",
        "Analysis reports are <strong>stored for 7 days</strong>",
        "What you get", "Built by someone on-call",
        "It's the first five minutes of an incident, automated.",
    ):
        assert copy in html, copy
    for bad in ("50 MB", "50MB", "Large-file analysis —",
                ".json up to", "Analyze free"):
        assert bad not in html, bad
    # Dollar amounts: checked on index.html's own markup — the shared
    # auth_form_script include legitimately carries the interim
    # MODAL_PACKS $5/$10/$25 catalog (live purchase copy, Decision
    # 11's inventory excludes it from the dollar-gated elements).
    for bad in ("$5", "$9", "$"):
        assert bad not in INDEX, bad


def test_s2_header_nav_unchanged_from_base():
    """Decision 4 gate: canonical lockup, mobile toggle + nav_script
    preserved and no header markup was redone.

    PREMISE CHANGED (#170 S5a, founder ruling 2026-11-11 splitting
    S5; Decisions 4/11 staged the label to S5): the signed-out nav
    label is now "Pricing" — the /credits href is unchanged. The
    original S2-era assertions (Credits label present, no Pricing
    anywhere) pinned the pre-S5 staging, not a permanent rule."""
    html = _render_index()
    assert '<a href="/" class="logo">stacksift<span>.</span></a>' in html
    assert 'class="nav-toggle"' in html
    assert 'aria-controls="site-nav"' in html
    assert 'id="site-nav"' in html
    assert "nav_script.html" in INDEX  # include preserved in source
    assert '<a href="/credits">Pricing</a>' in html
    assert '<a href="/credits">Credits</a>' not in html


# --- Live route: structure (teeth) + no-charging (gate) ---------------------


def _login_user(env, email="owner@example.com"):
    with env.sessions() as db:
        user = User(email=email, email_verified=True,
                    password_hash=auth.hash_password("Str0ng!Passw0rd"))
        db.add(user)
        db.commit()
        session, raw = auth.create_session(db, user.id)
        csrf = session.csrf_token
    env.client.cookies.set(auth.SESSION_COOKIE, raw,
                           domain="testserver.local", path="/")
    env.client.headers["X-CSRF-Token"] = csrf
    return csrf


def _row_counts(env):
    with env.sessions() as db:
        return (db.query(Operation).count(),
                db.query(Consent).count(),
                db.query(CreditLedger).count())


def test_s2_live_home_entry_cards_and_no_charging_rows(auth_env):
    _login_user(auth_env)
    before = _row_counts(auth_env)
    page = auth_env.client.get("/")
    assert page.status_code == 200
    # Teeth on the live route: the new composition renders.
    for marker in ('class="s2-eyebrow"', 'data-s2-entry="compare"',
                   'data-s2-entry="batch"', 'class="card s2-panel"'):
        assert marker in page.text, marker
    # Compare/Batch panel opt-in is asserted by direct template
    # render in test_s2_compare_batch_panels_only: their GET routes
    # are login-gated through the app's own SessionLocal (a different
    # database from the auth_env fixture), so the bare fixture cannot
    # serve them — the same fixture limitation S4 recorded for
    # /sample-report.
    # Gate: rendering this surface creates no charging rows
    # (Decision 12).
    auth_env.client.get("/")
    assert _row_counts(auth_env) == before


def test_s2_nonported_surfaces_carry_no_s2_markup(auth_env):
    """A7 nonported-surface check: My Reports, Pricing (/credits),
    Login, Settings and the sample render with no s2 markup outside
    the intended Analyze/Compare/Batch surfaces, and the canonical
    logo + nav-toggle stay intact on each."""
    _login_user(auth_env)
    for path in ("/reports", "/credits", "/login", "/settings"):
        page = auth_env.client.get(path)
        assert page.status_code == 200, (path, page.status_code)
        assert "s2-" not in page.text, path
        assert '<a href="/" class="logo">stacksift<span>.</span></a>' \
            in page.text, path
        assert 'class="nav-toggle"' in page.text, path
    # The intended surfaces DO carry it (control: the check above is
    # not vacuous).
    home = auth_env.client.get("/")
    assert "s2-entry-card" in home.text


def test_s2_sample_template_carries_no_s2_markup():
    """A7: the sample (deep_dive_report.html, is_sample) is a
    nonported surface for S2 — it renders with no S2 markup and
    keeps its SAMPLE labelling."""
    from app import deep_dive as dd
    from test_issue162_brief import _sample_artifact
    projection = dd.public_projection(_sample_artifact())
    html = templates.env.get_template("deep_dive_report.html").render(
        analysis_projection=projection, filename="sample.log",
        is_sample=True,
        branding={"business_name": "WellInstance",
                  "client_name": None, "report_title": None,
                  "accent": None, "logo_url": None})
    assert "s2-" not in html
    assert "SAMPLE" in html
