"""Issue #170 S5a: Pricing renames (founder ruling 2026-11-11, split S5).

Scope built here (spec: s5-pricing-spec-2026-11-11.md, items 8-9):
  - pricing.html FAQ heading "What does the Analysis Report
    include?" -> "What does the Investigation Report include?" and
    its body lead "The Analysis Report (Investigation Report)
    adds..." -> "The Investigation Report adds..." (naming ruling
    2026-11-09; the rest of the FAQ entry is byte-unchanged).
  - pricing.html <title> "StackSift — Credits" -> "Pricing |
    stacksift." (design format). The meta description stays
    credits-accurate — the design's dollar meta copy is gated to
    S5-full / #164 Phase C.
  - Signed-out header nav label "Credits" -> "Pricing" on every
    template carrying it; the href stays "/credits" everywhere
    (route rename is #164 Phase C scope).

NOT renamed (deliberate, pinned below): the Settings page's
"Credits" balance section (label + <h2>) and the Terms page's
"Credits" legal section heading + body-copy link — those name the
credit product itself, not the nav label, and the Settings section
label is already pinned by test_issue170_s4_design.py. reset.html
carries the nav label but was omitted from the spec's list; grep on
the base tree shows it, so it is flipped and pinned here.

Commerce is untouched: checkout banners, the balance strip + its
settlement polling script (#71), the pack buy forms, and the #156
offer_viewed script are asserted present and unchanged in shape.

PREMISE CHANGED (#164 Phase C, 2026-11-13): S5-full has landed —
the meta is dollar copy, the commerce regions are the dollar offer
cards (banners/balance strip/pack forms/signup-grant CTA retired),
Settings §02 is Purchases, and the Terms section is "Pricing and
purchases". The affected tests below are re-based accordingly,
with absence assertions at the same strength as the old presence
assertions.

No stateful control changes in this slice, so the standing
runtime-interaction-sequence requirement does not apply.

Teeth: the rename pins FAIL on the base tree (a646acc7) and pass
here; the commerce-unchanged pins pass on both trees (gates).
"""

from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
TEMPLATES = APP / "templates"

PRICING = (TEMPLATES / "pricing.html").read_text()

# Every template whose signed-out header carries the nav label
# (verified by grep on the base tree, 2026-11-11).
NAV_TEMPLATES = [
    "deep_dive_report.html", "forgot.html", "index.html",
    "login.html", "oauth_error.html", "pricing.html",
    "privacy.html", "report.html", "reports.html", "reset.html",
    "settings.html", "signup.html", "support.html", "terms.html",
    "verify.html",
]

OLD_NAV = '<a href="/credits">Credits</a>'
NEW_NAV = '<a href="/credits">Pricing</a>'


# --- FAQ rename (item 8) -------------------------------------------------

def test_s5a_faq_heading_renamed():
    assert "<h3>What does the Investigation Report include?</h3>" in PRICING
    assert "What does the Analysis Report include?" not in PRICING


def test_s5a_faq_lead_renamed_rest_of_entry_unchanged():
    assert "<p>The Investigation Report adds an Investigation Brief" in PRICING
    assert "The Analysis Report (Investigation Report) adds" not in PRICING
    # The remainder of the entry (price, terms, sample link) is the
    # founder-approved #164A copy and must survive verbatim.
    for kept in (
        "It costs $9 per report, paid by card at checkout.",
        "Exports (PDF, CSV, JSON) are included free, branding is "
        "included, and the report is kept for 90 days.",
        "disputes@goodfolkdigital.com",
        '<a href="/sample-report">See a sample Investigation Report →</a>',
    ):
        assert kept in PRICING, kept


# --- Pricing page title (item 9) ------------------------------------------

def test_s5a_pricing_title_uses_design_format():
    assert "<title>Pricing | stacksift.</title>" in PRICING
    assert "<title>StackSift — Credits</title>" not in PRICING


def test_s5a_meta_description_is_dollar_accurate():
    # PREMISE CHANGED (#164 Phase C, Decision 8): S5-full has landed
    # — the meta describes the dollar model truthfully, with the
    # four ruled prices and the free-exports policy.
    assert ('<meta name="description" content="StackSift pricing: '
            'free log analysis for everyone, and per-report dollar '
            'prices — Investigation Report $9, Compare $5, Batch $5, '
            'Large-File Analysis $5. Exports are free for all '
            'reports.">') in PRICING
    assert "StackSift credits:" not in PRICING
    assert "premium capabilities with credits" not in PRICING


# --- Nav label sweep (item 9) ----------------------------------------------

def test_s5a_nav_label_is_pricing_on_every_header_template():
    for name in NAV_TEMPLATES:
        html = (TEMPLATES / name).read_text()
        assert NEW_NAV in html, name
        assert 'href="/credits"' in html, name  # route unchanged


def test_s5a_no_nav_anchor_still_labelled_credits():
    # PREMISE CHANGED (#164 Phase C, Decision 10 copy sweep): even
    # the terms.html body-copy /credits anchor is labelled Pricing
    # now ("See Pricing for the per-report prices") — NO /credits
    # anchor anywhere is labelled Credits.
    for name in NAV_TEMPLATES:
        html = (TEMPLATES / name).read_text()
        assert OLD_NAV not in html, name
        assert NEW_NAV in html, name


def test_s5a_non_nav_names_now_dollar_era():
    # PREMISE CHANGED (#164 Phase C, Decisions 9-10): the names that
    # S5a deliberately left alone are renamed by Phase C — Settings
    # §02 is Purchases / "Purchase history", and the Terms legal
    # section is "Pricing and purchases".
    settings = (TEMPLATES / "settings.html").read_text()
    assert '<span class="s4-section-label">Purchases</span>' in settings
    assert "<h2>Purchase history</h2>" in settings
    assert '<span class="s4-section-label">Credits</span>' not in settings
    assert "<h2>Credits</h2>" not in settings
    terms = (TEMPLATES / "terms.html").read_text()
    assert "<h2>Pricing and purchases</h2>" in terms
    assert "<h2>Credits</h2>" not in terms


# --- Commerce regions unchanged (gates, pass on both trees) -----------------

def test_s5a_commerce_regions_now_dollar_offers_in_pricing_source():
    # PREMISE CHANGED (#164 Phase C, Decisions 1/8 + C6b/c): the
    # commerce regions are the dollar offer cards — no return
    # banners, no balance strip/poll, no pack buy forms, no
    # signup-grant CTA. The #156 beacon survives, retargeted.
    for marker in (
        # Dollar offer cards (the four ruled SKUs render here).
        'id="offers"',
        "offer-card",
        "Payment is captured at checkout",
        # #156 offer-visibility beacon script, retargeted (C6b).
        "offer_viewed",
        'querySelectorAll(".offer-card")',
    ):
        assert marker in PRICING, marker
    for retired in (
        # Checkout return banners (success / cancelled) — C6c.
        "checkout-banner",
        "Payment didn't go through — no charge was made",
        # Balance strip + settlement polling script (#71).
        "balance-strip",
        'id="credit-balance"',
        'fetch("/credits/balance"',
        # Pack buy forms / pack grid.
        '<form method="post" action="/credits/checkout"',
        'name="pack_id"',
        'id="packs"',
        # Signup-grant CTA copy.
        "10 free credits",
    ):
        assert retired not in PRICING, retired


# --- Live routes -------------------------------------------------------------

def test_s5a_rendered_credits_page_carries_new_names(auth_env):
    page = auth_env.client.get("/credits")
    assert page.status_code == 200
    assert "<title>Pricing | stacksift.</title>" in page.text
    assert NEW_NAV in page.text
    assert OLD_NAV not in page.text
    assert "What does the Investigation Report include?" in page.text
    assert "What does the Analysis Report include?" not in page.text


def test_s5a_rendered_home_nav_label_and_route_unchanged(auth_env):
    page = auth_env.client.get("/")
    assert page.status_code == 200
    assert NEW_NAV in page.text
    assert OLD_NAV not in page.text
    redir = auth_env.client.get("/pricing", follow_redirects=False)
    assert redir.status_code == 301
    assert redir.headers["location"] == "/credits"
