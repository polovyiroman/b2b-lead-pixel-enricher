import json
import time
from typing import Callable

from .contacts import (
    extract_decision_maker_deep,
    is_valid_person_name,
    strip_role_tokens_from_name,
)
from .tech_detector import detect_tech_with_evidence


def _test_01_corporate_entities() -> str:
    """
    Test 1/6: Corporate entity rejection & valid person preservation.
    Verifies Benjamin Otto, Annette Siragusano, Petra Scharner-Wolff pass,
    while BPO Capital, GFH Gesellschaft, YOU Verwaltungs, Otto Group are rejected.
    """
    valid_people = [
        ('Benjamin Otto', 'ottogroup'),
        ('Annette Siragusano', 'ottogroup'),
        ('Petra Scharner-Wolff', 'ottogroup'),
        ('Gundula Koele-Pabst', 'docmorris'),
    ]
    for raw_name, brand in valid_people:
        cleaned = strip_role_tokens_from_name(raw_name)
        if not is_valid_person_name(cleaned, brand):
            raise AssertionError(f"Valid person '{raw_name}' (cleaned='{cleaned}') was rejected for brand '{brand}'")

    # Verify hyphenated double-surname strips trailing board list token ('Katy') generically
    katy_cleaned = strip_role_tokens_from_name('Petra Scharner-Wolff Katy')
    if katy_cleaned != 'Petra Scharner-Wolff':
        raise AssertionError(f"Expected 'Petra Scharner-Wolff', got '{katy_cleaned}'")

    invalid_entities = [
        ('BPO Capital', 'ottogroup'),
        ('GFH Gesellschaft', 'ottogroup'),
        ('YOU Verwaltungs', 'aboutyou'),
        ('Otto Group', 'ottogroup'),
        ('DocMorris AG', 'docmorris'),
    ]
    for raw_corp, brand in invalid_entities:
        cleaned = strip_role_tokens_from_name(raw_corp)
        if is_valid_person_name(cleaned, brand):
            raise AssertionError(f"Corporate entity '{raw_corp}' (cleaned='{cleaned}') falsely passed as person")

    return "PASS (4 valid executives preserved, 5 corporate entities rejected)"


def _test_02_determinism_ottogroup_3x() -> str:
    """
    Test 2/6: Deterministic Primary DM selection across 3 permutations of page fetch order.
    Verifies Benjamin Otto (+ LinkedIn URL) is always selected #1 and JSON output is identical.
    """
    page_impressum = (
        'https://www.ottogroup.com/de/impressum',
        '<html><body>'
        '<p>Vertreten durch den Vorstand: Petra Scharner-Wolff</p>'
        '<p>Annette Siragusano, President</p>'
        '<p>BPO Capital, CEO</p>'
        '<p>GFH Gesellschaft, CEO</p>'
        '</body></html>',
        'Vertreten durch den Vorstand: Petra Scharner-Wolff. Annette Siragusano, President. BPO Capital, CEO.'
    )
    page_about = (
        'https://www.ottogroup.com/de/ueber-uns',
        '<html><body>'
        '<h2>Management</h2>'
        '<p>Benjamin Otto — Managing Director / CEO</p>'
        '<a href="https://www.linkedin.com/in/benjamin-otto1">LinkedIn Profile</a>'
        '</body></html>',
        'Benjamin Otto — Managing Director / CEO'
    )
    page_news = (
        'https://www.ottogroup.com/de/newsroom',
        '<html><body><p>Annette Siragusano, President Corporate Communications</p></body></html>',
        'Annette Siragusano, President Corporate Communications'
    )

    permutations = [
        [page_impressum, page_about, page_news],
        [page_about, page_news, page_impressum],
        [page_news, page_impressum, page_about],
    ]

    results = [extract_decision_maker_deep(p) for p in permutations]
    baseline_name, _, baseline_li, _, _, _, baseline_found, baseline_json = results[0]

    if baseline_name != 'Benjamin Otto':
        raise AssertionError(f"Expected primary DM 'Benjamin Otto', got '{baseline_name}'")
    if baseline_li != 'https://www.linkedin.com/in/benjamin-otto1':
        raise AssertionError(f"Expected LinkedIn URL 'https://www.linkedin.com/in/benjamin-otto1', got '{baseline_li}'")
    if 'BPO Capital' in (baseline_found or '') or 'GFH Gesellschaft' in (baseline_found or ''):
        raise AssertionError(f"Corporate pollution found in decision_makers_found: {baseline_found}")

    for idx, res in enumerate(results[1:], start=2):
        if res[0] != baseline_name or res[2] != baseline_li or res[7] != baseline_json:
            raise AssertionError(f"Non-deterministic output on run #{idx}: {res[0]} vs {baseline_name}")

    return "PASS (3x page-order permutations -> identical Benjamin Otto + LinkedIn)"


def _test_03_cache_merge_completeness_and_empty_render(
    normalize_tech_fn: Callable[[dict], None],
    resolve_cache_comp_fn: Callable[[bool, bool, bool, bool, str], str],
) -> str:
    """
    Test 3/6: Cache merge completeness contract + empty render protection (Unicredit/Bol case).
    """
    # Case A: Cache has GA4=True, but live scan failed (pw_used=False) -> MUST be 'partial_cached' (never 'full')
    comp_comfy = resolve_cache_comp_fn(True, False, True, False, 'partial_blocked')
    if comp_comfy != 'partial_cached':
        raise AssertionError(f"Comfy case: expected 'partial_cached', got '{comp_comfy}'")

    # Case B: PW rendered shell (pw_used=True, no timeout), but live_found_something=False -> MUST be 'partial_cached'
    comp_liki = resolve_cache_comp_fn(True, True, False, False, 'full')
    if comp_liki != 'partial_cached':
        raise AssertionError(f"Liki24 cache-only case: expected 'partial_cached', got '{comp_liki}'")

    # Case C: PW rendered clean AND live_found_something=True -> 'full'
    comp_clean = resolve_cache_comp_fn(True, True, False, True, 'full')
    if comp_clean != 'full':
        raise AssertionError(f"Clean live case: expected 'full', got '{comp_clean}'")

    # Case D (Task 5 Unicredit/Bol): 0 techs detected with 'full' -> must downgrade to 'partial_empty_render'
    empty_tech_info = {
        'detected_technologies_list': [],
        'tech_scan_completeness': 'full',
        'has_cookie_banner': False,
        'all_ga4_ids': None,
    }
    normalize_tech_fn(empty_tech_info)
    if empty_tech_info['tech_scan_completeness'] != 'partial_empty_render':
        raise AssertionError(
            f"Unicredit/Bol empty render case: expected 'partial_empty_render', got '{empty_tech_info['tech_scan_completeness']}'"
        )
    if empty_tech_info.get('has_ga4') is not None:
        raise AssertionError(f"Expected has_ga4=None on partial_empty_render, got {empty_tech_info.get('has_ga4')}")

    return "PASS (partial_cached enforced on failed/empty live; partial_empty_render on 0-tech scan)"


def _test_04_vorstand_role_extraction() -> str:
    """
    Test 4/6: German 'Vorstand:' pattern extraction & role normalization (DocMorris case).
    """
    html = (
        '<html><body>'
        '<p>DocMorris N.V., Vertreten durch den Vorstand: Gundula Koele-Pabst, Heerlen.</p>'
        '</body></html>'
    )
    pages = [('https://www.docmorris.de/de/impressum', html, 'Vertreten durch den Vorstand: Gundula Koele-Pabst')]
    dm_name, dm_role, _, _, _, src_type, _, dms_json = extract_decision_maker_deep(pages)

    if dm_name != 'Gundula Koele-Pabst':
        raise AssertionError(f"Expected 'Gundula Koele-Pabst', got '{dm_name}'")
    if not dm_role or 'CEO' not in dm_role:
        raise AssertionError(f"Expected role containing 'CEO', got '{dm_role}'")
    if src_type != 'impressum_page':
        raise AssertionError(f"Expected source_type 'impressum_page', got '{src_type}'")
    parsed = json.loads(dms_json or '[]')
    if not parsed or parsed[0].get('name') != 'Gundula Koele-Pabst':
        raise AssertionError(f"Invalid decision_makers_json: {dms_json}")

    return "PASS ('Vorstand: Gundula Koele-Pabst' -> CEO role + valid JSON)"


def _test_05_sgtm_positive_fixture(normalize_tech_fn: Callable[[dict], None]) -> str:
    """
    Test 5/6: Positive sGTM custom-domain GTM loader detection.
    """
    pos_html = (
        '<html><head>'
        '<script src="https://metrics.custom-domain.io/gtm.js?id=GTM-TEST123"></script>'
        '<script src="https://www.googletagmanager.com/gtag/js?id=G-12345678AB"></script>'
        '</head><body></body></html>'
    )
    pos_res = detect_tech_with_evidence(pos_html, '', ['GTM-TEST123'], 'https://example.com/', 'full')
    normalize_tech_fn(pos_res)
    if pos_res.get('has_sgtm') is not True:
        raise AssertionError(f"Expected has_sgtm=True on positive fixture, got {pos_res.get('has_sgtm')}")
    if 'Server-Side GTM (sGTM)' not in (pos_res.get('detected_technologies_list') or []):
        raise AssertionError("Expected 'Server-Side GTM (sGTM)' in detected_technologies_list")

    return "PASS (metrics.custom-domain.io/gtm.js -> has_sgtm=True)"


def _test_06_sgtm_negative_fixtures(normalize_tech_fn: Callable[[dict], None]) -> str:
    """
    Test 6/6: Negative sGTM fixtures (stats.g.doubleclick.net/g/collect, google-analytics.com, custom g/collect without gtm.js).
    """
    neg_fixtures = [
        (
            '<html><head>'
            '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-INTER01"></script>'
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-INTER12345"></script>'
            '<script>fetch("https://stats.g.doubleclick.net/g/collect?v=2&tid=G-XXXX")</script>'
            '</head><body></body></html>'
        ),
        (
            '<html><head>'
            '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-RINGO01"></script>'
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-RINGO12345"></script>'
            '<script>https://www.google-analytics.com/g/collect?v=2&tid=G-YYYY</script>'
            '</head><body></body></html>'
        ),
        (
            '<html><head>'
            '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-COMP01"></script>'
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-COMP12345"></script>'
            '<script>https://metrics.company.com/g/collect?v=2</script>'
            '</head><body></body></html>'
        ),
    ]
    for idx, nf_html in enumerate(neg_fixtures, start=1):
        nf_res = detect_tech_with_evidence(nf_html, '', [f'GTM-NEG00{idx}'], 'https://example.com/', 'full')
        normalize_tech_fn(nf_res)
        if nf_res.get('has_sgtm') is not False:
            raise AssertionError(f"Expected negative_{idx} has_sgtm=False, got {nf_res.get('has_sgtm')}")

    return "PASS (negative_1=False, negative_2=False, negative_3=False)"


def run_startup_regression_gate(
    log_fn: Callable[[str], None],
    normalize_tech_fn: Callable[[dict], None],
    resolve_cache_comp_fn: Callable[[bool, bool, bool, bool, str], str],
) -> None:
    """
    Blocking CI/CD Regression Gate executed inside Apify container before any scraping starts.
    If any of the 6 core regression tests fail, raises RuntimeError and aborts the run immediately.
    """
    t0 = time.monotonic()
    suite = [
        ('test_01_corporate_entities', _test_01_corporate_entities),
        ('test_02_determinism_ottogroup_3x', _test_02_determinism_ottogroup_3x),
        (
            'test_03_cache_merge_completeness',
            lambda: _test_03_cache_merge_completeness_and_empty_render(normalize_tech_fn, resolve_cache_comp_fn),
        ),
        ('test_04_vorstand_role', _test_04_vorstand_role_extraction),
        ('test_05_sgtm_positive', lambda: _test_05_sgtm_positive_fixture(normalize_tech_fn)),
        ('test_06_sgtm_negative_full', lambda: _test_06_sgtm_negative_fixtures(normalize_tech_fn)),
    ]

    passed_count = 0
    for test_name, test_callable in suite:
        try:
            detail = test_callable()
            passed_count += 1
            log_fn(f"[REGRESSION SUITE] {test_name}: {detail}")
        except Exception as exc:
            log_fn(f"[REGRESSION SUITE FAIL] {test_name}: {exc}")
            raise RuntimeError(f"Startup Regression Gate aborted Actor run: {test_name} failed ({exc})") from exc

    elapsed_ms = (time.monotonic() - t0) * 1000.0
    log_fn(
        f"[REGRESSION SUITE GATE PASS] {passed_count}/{len(suite)} tests green in {elapsed_ms:.1f}ms "
        f"(corporate_entities=PASS, determinism_3x=PASS, cache_merge=PASS, vorstand=PASS, "
        f"sgtm_pos=True, sgtm_neg_1_2_3=False)"
    )
