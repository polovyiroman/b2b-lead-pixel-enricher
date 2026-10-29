import json
import time
from typing import Callable

from .config import DEFAULT_MANUAL_SEEDS
from .contacts import (
    build_decision_makers_json_from_summary,
    classify_email_type,
    extract_decision_maker_deep,
    is_valid_person_name,
    strip_role_tokens_from_name,
)
from .domain_helpers import (
    KNOWN_POISONED_CACHE_RECOVERY,
    KNOWN_PW_HOPELESS,
    SALES_ACTIONABILITY_ENUM_VALUES,
    build_safe_cache_payload,
    derive_sales_actionability_class,
    heal_poisoned_cache_record,
    merge_missing_techs_from_cache,
    normalize_cached_record_booleans,
    sanitize_cached_dms,
)
from .qualifier import (
    classify_company_category,
    compute_data_quality_score,
)
from .scraper import (
    _is_safe_domain,
    get_clean_canonical_domain,
    prepare_domains,
)
from .tech_detector import detect_tech_with_evidence


def _test_01_corporate_entities() -> str:
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


def _test_03_cache_merge_completeness_and_liki24_partial_merge(
    normalize_tech_fn: Callable[[dict], None],
    resolve_cache_comp_fn: Callable[..., str],
) -> str:
    comp_comfy = resolve_cache_comp_fn(True, False, True, False, 'partial_blocked', False)
    if comp_comfy != 'partial_cached':
        raise AssertionError(f"Comfy case: expected 'partial_cached', got '{comp_comfy}'")

    comp_macpaw_curl = resolve_cache_comp_fn(True, False, False, True, 'full', True)
    if comp_macpaw_curl != 'full':
        raise AssertionError(f"Macpaw curl-clean live case: expected 'full', got '{comp_macpaw_curl}'")

    liki_live_partial = {
        'has_ga4': True,
        'has_gtm': False,
        'has_google_ads': True,
        'has_meta_pixel': False,
        'has_tiktok_pixel': False,
        'has_linkedin_pixel': False,
        'has_pinterest_tag': False,
        'has_hubspot': False,
        'has_klaviyo': False,
        'has_sgtm': False,
        'all_ga4_ids': 'G-FRYX20Z9FG',
        'ga4_detection_confidence': 'High',
        'detected_cms_list': [],
        'detected_cms': None,
        'has_cookie_banner': False,
        'detected_technologies_list': ['Google Analytics (GA4)', 'Google Ads Conversion'],
        'technology_evidence': 'GA4 live',
        'technology_evidence_summary': 'GA4, Google Ads',
        'technology_evidence_json': json.dumps({
            'Google Analytics (GA4)': {'source': 'live_html'},
            'Google Ads Conversion': {'source': 'live_html'},
        }),
        'tech_scan_completeness': 'partial_blocked',
    }
    liki_cache_full = {
        'has_ga4': True,
        'has_gtm': True,
        'has_google_ads': True,
        'has_meta_pixel': True,
        'all_ga4_ids': 'G-FRYX20Z9FG',
        'detected_technologies': 'Google Tag Manager; Google Analytics (GA4); Google Ads Conversion; Meta Pixel',
        'technology_evidence': 'GTM + GA4 + Google Ads + Meta Pixel',
    }
    merged_liki, was_recovered, added_cnt = merge_missing_techs_from_cache(
        liki_live_partial, liki_cache_full, pw_used_flag=True, pw_had_timeout_or_block=True
    )
    normalize_tech_fn(merged_liki)
    merged_list = merged_liki.get('detected_technologies_list') or []
    if 'Google Tag Manager' not in merged_list or 'Meta Pixel' not in merged_list:
        raise AssertionError(f"Liki24 partial+cache merge failed to recover GTM/Meta: {merged_list}")
    if merged_liki.get('tech_scan_completeness') != 'partial_cached' or not was_recovered or added_cnt != 2:
        raise AssertionError(f"Liki24 expected partial_cached with 2 recovered techs, got comp={merged_liki.get('tech_scan_completeness')}, cnt={added_cnt}")

    empty_tech_info = {
        'detected_technologies_list': [],
        'tech_scan_completeness': 'full',
        'has_cookie_banner': False,
        'all_ga4_ids': None,
    }
    normalize_tech_fn(empty_tech_info)
    if empty_tech_info['tech_scan_completeness'] != 'partial_empty_render':
        raise AssertionError(f"Expected 'partial_empty_render', got '{empty_tech_info['tech_scan_completeness']}'")

    return "PASS (Liki24 partial+cache merges GTM+Meta; Macpaw curl->full; 0-tech->partial_empty_render)"


def _test_04_vorstand_role_extraction() -> str:
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


def _test_07_inweb_dm_consistency_and_liki24_hygiene() -> str:
    raw_inweb_found = (
        'Ігор Мутерко (Founder) [https://inweb.ua/ua/team/]; '
        'Олексій Мамонтов (Chief Executive Officer (CEO)) [https://inweb.ua/ua/team/]; '
        'Олександр Салієнко (Owner) [https://inweb.ua/ua/]'
    )
    dm_name, _, dms_found_str = sanitize_cached_dms(
        'Олексій Мамонтов',
        'Chief Executive Officer (CEO)',
        raw_inweb_found,
        brand_root='inweb',
    )
    dms_json_str = build_decision_makers_json_from_summary(dms_found_str, None)
    dms_json = json.loads(dms_json_str or '[]')
    first_found_name = (dms_found_str or '').split(';')[0].split('(')[0].strip()

    if not dm_name or dm_name != dms_json[0]['name'] or dm_name != first_found_name:
        raise AssertionError(
            f"Inweb DM mismatch: dm_name='{dm_name}', json[0]='{dms_json[0]['name']}', found[0]='{first_found_name}'"
        )
    if dm_name != 'Олексій Мамонтов':
        raise AssertionError(f"Expected CEO 'Олексій Мамонтов' to rank #1 over Founder, got '{dm_name}'")

    liki_cached = {
        'has_sgtm': True,
        'has_ga4': True,
        'has_gtm': True,
        'detected_technologies': 'Google Tag Manager; Server-Side GTM (sGTM); Google Analytics (GA4); Meta Pixel',
        'detected_signals': 'Meta Pixel, GA4, GTM, sGTM',
        'technology_evidence': (
            'Google Tag Manager: id=GTM-LIKI @ https://liki24.com/ | '
            'Server-Side GTM (sGTM): custom endpoint "https://stats.g.doubleclick.net/g/collect?v=2" @ https://liki24.com/'
        ),
        'tech_scan_completeness': 'partial_cached',
    }
    normalize_cached_record_booleans(liki_cached)
    if 'sGTM' in (liki_cached.get('detected_signals') or ''):
        raise AssertionError(f"Stale sGTM remained in detected_signals: {liki_cached.get('detected_signals')}")
    if 'Server-Side GTM' in (liki_cached.get('technology_evidence') or ''):
        raise AssertionError(f"Stale sGTM remained in technology_evidence: {liki_cached.get('technology_evidence')}")

    return "PASS (Inweb dm_name==json[0]==found[0] deterministic; Liki24 stale sGTM purged)"


def _test_08_glossier_spa_ecommerce_category() -> str:
    for run_idx in range(3):
        cat, _ = classify_company_category(
            'glossier.com',
            'Glossier | Skincare, Makeup, Body, Fragrance',
            'Glossier is a new approach to beauty.',
            ['Google Analytics (GA4)', 'Meta Pixel'],
            '<html><body><script>fetch("/cart.js"); const v = {"variant": 123};</script></body></html>',
        )
        if cat != 'E-commerce / Retail Brand':
            raise AssertionError(f"Glossier run #{run_idx + 1}: expected 'E-commerce / Retail Brand', got '{cat}'")

    spa_cat, spa_conf = classify_company_category(
        'unknown-dtc-brand.io',
        'Modern Essentials',
        'Everyday essentials designed for life.',
        ['Google Analytics (GA4)'],
        '<html><body><script>window.Shopify = {}; fetch("/cart.js"); const p = {"product": true, "variant": 1};</script></body></html>',
    )
    if spa_cat != 'E-commerce / Retail Brand':
        raise AssertionError(f"SPA fallback failed: expected 'E-commerce / Retail Brand', got '{spa_cat}' ({spa_conf})")

    ringo_cat, _ = classify_company_category('ringostat.com', 'Ringostat — Call Tracking & PBX', '', ['Google Analytics (GA4)'])
    if ringo_cat != 'SaaS / Marketplace / Tech Platform':
        raise AssertionError(f"Ringostat category regressed: got '{ringo_cat}'")

    return "PASS (Glossier 3x + SPA e-com fallback -> E-commerce / Retail Brand; SaaS intact)"


def _test_09_curl_clean_live_without_cms_stays_full(normalize_tech_fn: Callable[[dict], None]) -> str:
    html = (
        '<html><head>'
        '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-KW4BC5"></script>'
        '<script src="https://www.googletagmanager.com/gtag/js?id=G-1QQT66XX0W"></script>'
        '</head><body>MacPaw</body></html>'
    )
    info = detect_tech_with_evidence(html, '', ['GTM-KW4BC5'], 'https://macpaw.com/', 'full')
    normalize_tech_fn(info)
    if info.get('has_ga4') is not True or info.get('detected_cms') is not None:
        raise AssertionError(f"Unexpected initial Macpaw fixture state: {info}")
    if info.get('tech_scan_completeness') != 'full':
        raise AssertionError(f"Expected 'full' completeness for curl-clean Macpaw fixture, got '{info.get('tech_scan_completeness')}'")

    return "PASS (Custom site with live GTM+GA4 and detected_cms=None stays 'full')"


def _test_10_aboutyou_ga4_cap_and_affiliate_creator_classification(normalize_tech_fn: Callable[[dict], None]) -> str:
    fake_27_ids = [f'G-TEST{i:02d}ABCD' for i in range(1, 28)]
    scripts = ''.join(f"<script>gtag('config', '{gid}');</script>" for gid in fake_27_ids)
    html_27 = f"<html><head>{scripts}</head><body>AboutYou</body></html>"
    info_27 = detect_tech_with_evidence(html_27, '', ['GTM-AY1234'], 'https://www.aboutyou.de/', 'full')
    normalize_tech_fn(info_27)

    displayed_ids = [x.strip() for x in (info_27.get('all_ga4_ids') or '').split(';') if x.strip()]
    if len(displayed_ids) != 5:
        raise AssertionError(f"Expected all_ga4_ids capped at 5, got {len(displayed_ids)}: {displayed_ids}")
    if info_27.get('all_ga4_ids_count') != 27:
        raise AssertionError(f"Expected all_ga4_ids_count=27, got {info_27.get('all_ga4_ids_count')}")
    if info_27.get('ga4_detection_confidence') != 'High (multiplexed 27-property)':
        raise AssertionError(f"Expected 'High (multiplexed 27-property)', got '{info_27.get('ga4_detection_confidence')}'")

    ay_type = classify_email_type('affiliate.creator@aboutyou.com', 'aboutyou')
    if ay_type != 'influencer_gifting_inbox':
        raise AssertionError(f"Expected 'influencer_gifting_inbox' for affiliate.creator@aboutyou.com, got '{ay_type}'")

    if classify_email_type('partnerwerden@docmorris.de', 'docmorris') != 'b2b_partnerships':
        raise AssertionError("partnerwerden@docmorris.de regressed from b2b_partnerships")
    if classify_email_type('sales@ringostat.com', 'ringostat') != 'wholesale_or_sales_inbox':
        raise AssertionError("sales@ringostat.com regressed from wholesale_or_sales_inbox")

    return "PASS (27 GA4 IDs capped to 5 + count=27; affiliate.creator@ -> influencer_gifting_inbox)"


def _test_11_poisoned_cache_recovery_and_safe_write_policy(normalize_tech_fn: Callable[[dict], None]) -> str:
    poisoned_v2012_cache = {
        'has_ga4': True,
        'has_gtm': False,
        'has_google_ads': True,
        'has_meta_pixel': False,
        'all_ga4_ids': 'G-FRYX20Z9FG',
        'detected_technologies': 'Google Analytics (GA4); Google Ads Conversion',
        'technology_evidence': 'GA4 + Google Ads only (poisoned in v20.12)',
    }
    healed_cache = heal_poisoned_cache_record('liki24.com', poisoned_v2012_cache)
    empty_live = {
        'has_ga4': False,
        'has_gtm': False,
        'has_google_ads': False,
        'has_meta_pixel': False,
        'has_tiktok_pixel': False,
        'has_linkedin_pixel': False,
        'has_pinterest_tag': False,
        'has_hubspot': False,
        'has_klaviyo': False,
        'has_sgtm': False,
        'all_ga4_ids': None,
        'ga4_detection_confidence': None,
        'detected_cms_list': [],
        'detected_cms': None,
        'has_cookie_banner': False,
        'detected_technologies_list': [],
        'technology_evidence': None,
        'technology_evidence_summary': None,
        'technology_evidence_json': None,
        'tech_scan_completeness': 'partial_empty_render',
    }
    merged_liki, _, _ = merge_missing_techs_from_cache(
        empty_live, healed_cache or {}, pw_used_flag=True, pw_had_timeout_or_block=False
    )
    normalize_tech_fn(merged_liki)
    techs = merged_liki.get('detected_technologies_list') or []
    if len(techs) < 4 or 'Google Tag Manager' not in techs or 'Meta Pixel' not in techs:
        raise AssertionError(f"Poisoned Liki24 cache failed to heal to 4 techs: {techs}")

    liki_score = compute_data_quality_score(
        'Tier D (Low Sales Fit: customer_support_inbox)',
        len(techs),
        None,
        None,
        None,
        merged_liki['tech_scan_completeness'],
        True,
        company_category='E-commerce / Retail Brand',
    )
    if liki_score < 20:
        raise AssertionError(f"Expected Liki24 score >= 20 after healing, got {liki_score}")

    prior_clean_cache = {
        'detected_technologies': 'Google Tag Manager; Google Analytics (GA4); Google Ads Conversion; Meta Pixel',
        'has_gtm': True,
        'has_ga4': True,
        'has_google_ads': True,
        'has_meta_pixel': True,
    }
    bad_partial_run = {
        'tech_scan_completeness': 'partial_blocked',
        'detected_technologies': 'Google Analytics (GA4); Google Ads Conversion',
        'has_gtm': None,
        'has_ga4': True,
        'has_google_ads': True,
        'has_meta_pixel': None,
    }
    safe_payload = build_safe_cache_payload(bad_partial_run, prior_clean_cache)
    if safe_payload.get('_partial_write') is not True:
        raise AssertionError("Expected _partial_write=True on partial cache payload")
    saved_techs = [x.strip() for x in (safe_payload.get('detected_technologies') or '').split(';') if x.strip()]
    if len(saved_techs) != 4 or 'Google Tag Manager' not in saved_techs or 'Meta Pixel' not in saved_techs:
        raise AssertionError(f"Safe cache write policy allowed partial run to overwrite rich cache: {saved_techs}")

    return f"PASS (Poisoned Liki24 healed to 4 techs, score={liki_score}>=20; _partial_write safe union verified)"


def _test_12_v2015_security_ssrf_rozetka_and_actionability_enum() -> str:
    unsafe_targets = [
        '127.0.0.1',
        '10.0.0.1',
        '192.168.1.1',
        '169.254.169.254',
        'localhost',
        'metadata.internal',
        'printer.local',
        'router.lan',
    ]
    for bad in unsafe_targets:
        if _is_safe_domain(bad):
            raise AssertionError(f"SSRF check failed: unsafe target '{bad}' was accepted")

    if not _is_safe_domain('example.com') or not _is_safe_domain('ringostat.com'):
        raise AssertionError("Valid domain 'example.com' was falsely rejected by _is_safe_domain")

    prep = prepare_domains(['file:///etc/passwd', 'http://127.0.0.1:8080/admin', 'https://macpaw.com'])
    if len(prep) != 1 or prep[0][0] != 'macpaw.com':
        raise AssertionError(f"prepare_domains failed SSRF filtering: {prep}")

    rozetka_seed = DEFAULT_MANUAL_SEEDS.get('rozetka.com.ua', {})
    if rozetka_seed.get('all_ga4_ids') is not None:
        raise AssertionError(f"Fake Rozetka GA4 ID still present: {rozetka_seed.get('all_ga4_ids')}")

    for hopeless_dom in ('grammarly.com', 'laredoute.fr', 'zalando.de'):
        if hopeless_dom not in KNOWN_PW_HOPELESS:
            raise AssertionError(f"Expected '{hopeless_dom}' in KNOWN_PW_HOPELESS")

    liki_rec = KNOWN_POISONED_CACHE_RECOVERY.get('liki24.com', {})
    if not liki_rec.get('recovery_verified_at') or not liki_rec.get('max_recovery_age_days'):
        raise AssertionError("KNOWN_POISONED_CACHE_RECOVERY['liki24.com'] missing expiry metadata")

    enum_cases = [
        ('Sales-Ready Tier 1.5 (Verified DM)', 'E-commerce / Retail Brand', 'sales_ready'),
        ('Partnership-Ready Only (B2B Inbox)', 'SaaS / Marketplace / Tech Platform', 'partnership'),
        ('Gatekeeper-Ready Only (Office Inbox)', 'E-commerce / Retail Brand', 'gatekeeper'),
        ('Tech-Qualified Account Only', 'E-commerce / Retail Brand', 'tech_only'),
        ('Partner Pipeline Only', 'B2B Agency / Marketing Media', 'partner_agency'),
        ('Unverified (Scan Blocked by WAF)', 'E-commerce / Retail Brand', 'unqualified'),
    ]
    for verd, cat, expected_cls in enum_cases:
        got = derive_sales_actionability_class(verd, cat)
        if got != expected_cls or got not in SALES_ACTIONABILITY_ENUM_VALUES:
            raise AssertionError(f"Actionability enum mismatch for '{verd}': expected '{expected_cls}', got '{got}'")

    return "PASS (SSRF blocked; G-ROZETKA-GA4 removed; PW hopeless updated; 6-enum actionability verified)"


def _test_13_subdomain_canonicalization() -> str:
    cases = [
        ('https://en.zalando.de/women-home/', 'zalando.de', 'zalando.de'),
        ('https://en.aboutyou.de/your-shop', 'aboutyou.de', 'aboutyou.de'),
        ('https://www.en.aboutyou.de/', 'aboutyou.de', 'aboutyou.de'),
        ('https://ua.ringostat.com/', 'ringostat.com', 'ringostat.com'),
        ('https://rozetka.com.ua/ua/', 'rozetka.com.ua', 'rozetka.com.ua'),
    ]
    for final_u, fb, expected in cases:
        got = get_clean_canonical_domain(final_u, fb)
        if got != expected:
            raise AssertionError(f"Subdomain canonicalization failed for '{final_u}': expected '{expected}', got '{got}'")

    return "PASS (en.zalando.de->zalando.de, en.aboutyou.de->aboutyou.de, rozetka.com.ua intact)"


def _test_14_first_party_sgtm_collect_and_consent_mode_v2(normalize_tech_fn: Callable[[dict], None]) -> str:
    """
    Test 14/14 (v20.17 Deep Architecture Audit):
    1. Verifies first-party sGTM collector (https://sgtm.brand.com/g/collect?v=2&tid=G-12345678AB&gcs=G111&gcd=13r3r3r3r5)
       is detected as Server-Side GTM (has_sgtm=True) + Consent Mode v2 (has_consent_mode_v2_signals=True).
    2. Verifies productsafety@aboutyou.com is classified as 'legal_or_hr_inbox' so customer-facing inboxes win.
    """
    html_sgtm_collect = (
        '<html><head>'
        '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-STD1234"></script>'
        '</head><body>'
        '<!-- pw_net_req: https://sgtm.brand.com/g/collect?v=2&tid=G-12345678AB&gcs=G111&gcd=13r3r3r3r5 -->'
        '</body></html>'
    )
    info = detect_tech_with_evidence(html_sgtm_collect, '', ['GTM-STD1234'], 'https://brand.com/', 'full')
    normalize_tech_fn(info)
    if info.get('has_sgtm') is not True:
        raise AssertionError(f"Expected has_sgtm=True on first-party /g/collect with tid=G-, got {info.get('has_sgtm')}")
    if info.get('has_consent_mode_v2_signals') is not True:
        raise AssertionError("Expected has_consent_mode_v2_signals=True when gcs=G111 & gcd= present")

    ps_type = classify_email_type('productsafety@aboutyou.com', 'aboutyou')
    if ps_type != 'legal_or_hr_inbox':
        raise AssertionError(f"Expected 'legal_or_hr_inbox' for productsafety@aboutyou.com, got '{ps_type}'")

    return "PASS (first-party sGTM /g/collect+tid=G- -> has_sgtm=True; gcs/gcd -> Consent Mode v2; productsafety@ -> legal)"


def run_startup_regression_gate(
    log_fn: Callable[[str], None],
    normalize_tech_fn: Callable[[dict], None],
    resolve_cache_comp_fn: Callable[..., str],
) -> None:
    t0 = time.monotonic()
    suite = [
        ('test_01_corporate_entities', _test_01_corporate_entities),
        ('test_02_determinism_ottogroup_3x', _test_02_determinism_ottogroup_3x),
        (
            'test_03_cache_merge_completeness',
            lambda: _test_03_cache_merge_completeness_and_liki24_partial_merge(normalize_tech_fn, resolve_cache_comp_fn),
        ),
        ('test_04_vorstand_role', _test_04_vorstand_role_extraction),
        ('test_05_sgtm_positive', lambda: _test_05_sgtm_positive_fixture(normalize_tech_fn)),
        ('test_06_sgtm_negative_full', lambda: _test_06_sgtm_negative_fixtures(normalize_tech_fn)),
        ('test_07_inweb_consistency_and_liki24_hygiene', _test_07_inweb_dm_consistency_and_liki24_hygiene),
        ('test_08_glossier_spa_ecommerce_category', _test_08_glossier_spa_ecommerce_category),
        ('test_09_curl_clean_live_without_cms_stays_full', lambda: _test_09_curl_clean_live_without_cms_stays_full(normalize_tech_fn)),
        ('test_10_aboutyou_ga4_cap_and_affiliate_creator', lambda: _test_10_aboutyou_ga4_cap_and_affiliate_creator_classification(normalize_tech_fn)),
        ('test_11_poisoned_cache_recovery_and_safe_write', lambda: _test_11_poisoned_cache_recovery_and_safe_write_policy(normalize_tech_fn)),
        ('test_12_v2015_security_ssrf_rozetka_and_actionability', _test_12_v2015_security_ssrf_rozetka_and_actionability_enum),
        ('test_13_subdomain_canonicalization', _test_13_subdomain_canonicalization),
        ('test_14_first_party_sgtm_collect_and_consent_mode_v2', lambda: _test_14_first_party_sgtm_collect_and_consent_mode_v2(normalize_tech_fn)),
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
        f"[REGRESSION SUITE GATE PASS] {passed_count}/{len(suite)} tests green in {elapsed_ms:.1f}ms"
    )
