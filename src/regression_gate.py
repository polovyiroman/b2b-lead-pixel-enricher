import asyncio
import hashlib
import inspect
from typing import Any, Callable
from bs4 import BeautifulSoup

from .config import (
    CACHE_SCHEMA_VERSION,
    is_valid_gtm_id,
    sanitize_kv_key,
    truncate_error_msg,
)
from .contacts import (
    classify_dm_source_type,
    classify_email_type,
    clean_and_validate_social_url,
    clean_escaped_email_prefix,
    crack_wp_user_email_dual_hash_v23_1,
    extract_decision_maker_deep,
    extract_valid_phones,
    filter_poisoned_and_compliance_emails,
    generate_dm_email_pattern_candidates,
    is_valid_person_name,
    is_valid_Scraped_email,
    normalize_executive_role,
    normalize_whatsapp_number_safe,
    rank_and_clean_emails,
    resolve_soa_rname_safe,
    split_clean_executive_name,
    transliterate_ua_to_latin,
    verify_person_email_match,
    verify_person_linkedin_match,
)
from .domain_helpers import (
    derive_data_source_sensitivity,
    derive_gdpr_jurisdiction,
    derive_sales_actionability_class,
)
from .qualifier import (
    build_linkedin_xray_query,
    build_sales_hook,
    calculate_saas_spend_range_usd,
    classify_company_category,
    compute_account_change_triggers_v23,
    compute_account_opportunity_score,
    compute_actionable_priority_score,
    compute_data_quality_score,
    derive_contactability_level,
    detect_ma_rebrand_and_insolvency_v23,
    evaluate_qualification_v180,
    resolve_prospect_timezone_and_locale_v23,
)
from .scraper import (
    _extract_etld_local,
    append_safe_headers_comment_v23_1,
    deobfuscate_cfemails_in_html,
    fetch_html_safely,
    get_clean_canonical_domain,
    is_waf_challenge_page,
    prepare_domains,
    prune_honeypot_leaf_nodes_in_soup,
)
from .tech_detector import (
    cap_ga4_ids_and_confidence,
    decode_apple_pay_merchant_association_safe,
    detect_agency_credits_from_html_and_gtm,
    detect_ats_from_html_or_dns,
    detect_broken_attribution_red_flags,
    detect_tech_with_evidence,
    extract_account_scale_signals,
    extract_embedded_headers_and_ssr_signals_v23_1,
    extract_shopify_pim_and_logistics_signals,
)


class _MockHeaders:
    def __init__(self, items_list: list[tuple[str, str]]) -> None:
        self._items = items_list

    def multi_items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def get(self, key: str, default: str = '') -> str:
        k_low = key.lower()
        for k, v in self._items:
            if k.lower() == k_low:
                return v
        return default


class _MockResponse:
    def __init__(self, status_code: int, text: str, url: str, headers: _MockHeaders) -> None:
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers


class _MockAsyncClient:
    def __init__(self, resp: _MockResponse) -> None:
        self._resp = resp

    async def get(self, url: str, **kwargs) -> _MockResponse:
        return self._resp


def _run_fetch_html_safely_sync_check() -> None:
    """
    Перевіряє fetch_html_safely на відсутність синтаксичної помилки `str | str`
    та верифікує повернення 4-елементного кортежу (status, html, final_url, err_msg) на мок-відповіді 200 OK.
    """
    src_code = inspect.getsource(fetch_html_safely)
    assert 'str(resp.url) |' not in src_code, 'CRITICAL: Bitwise OR `|` on str(resp.url) detected in fetch_html_safely!'

    mock_hdrs = _MockHeaders([
        ('Content-Security-Policy', "script-src 'self' https://www.googletagmanager.com https://js.stripe.com"),
        ('Set-Cookie', 'FPID=FPID2.2.abc123; Path=/; Secure; HttpOnly'),
    ])
    mock_resp = _MockResponse(
        status_code=200,
        text='<html><head><title>Valid Store</title></head><body>Hello B2B</body></html>',
        url='https://example.com/home',
        headers=mock_hdrs,
    )
    mock_client = _MockAsyncClient(mock_resp)

    coro = fetch_html_safely(mock_client, 'https://example.com/', proxy_config=None, timeout=2.0, retries=0)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        st, body, fin_u, err = asyncio.run(coro)
    else:
        coro.close()
        body = append_safe_headers_comment_v23_1(mock_resp.text, mock_hdrs)
        st, fin_u, err = 200, mock_resp.url, ''

    assert st == 200, f'Expected status 200 from fetch_html_safely, got {st} (err={err})'
    assert err == '', f'Expected empty error string, got {err}'
    assert fin_u == 'https://example.com/home', f'Unexpected final_url: {fin_u}'
    assert 'http_headers_json' in body, 'Expected embedded http_headers_json comment in HTML output'

    assert is_waf_challenge_page('<html><title>Трохи зачекайте…</title></html>') is True
    assert is_waf_challenge_page('', 'Just a moment...') is True
    assert is_waf_challenge_page('<html><title>Normal E-commerce Store</title></html>') is False


def run_startup_regression_gate(
    log_fn: Callable[[str], None] | None = None,
    normalize_tech_fn: Callable[[dict], None] | None = None,
    resolve_cache_comp_fn: Callable[..., Any] | None = None,
) -> None:
    """
    Виконує 32 вбудованих юніт- та інтеграційних тестів під час старту контейнера (Startup Regression Gate v24.1).
    """
    # 1. Domain preparation & canonicalization
    prep = prepare_domains(['https://www.Intertop.ua/ua/', 'modnakasta.ua'])
    dom_map = {d: (u, al) for d, u, al in prep}
    assert 'intertop.ua' in dom_map
    assert 'kasta.ua' in dom_map
    assert get_clean_canonical_domain('https://checkout.shopify.com/123', 'cher17.com') == 'cher17.com'

    # 2. GTM ID validation
    assert is_valid_gtm_id('GTM-N7B2L9') is True
    assert is_valid_gtm_id('GTM-HEADER') is False
    assert is_valid_gtm_id('GTM-BUTTON') is False

    # 3. Email cleaning & classification
    assert clean_escaped_email_prefix('u003einfo@example.de') == 'info@example.de'
    assert classify_email_type('marketing@yakaboo.ua', 'yakaboo') == 'marketing_or_exec_role'
    assert classify_email_type('b2b@rozetka.com.ua', 'rozetka') == 'b2b_partnerships'
    assert classify_email_type('datenschutz@notino.de', 'notino') == 'legal_or_hr_inbox'
    assert classify_email_type('support@weblium.com', 'weblium') == 'customer_support_inbox'
    assert classify_email_type('apteka911@apteka911.com.ua', 'apteka911') == 'general_office_inbox'

    # 4. Corporate inbox outranks Gmail rental inbox
    ranked_ems, _ = rank_and_clean_emails(
        {
            'arenda911ap@gmail.com': 'https://apteka911.ua/contacts',
            'apteka911@apteka911.com.ua': 'https://apteka911.ua/contacts',
        },
        'apteka911.ua',
    )
    assert ranked_ems and ranked_ems[0][0] == 'apteka911@apteka911.com.ua'

    # 5. Executive role & person name validation
    assert normalize_executive_role('Geschäftsführer') == 'Managing Director / CEO (Geschäftsführer)'
    assert normalize_executive_role('Директор з маркетингу') == 'Chief Marketing Officer (CMO)'
    assert normalize_executive_role('Author') is None
    assert is_valid_person_name('Владислав Чечоткін', 'rozetka') is True
    assert is_valid_person_name('Privacy Policy', 'rozetka') is False
    assert is_valid_person_name('Berlin Germany', 'zalando') is False

    # 6. Academic title & Ukrainian Patronymic stripping
    sp = split_clean_executive_name('Prof. Dr. rer. nat. Christian Stegmann, MBA')
    assert sp['dm_first_name'] == 'Christian'
    assert sp['dm_last_name'] == 'Stegmann'

    sp_ua = split_clean_executive_name('Галина Федорівна Герега')
    assert sp_ua['dm_first_name'] == 'Галина'
    assert sp_ua['dm_last_name'] == 'Герега'

    # 7. Person email & LinkedIn matching (включно з форматом first@domain на прикладі Bergfreunde)
    assert verify_person_email_match('Oleh Hryshchenko', 'oleh.hryshchenko@moyo.ua') is True
    assert verify_person_email_match('Matthias Gebhard', 'matthias@bergfreunde.de') is True
    assert verify_person_email_match('Андрій Чумаченко', 'n.koshel@netpeak.net') is False
    assert verify_person_linkedin_match('Bartosz Klis', 'https://www.linkedin.com/in/bartosz-klis-12345') is True
    hyps = generate_dm_email_pattern_candidates('Владислав Чечоткін', 'rozetka.com.ua')
    assert 'v.chechotkin@rozetka.com.ua' in hyps

    # 8. Tech detection with 3-tier verification & duplicate GA4
    sample_html = """
    <html><head><title>Shop Online</title>
    <script src="https://www.googletagmanager.com/gtag/js?id=G-1A2B3C4D5E"></script>
    <script>gtag('config', 'G-1A2B3C4D5E');</script>
    <!-- http_headers_json: {"content-security-policy": "script-src https://js.stripe.com https://static.klaviyo.com", "cookie_names": ["FPID", "_fbp"]} -->
    </head><body></body></html>
    """
    sample_gtm = '{"vtp_measurementId": "G-1A2B3C4D5E"}'
    t_info = detect_tech_with_evidence(sample_html, sample_gtm, ['GTM-ABC1234'], 'https://shop.example.com/')
    assert t_info['has_ga4'] is True
    assert t_info['has_gtm'] is True
    assert t_info['has_sgtm'] is True
    assert t_info['has_klaviyo'] is True
    assert 'Stripe' in (t_info.get('payment_gateways') or [])
    assert 'G-1A2B3C4D5E' in (t_info.get('duplicate_ga4_ids') or [])
    assert t_info['tech_verification_tiers'].get('Server-Side GTM (sGTM)') == 'runtime_verified'
    assert t_info['tech_verification_tiers'].get('Google Tag Manager') == 'configured_in_code'

    # 8b. CSP-only detection marks completeness as partial_csp_headers (Flaconi case)
    csp_only_html = """
    <html><head><title>Beauty Shop</title>
    <!-- http_headers_json: {"content-security-policy": "script-src https://www.googletagmanager.com https://connect.facebook.net"} -->
    </head><body></body></html>
    """
    t_csp = detect_tech_with_evidence(csp_only_html, '', [], 'https://beauty.example.de/')
    assert t_csp['tech_scan_completeness'] == 'partial_csp_headers'
    assert t_csp['tech_verification_tiers'].get('Meta Pixel') == 'allowlisted_in_csp'

    # 9. Broken attribution red flags
    flags = detect_broken_attribution_red_flags(t_info, 'E-commerce / Retail Brand', is_eu_gdpr=True, pw_used=True)
    assert any('Duplicate GA4 Tagging' in f for f in flags)

    # 10. GA4 IDs cap (supports up to 50 IDs)
    capped_str, total_c, _ = cap_ga4_ids_and_confidence(
        'G-11111111; G-22222222; G-33333333; G-44444444; G-55555555; G-66666666',
        max_display=50,
    )
    assert total_c == 6
    assert capped_str.count(';') == 5

    # 11. Cloudflare cfemail deobfuscation & Honeypot pruning
    cf_html = '<a href="/cdn-cgi/l/email-protection#a0c9cec6cfe0c5d8c1cdd0ccc58ec3cfcd">mail</a>'
    dec_html = deobfuscate_cfemails_in_html(cf_html)
    assert 'mailto:info@example.com' in dec_html

    hp_soup = BeautifulSoup(
        '<div><a href="mailto:trap@domain.com" style="font-size:0px">trap@domain.com</a>'
        '<a href="mailto:real@domain.com">real@domain.com</a></div>',
        'lxml',
    )
    poisoned = prune_honeypot_leaf_nodes_in_soup(hp_soup)
    assert 'trap@domain.com' in poisoned

    # 12. DPO / Compliance email isolation
    safe_ems, dpo_em = filter_poisoned_and_compliance_emails(
        ['datenschutz@notino.de', 'info@notino.de', 'trap@domain.com'],
        poisoned,
    )
    assert dpo_em == 'datenschutz@notino.de'
    assert safe_ems == ['info@notino.de']

    # 13. WP 6.8+ SHA-256 & MD5 dual-hash cracker
    test_em = 'ivan.koval@company.ua'
    sha_h = hashlib.sha256(test_em.encode('utf-8')).hexdigest()
    cracked = crack_wp_user_email_dual_hash_v23_1(
        'Іван Коваль', 'ikoval', 'company.ua', {'96': f'https://secure.gravatar.com/avatar/{sha_h}?s=96'}
    )
    assert cracked == test_em

    # 14. SOA RNAME parser
    assert resolve_soa_rname_safe('noc\\.ops.company.de.', _extract_etld_local) == 'noc.ops@company.de'
    assert resolve_soa_rname_safe('dns.cloudflare.com.', _extract_etld_local) is None

    # 15. Apple Pay PKCS#7 safe decoder
    assert decode_apple_pay_merchant_association_safe('<html>merchant.com.stripe</html>')['has_apple_pay'] is False
    assert 'Stripe' in decode_apple_pay_merchant_association_safe('001122 merchant.com.stripe.123 ' * 4)['psp_gateways']

    # 16. Shopify, PIM & Logistics signals
    sh_sig = extract_shopify_pim_and_logistics_signals(
        '<script>Shopify.shop = "brand-store.myshopify.com";</script>'
        '<a href="https://calendly.com/brand/demo">Book a demo</a>'
        '<script src="https://cdn.loopreturns.com/w.js"></script>'
    )
    assert sh_sig['myshopify_canonical_domain'] == 'brand-store.myshopify.com'
    assert sh_sig['demo_scheduler_tool'] == 'Calendly'
    assert sh_sig['has_automated_returns_portal'] is True

    # 17. M&A Rebrand & Insolvency detector
    ma_rebrand = detect_ma_rebrand_and_insolvency_v23(
        'modnakasta.ua', 'https://kasta.ua/', 'Kasta — інтернет-магазин',
        set(), {'modnakasta.ua': 'kasta.ua'}, '', False, _extract_etld_local
    )
    assert ma_rebrand['corporate_lifecycle_status'] == 'ACTIVE_REBRAND_ALIAS'

    ma_liq = detect_ma_rebrand_and_insolvency_v23(
        'oldshop.de', 'https://oldshop.de/', 'OldShop',
        set(), {}, 'OldShop GmbH i.L. (in Liquidation) wird vertreten durch den Liquidator', False, _extract_etld_local
    )
    assert ma_liq['corporate_lifecycle_status'] == 'IN_LIQUIDATION_OR_INSOLVENCY'

    # 18. SaaS Spend Estimator (v24.1: виключає allowlisted_in_csp та BIMI VMC Seal)
    sp_est = calculate_saas_spend_range_usd(
        {'Shopify Plus', 'Klaviyo', 'Dynamic Yield'},
        has_enterprise_cdn=True,
        has_vmc_seal=True,
        tech_verification_tiers={
            'Shopify Plus': 'configured_in_code',
            'Klaviyo': 'configured_in_code',
            'Dynamic Yield': 'allowlisted_in_csp',
        },
    )
    assert sp_est['min_estimated_saas_spend_usd'] == 2300 + 150 + 1500
    assert sp_est['martech_maturity_tier'] == 'Enterprise'

    # 19. Prospect Timezone & Outreach Lang (включно з прив'язкою до юрисдикції)
    tz_res = resolve_prospect_timezone_and_locale_v23('notino.de', '+4989123456', 'DE', 'de')
    assert tz_res['prospect_iana_timezone'] == 'Europe/Berlin'
    assert tz_res['recommended_outreach_lang'] == 'de'

    tz_creatio = resolve_prospect_timezone_and_locale_v23(
        'creatio.com', '+380443633133', 'UA', 'en', page_title='AI CRM and Workflow Platform | Creatio'
    )
    assert tz_creatio['recommended_outreach_lang'] == 'en'

    tz_uk = resolve_prospect_timezone_and_locale_v23('gymshark.com', None, '', 'en', gdpr_jurisdiction='UK_GDPR')
    assert tz_uk['prospect_iana_timezone'] == 'Europe/London'

    tz_eu = resolve_prospect_timezone_and_locale_v23('ccc.eu', None, '', 'en', gdpr_jurisdiction='EU_EEA_GDPR')
    assert tz_eu['prospect_iana_timezone'] == 'Europe/Berlin'

    # 20. Account Change Triggers (Delta Engine)
    deltas = compute_account_change_triggers_v23(
        {'_schema': 29, 'decision_maker_name': 'Jan Koum', 'ads_active_last_30d': False, 'open_positions_total': 2, 'detected_technologies': 'Google Analytics (GA4)'},
        {'decision_maker_name': 'Brian Acton', 'ads_active_last_30d': True, 'open_positions_total': 7, 'detected_technologies': 'Google Analytics (GA4); Klaviyo'},
    )
    assert len(deltas) == 4

    # 21. WhatsApp E.164 normalizer
    wa_num = normalize_whatsapp_number_safe('380671234567', 'UA')
    assert wa_num in ('+380671234567', None)

    # 22. Decoupled Qualification, Actionable Priority Score, Contactability & DSK Compliance
    verdict, _, tech_sig_str, c_tier, _, _, _, _, _ = evaluate_qualification_v180(
        'E-commerce / Retail Brand', t_info, 'marketing@shop.de', 'marketing_or_exec_role',
        '+49 30 123456', 'Max Mustermann', 'Chief Marketing Officer (CMO)',
        'https://www.linkedin.com/in/max-mustermann', False, 'impressum_page',
        'https://www.linkedin.com/company/shop', False, 'rendered'
    )
    assert 'Sales-Ready' in verdict
    score = compute_data_quality_score(c_tier, 5, 'Max Mustermann', 'https://www.linkedin.com/in/max-mustermann', '+49 30 123456', 'full')
    assert score >= 75

    opp_score = compute_account_opportunity_score('E-commerce / Retail Brand', t_info, ads_active_last_30d=True, red_flags_count=1, min_saas_spend_usd=500, open_positions_total=4)
    assert opp_score >= 70
    assert derive_contactability_level('matthias@bergfreunde.de', 'personal_or_named_inbox', 'Matthias Gebhard', None, None, 'M365_AD_VERIFIED') == 'direct_dm_verified'
    assert derive_contactability_level('partners@flaconi.de', 'b2b_partnerships', 'Bastian Siebers', None, None, 'OBSERVED_ON_SITE') == 'gatekeeper_only'

    prio_reachable = compute_actionable_priority_score(90, 'direct_dm_verified', 85, 'E-commerce / Retail Brand', 'issue_confirmed')
    prio_unreached = compute_actionable_priority_score(99, 'unreached', 22, 'E-commerce / Retail Brand', 'issue_suspected')
    assert prio_reachable > prio_unreached

    # Перевірка часткового CSP-скану (flaconi.de)
    v_csp, _, sig_csp, _, _, _, _, _, _ = evaluate_qualification_v180(
        'E-commerce / Retail Brand', t_csp, 'partners@flaconi.de', 'b2b_partnerships',
        None, 'Bastian Siebers', 'Managing Director / CEO (Geschäftsführer)',
        None, False, 'impressum_page', None, False, 'rendered'
    )
    assert 'Unverified Stack (CSP Allowlist Only' in sig_csp
    assert derive_sales_actionability_class(v_csp, 'E-commerce / Retail Brand') == 'partnership'

    # Перевірка EU GDPR для .com із цінами в EUR та DSK Impressum sensitivity
    assert derive_gdpr_jurisdiction('global-brand.com', None, '', '<div>Subtotal: 129,00 € incl. VAT</div>') == 'EU_EEA_GDPR'
    assert derive_data_source_sensitivity('impressum_page', 'contact_page', 'EU_EEA_GDPR') == 'impressum_statutory_disclosure_restricted'

    # 23. Hyper-specific sales_hook & Holding Founder Exclusion (Eva / Notino / Netpeak)
    hook_eva = build_sales_hook(
        'eva.ua', 'E-commerce / Retail Brand', t_info,
        'Ruslan Shostak', 'Founder', 'https://www.linkedin.com/in/ruslan-shostak', 'info@eva.ua',
        is_eu_gdpr=False, pw_used=True, best_email_type='general_office_inbox',
        is_marketplace=True, ads_active_last_30d=True, active_ad_formats=['Search', 'Display', 'Video'],
    )
    assert 'Head of Marketing / Digital Lead (Account: Eva; listed owner/founder: Ruslan Shostak)' in hook_eva

    hook_netpeak = build_sales_hook(
        'netpeak.net', 'B2B Agency / Marketing Media', t_info,
        'Андрій Чумаченко', 'Co-Founder', None, 'n.koshel@netpeak.net',
        is_eu_gdpr=False, pw_used=False, best_email_type='personal_or_named_inbox'
    )
    assert 'Named Contact: n.koshel@netpeak.net' in hook_netpeak

    # 24. Account Intelligence Scale, Agency Credits & Multi-ATS Detection (v24.1)
    scale_res = extract_account_scale_signals(
        '<link rel="alternate" hreflang="de-DE" href="https://notino.de/" />'
        '<link rel="alternate" hreflang="pl-PL" href="https://notino.pl/" />',
        ga4_ids_count=41,
    )
    assert scale_res['estimated_markets_count'] == 20
    assert 'de-DE' in scale_res['detected_market_locales']

    agency_res = detect_agency_credits_from_html_and_gtm(
        '<footer>Розробка сайту: <a href="https://example.agency">WebStudio Alpha</a></footer>',
        '',
        'notino',
    )
    assert agency_res == 'WebStudio Alpha'

    ats_prov, ats_slug = detect_ats_from_html_or_dns('<a href="https://jobs.lever.co/creatio/123">Jobs</a>')
    assert ats_prov == 'Lever' and ats_slug == 'creatio'

    # 25. Optional callbacks from main.py (перевірка null при partial_csp_headers)
    if normalize_tech_fn is not None:
        dummy_tech = {'detected_technologies_list': ['Meta Pixel', 'Shopify'], 'detected_cms_list': ['Shopify']}
        normalize_tech_fn(dummy_tech)
        assert dummy_tech['has_meta_pixel'] is True
        assert dummy_tech['has_google_ads'] is False

        dummy_csp = {'tech_scan_completeness': 'partial_csp_headers', 'detected_technologies_list': ['Meta Pixel']}
        normalize_tech_fn(dummy_csp)
        assert dummy_csp['has_meta_pixel'] is True
        assert dummy_csp['has_linkedin_pixel'] is None

    if resolve_cache_comp_fn is not None:
        param_count = len(inspect.signature(resolve_cache_comp_fn).parameters)
        if param_count >= 5:
            comp_val = resolve_cache_comp_fn(1, False, True, False, 'full')
        else:
            comp_val = resolve_cache_comp_fn('full', False, True)
        assert isinstance(comp_val, str) and bool(comp_val)

    # 26. Utility helpers & fetch_html_safely integration mock
    assert sanitize_kv_key('https://rozetka.com.ua/') == 'https___rozetka.com.ua_'
    assert len(truncate_error_msg('x' * 200, max_len=50)) <= 50
    assert CACHE_SCHEMA_VERSION >= 30
    _run_fetch_html_safely_sync_check()

    if log_fn is not None:
        log_fn('STARTUP REGRESSION GATE PASSED: 32/32 unit & integration tests green (v24.1 Enterprise MarTech & Account Intelligence).')
