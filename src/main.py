import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
import re
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set
from urllib.parse import urlparse
from apify import Actor
from curl_cffi.requests import AsyncSession

try:
    from aiohttp import web
    _AIOHTTP_AVAILABLE = True
except ImportError:
    web = None
    _AIOHTTP_AVAILABLE = False

from .config import (
    CACHE_SCHEMA_VERSION,
    DEFAULT_MANUAL_SEEDS,
    DM_SOURCE_BLACKLIST,
    EVERGREEN_MAX_AGE_DAYS,
    GTM_ID_REGEX,
    INFRA_SAN_DENYLIST,
    KNOWN_DOMAIN_REDIRECT_ALIASES,
    KNOWN_MARKETPLACE_DOMAINS,
    MIN_COMPATIBLE_CACHE_SCHEMA,
    PUBLIC_WEBMAIL_DOMAINS,
    clean_url_port,
    compute_snapshot_age_days,
    is_valid_gtm_id,
    sanitize_kv_key,
    truncate_error_msg,
)
from .contacts import (
    build_decision_makers_json_from_summary,
    classify_dm_source_type,
    classify_email_source_type_and_note,
    classify_email_type,
    clean_escaped_email_prefix,
    extract_decision_maker_deep,
    extract_named_email_owner_hint,
    fetch_dm_via_serp_fallback,
    filter_poisoned_and_compliance_emails,
    generate_dm_email_pattern_candidates,
    is_marketing_or_digital_role,
    query_doh_json,
    query_wikidata_holding_and_ceo,
    rank_and_clean_emails,
    run_unified_dns_intelligence_v23,
    split_clean_executive_name,
    verify_ceo_email_cascade_port443_v23_1,
    verify_email_deliverability_deep,
    verify_person_email_match,
    verify_predicted_emails_via_api,
)
from .domain_helpers import (
    KNOWN_POISONED_CACHE_RECOVERY,
    KNOWN_PW_HOPELESS,
    PW_GLOBAL_MAX_ATTEMPTS_PER_DOMAIN,
    build_compliance_note,
    build_safe_cache_payload,
    build_timeout_stub,
    check_hostname_ssrf_and_dns_async,
    compute_google_ads_confidence,
    contact_link_priority,
    derive_gdpr_jurisdiction,
    derive_human_contact_tier,
    derive_legal_basis_for_processing,
    derive_pii_fields,
    derive_sales_actionability_class,
    detect_country_hint,
    domain_weight,
    extract_etld_plus_one,
    guess_region_from_domain,
    heal_poisoned_cache_record,
    merge_missing_techs_from_cache,
    normalize_cached_record_booleans,
    normalize_pw_empty_status,
    normalize_tech_info_booleans,
    remaining_run_seconds,
    resolve_cache_merged_completeness,
    resolve_effective_phone_region,
    sanitize_cached_dms,
    sanitize_cached_phones,
)
from .qualifier import (
    build_linkedin_xray_query,
    build_manual_seed_record,
    build_sales_hook,
    calculate_saas_spend_range_usd,
    classify_company_category,
    compute_account_change_triggers_v23,
    compute_data_quality_score,
    detect_ma_rebrand_and_insolvency_v23,
    evaluate_qualification_v180,
    fetch_rdap_domain_maturity_v23,
    is_marketplace_platform,
    resolve_prospect_timezone_and_locale_v23,
    verify_eu_entity_vies_and_gleif,
)
from .regression_gate import run_startup_regression_gate
from .scraper import (
    _is_safe_domain,
    classify_failure_status,
    close_shared_playwright_browser,
    configure_pw,
    discover_links_from_sitemap,
    extract_semantic_contact_links_from_html,
    extract_tls_x509_der_intel,
    fetch_gtm_scripts,
    fetch_html_playwright_fallback,
    fetch_html_safely,
    fetch_store_and_well_known_bundle,
    fetch_waf_bypass_or_wayback_legal,
    get_clean_canonical_domain,
    is_allowed_by_robots,
    is_dynamic_hopeless_waf,
    is_playwright_available,
    is_soft_404_page,
    load_robots_rules,
    parse_html_sync,
    prepare_domains,
    pw_locale_for_region,
)
from .tech_detector import (
    build_evidence_json_from_cached_record,
    build_summary_from_cached_record,
    decode_apple_pay_merchant_association_safe,
    detect_broken_attribution_red_flags,
    detect_tech_with_evidence,
    extract_shopify_pim_and_logistics_signals,
    fetch_google_ads_transparency_intel_v23_1,
    fetch_public_ats_hiring_intel,
)

SDR_COMPACT_COLUMNS = (
    'canonical_domain',
    'sales_actionability_class',
    'contact_quality_tier_human',
    'data_quality_score',
    'company_category',
    'decision_maker_name',
    'decision_maker_role',
    'decision_maker_linkedin_url',
    'best_email',
    'best_email_type',
    'primary_phone',
    'detected_signals',
    'tech_scan_completeness',
    'sales_hook',
    'sales_opportunity',
    'next_best_action',
    'decision_maker_search_query',
    'gdpr_jurisdiction',
    'data_confidence_warning',
)

LOW_VALUE_LIVE_EMAIL_TYPES = {
    'customer_support_inbox',
    'legal_or_hr_inbox',
    'pr_and_media_inbox',
    'influencer_gifting_inbox',
    'department_or_general_inbox',
    'admissions_or_department_inbox',
}


# ==============================================================================
# v23.1 Complete: Адаптивний OSINT Budget Runner, Дедуплікатор Холдингів та Standby Server
# ==============================================================================

async def run_osint_tasks_with_time_budget(
    named_coros: Dict[str, Coroutine[Any, Any, Any]],
    budget_seconds: float = 3.0
) -> Dict[str, Any]:
    if not named_coros:
        return {}
    task_map = {name: asyncio.create_task(coro) for name, coro in named_coros.items()}
    results: Dict[str, Any] = {name: None for name in named_coros}
    pending = set(task_map.values())
    try:
        done, pending = await asyncio.wait(
            task_map.values(),
            timeout=budget_seconds,
            return_when=asyncio.ALL_COMPLETED,
        )
        for name, task in task_map.items():
            if task in done and not task.cancelled() and task.exception() is None:
                results[name] = task.result()
    finally:
        for p_task in pending:
            if not p_task.done():
                p_task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    return results


class SafeBatchHoldingDeduplicator:
    def __init__(self) -> None:
        self._seen_keys: Dict[str, str] = {}

    def check_and_register(self, record: Dict[str, Any], brand_root: str) -> str:
        domain = str(record.get("canonical_domain") or "")
        email = str(record.get("best_email") or "").strip().lower()
        dm_name = str(record.get("decision_maker_name") or "").strip().lower()
        myshopify = str(record.get("myshopify_canonical_domain") or "").strip().lower()

        lookup_keys = []
        if email and "@" in email and not email.startswith(("info@", "contact@", "support@", "hello@", "office@")):
            lookup_keys.append(f"email:{email}")
        if dm_name and len(dm_name) >= 5 and brand_root:
            lookup_keys.append(f"dm:{dm_name}:{brand_root.lower()}")
        if myshopify:
            lookup_keys.append(f"shop:{myshopify}")

        for k in lookup_keys:
            if k in self._seen_keys and self._seen_keys[k] != domain:
                return f"HOLDING_DUPLICATE_SKIP_OUTREACH (primary: {self._seen_keys[k]})"
        for k in lookup_keys:
            self._seen_keys.setdefault(k, domain)
        return "PRIMARY_OUTREACH_TARGET"


async def start_standby_http_server(enrich_single_domain_func: Callable[[str, str], Any]) -> None:
    if not _AIOHTTP_AVAILABLE or web is None:
        raise RuntimeError("aiohttp is required for Standby HTTP Server mode")
    port = int(os.environ.get("ACTOR_WEB_SERVER_PORT") or os.environ.get("APIFY_CONTAINER_PORT") or "8080")

    async def handle_request(request: web.Request) -> web.Response:
        if request.headers.get("x-apify-container-server-readiness-probe"):
            return web.json_response({"status": "ready", "version": "23.1"}, status=200)

        domain = (request.query.get("domain") or "").strip()
        if not domain:
            if request.path == "/":
                return web.json_response({"status": "ready", "version": "23.1"}, status=200)
            return web.json_response({"error": "Missing required query parameter: domain"}, status=400)

        reg_dom, _ = extract_etld_plus_one(domain)
        is_allowed, reason = await check_hostname_ssrf_and_dns_async(reg_dom)
        if not is_allowed and reason == "ssrf_blocked":
            return web.json_response({"error": "Blocked private or non-public target host"}, status=400)

        scan_mode = (request.query.get("scanMode") or "fast_http_only").strip()
        record = await enrich_single_domain_func(domain, scan_mode)
        return web.json_response(record, status=200)

    app = web.Application()
    app.router.add_get("/", handle_request)
    app.router.add_get("/enrich", handle_request)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    await asyncio.Event().wait()


# ==============================================================================
# Core Formatting, Cache Helpers & Domain Pipeline
# ==============================================================================

def format_record_for_output_view(record: dict, output_view: str = 'full_audit') -> dict:
    if (output_view or 'full_audit').lower().strip() == 'sdr_compact':
        compact = {col: record.get(col) for col in SDR_COMPACT_COLUMNS}
        opp = str(record.get('sales_opportunity') or '')
        compact['pain_point_detected'] = opp.split(' | ')[0] if 'Red Flag' in opp else None
        note = str(record.get('email_source_note') or '')
        if 'DM Email Pattern Hypothesis (MX Valid): ' in note:
            compact['predicted_dm_email'] = note.split('DM Email Pattern Hypothesis (MX Valid): ', 1)[1].split(',')[0].strip()
        else:
            compact['predicted_dm_email'] = None
        return compact
    return record


def _is_cache_record_fresh(c_rec: dict | None, max_cache_age_days: int) -> bool:
    if not isinstance(c_rec, dict) or max_cache_age_days <= 0:
        return False
    prev_time = c_rec.get('last_checked_at')
    if not prev_time:
        return True
    age_days = compute_snapshot_age_days(prev_time)
    if age_days is not None and age_days > max_cache_age_days:
        return False
    return True


async def _send_completion_webhook(
    client: AsyncSession,
    webhook_url: str | None,
    run_telemetry: dict,
    records: list[dict],
) -> None:
    if not webhook_url or not isinstance(webhook_url, str):
        return
    clean_wh = webhook_url.strip()
    if not clean_wh.startswith(('https://', 'http://')):
        return
    parsed_wh = urlparse(clean_wh)
    if not _is_safe_domain(parsed_wh.netloc):
        Actor.log.warning(f'[WEBHOOK SKIP] Unsafe or internal webhook host rejected: {parsed_wh.netloc}')
        return

    payload = {
        'event': 'b2b_lead_pixel_enricher.run_completed',
        'version': '23.1',
        'summary': run_telemetry,
        'records_count': len(records),
        'sales_ready_count': sum(1 for r in records if r.get('sales_actionability_class') == 'sales_ready'),
        'partnership_count': sum(1 for r in records if r.get('sales_actionability_class') in ('partnership', 'partner_agency')),
        'records': records[:250],
    }
    try:
        resp = await client.post(
            clean_wh,
            headers={'Content-Type': 'application/json'},
            json=payload,
            timeout=10.0,
            proxy=None,
        )
        Actor.log.info(f'[WEBHOOK SENT] POST {clean_wh} -> HTTP {resp.status_code} ({len(records)} records)')
    except Exception as exc:
        Actor.log.warning(f'[WEBHOOK WARN] Failed to POST to {clean_wh}: {exc}')


async def _get_playwright_proxy_url(proxy_config, domain_key: str) -> str | None:
    if proxy_config is None:
        return None
    try:
        return await proxy_config.new_url(
            session_id=f"pw_{abs(hash(domain_key)) % 100000}"
        )
    except Exception as exc:
        Actor.log.warning(f"[PROXY WARN] Failed to allocate Playwright proxy session for {domain_key}: {exc}")
        return None


def _build_early_abort_record(
    domain_key: str,
    canonical_domain: str,
    aliases_str: str,
    clean_website_url: str,
    fail_status: str,
    short_err_msg: str,
    checked_at: str,
    pw_status_str: str = 'skipped_dns_or_unreachable',
) -> dict:
    cat, cat_conf = classify_company_category(domain_key, '', '', [])
    c_hint = detect_country_hint(canonical_domain, '', '', None, '')
    blocked_jur = derive_gdpr_jurisdiction(canonical_domain, None, c_hint, '')
    blocked_is_eu = blocked_jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')
    verdict = (
        'Disqualified (SSRF / Non-Public Target Blocked)'
        if fail_status == 'ssrf_blocked'
        else 'Unverified (Domain Unreachable / DNS Error)'
    )
    return {
        'input_domain': domain_key,
        'canonical_domain': canonical_domain,
        'aliases': aliases_str,
        'input_was_redirected': False,
        'redirect_chain': None,
        'website_url': clean_website_url,
        'final_redirect_url': clean_website_url,
        'status': fail_status,
        'cached_snapshot_source': f'none (live_{fail_status})',
        'cached_snapshot_age_days': None,
        'error_message': short_err_msg,
        'data_quality_score': 0,
        'sales_readiness_verdict': verdict,
        'sales_actionability_class': derive_sales_actionability_class(verdict, cat),
        'company_category': cat,
        'category_confidence': cat_conf,
        'marketplace_platform': canonical_domain in KNOWN_MARKETPLACE_DOMAINS,
        'marketplace_platform_pollution_detected': False,
        'icp_fit_tier': 'Unverified (Site Unreachable)',
        'technical_signal_strength': None,
        'tech_scan_completeness': 'partial_blocked',
        'tech_rescan_needed': (fail_status != 'ssrf_blocked'),
        'contact_quality_tier': 'Tier F (Site Unreachable)',
        'contact_quality_tier_human': 'No Contact',
        'contact_enrichment_status': fail_status,
        'data_confidence_warning': f'Domain pre-check failed ({fail_status}: {short_err_msg}).',
        'gdpr_eu_domain': blocked_is_eu,
        'gdpr_jurisdiction': blocked_jur,
        'legal_basis_for_processing': None,
        'data_subject_can_request_deletion': True,
        'data_retention_policy_days': 365,
        'personal_data_fields_in_record': f'none ({fail_status})',
        'compliance_note': build_compliance_note(canonical_domain, c_hint),
        'playwright_available': is_playwright_available(),
        'playwright_used': False,
        'playwright_status': pw_status_str,
        'playwright_attempts_count': 0,
        'playwright_paths_attempted': None,
        'page_title': f'[Site {fail_status}: {short_err_msg}]',
        'meta_description': None,
        'best_email': None,
        'email_domain': None,
        'best_email_type': None,
        'email_source_type': None,
        'email_source_note': None,
        'named_email_owner_role_hint': None,
        'email_deliverability_check': None,
        'all_emails_deliverability': None,
        'all_emails_classification': None,
        'email_source_url': None,
        'primary_phone': None,
        'e164_phone': None,
        'phone_availability': 'site_blocked',
        'phone_source_url': None,
        'decision_maker_name': None,
        'decision_maker_role': None,
        'decision_maker_source_url': None,
        'decision_maker_source_type': None,
        'decision_makers_found': None,
        'decision_makers_json': None,
        'decision_maker_linkedin_url': None,
        'decision_maker_search_query': build_linkedin_xray_query(canonical_domain, cat, c_hint),
        'linkedin_url': None,
        'instagram_url': None,
        'facebook_url': None,
        'telegram_url': None,
        'tiktok_url': None,
        'youtube_url': None,
        'social_source_url': None,
        'detected_signals': None,
        'detected_cms': None,
        'consent_mode_likely': None,
        'ga4_detection_confidence': None,
        'has_google_ads_confidence': 'unknown',
        'sales_hook': None,
        'sales_opportunity': f'Scan {fail_status} ({short_err_msg}) — cannot verify stack without access',
        'next_best_action': 'Verify domain spelling / DNS status or use decision_maker_search_query on LinkedIn',
        'technology_evidence_summary': None,
        'technology_evidence': None,
        'technology_evidence_json': None,
        'has_meta_pixel': None,
        'has_tiktok_pixel': None,
        'has_google_ads': None,
        'has_linkedin_pixel': None,
        'has_pinterest_tag': None,
        'has_hubspot': None,
        'has_klaviyo': None,
        'has_ga4': None,
        'has_gtm': None,
        'has_sgtm': None,
        'all_ga4_ids': None,
        'all_ga4_ids_count': None,
        'detected_technologies': None,
        'all_emails': None,
        'all_phones': None,
        'last_checked_at': checked_at,
    }


async def process_domain(
    client: AsyncSession,
    domain_key: str,
    root_url: str,
    initial_aliases: list[str],
    scan_contacts: bool,
    unpack_gtm: bool,
    default_region: str,
    proxy_config,
    cache_store,
    manual_seeds: dict[str, dict],
    thread_pool: ThreadPoolExecutor,
    semaphore: asyncio.Semaphore,
    serper_api_key: str | None = None,
    reoon_api_key: str | None = None,
    millionverifier_api_key: str | None = None,
    max_cache_age_days: int = 30,
    bypass_hopeless_waf: bool = False,
    scan_mode: str = 'full_audit',
    enable_deep_osint: bool = False,
) -> dict:
    checked_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    loop = asyncio.get_running_loop()
    pw_used_flag = False
    is_fast_http_only = (scan_mode or '').lower().strip() == 'fast_http_only'
    pw_status_str = 'disabled_fast_mode' if is_fast_http_only else ('not_needed' if is_playwright_available() else 'disabled')
    pw_attempts_count = 0
    pw_attempted_paths: list[str] = []
    pw_had_timeout_or_block = False
    allow_cache_reads = (cache_store is not None and max_cache_age_days > 0)

    # Фаза 4 (v23.1): Неблокуючий сокет-префільтр SSRF vs DNS (NXDOMAIN) за 0 мс до запуску HTTP/Playwright
    reg_input_dom, _ = extract_etld_plus_one(domain_key)
    check_host = reg_input_dom or domain_key
    is_host_allowed, host_reason = await check_hostname_ssrf_and_dns_async(check_host, timeout=1.5)
    if not is_host_allowed:
        aliases_str_early = '; '.join(initial_aliases) if initial_aliases else domain_key
        if host_reason == 'ssrf_blocked':
            Actor.log.warning(f'[SSRF BLOCKED] {domain_key} rejected by socket pre-filter')
            return _build_early_abort_record(
                domain_key, domain_key, aliases_str_early, f'https://{domain_key}/',
                'ssrf_blocked', 'Blocked private or non-public target IP/host', checked_at,
                pw_status_str='skipped_ssrf_blocked'
            )
        if host_reason == 'dns_error' and domain_key not in manual_seeds:
            Actor.log.info(f'[DNS ERROR FAST-ABORT] {domain_key} NXDOMAIN; skipping HTTP and Playwright')
            return _build_early_abort_record(
                domain_key, domain_key, aliases_str_early, f'https://{domain_key}/',
                'dns_error', 'Domain does not resolve in DNS (NXDOMAIN)', checked_at,
                pw_status_str='skipped_dns_or_unreachable'
            )

    async with semaphore:
        status, html, final_url, err_msg = await fetch_html_safely(
            client, root_url, proxy_config=proxy_config
        )

    short_err_msg = truncate_error_msg(err_msg)
    canonical_domain = get_clean_canonical_domain(final_url, domain_key)
    _, brand_root = extract_etld_plus_one(canonical_domain)
    if not brand_root:
        brand_root = canonical_domain.split('.')[0].lower() if canonical_domain else ''

    prelim_fail_class = classify_failure_status(status, err_msg) if (status == 0 or status >= 400) else 'ok'
    is_non_recoverable_net_err = (status == 0 and prelim_fail_class in ('dns_error', 'unreachable', 'ssl_error'))

    is_pw_hopeless = (
        is_fast_http_only
        or is_non_recoverable_net_err
        or (
            not bypass_hopeless_waf
            and (
                canonical_domain in KNOWN_PW_HOPELESS
                or domain_key in KNOWN_PW_HOPELESS
                or is_dynamic_hopeless_waf(err_msg)
            )
        )
    )

    if (status == 0 or status in (403, 429, 503)) and is_playwright_available():
        if is_pw_hopeless:
            if is_non_recoverable_net_err:
                pw_status_str = f'skipped_{prelim_fail_class}'
            elif is_fast_http_only:
                pw_status_str = 'skipped_fast_http_only'
            else:
                pw_status_str = 'skipped_hopeless_waf'
            pw_had_timeout_or_block = True
            Actor.log.info(f'[PW SKIP] {canonical_domain} ({pw_status_str}: {short_err_msg}); skipping Playwright rescue')
        else:
            rescue_url = clean_url_port(root_url) or root_url
            pw_proxy = await _get_playwright_proxy_url(proxy_config, canonical_domain)
            rescue_locale = pw_locale_for_region(guess_region_from_domain(canonical_domain) or default_region)
            Actor.log.info(
                f'HTTP/Curl status={status} for {canonical_domain} ({short_err_msg}); '
                f'attempting Playwright rescue on {rescue_url} (locale={rescue_locale}, start_res={status != 0})'
            )
            pw_attempted_paths.append(rescue_url)
            (
                pw_rescue_html,
                pw_rescue_url,
                pw_rescue_status,
                pw_rescue_inc,
                pw_rescue_attempts
            ) = await fetch_html_playwright_fallback(
                rescue_url,
                proxy_url=pw_proxy,
                locale=rescue_locale,
                max_attempts=PW_GLOBAL_MAX_ATTEMPTS_PER_DOMAIN,
                start_residential=(status != 0),
            )
            pw_attempts_count += pw_rescue_attempts
            pw_rescue_status = normalize_pw_empty_status(pw_rescue_status, pw_rescue_html)
            if pw_rescue_status == 'rendered' and pw_rescue_html:
                Actor.log.info(f'Playwright rescue succeeded for {canonical_domain} ({len(pw_rescue_html)} bytes)!')
                status = 200
                html = pw_rescue_html
                final_url = pw_rescue_url
                err_msg = ''
                short_err_msg = ''
                pw_used_flag = True
                pw_status_str = 'rendered'
                canonical_domain = get_clean_canonical_domain(final_url, domain_key)
                _, brand_root = extract_etld_plus_one(canonical_domain)
                if pw_rescue_inc and len(pw_rescue_html) < 15_000:
                    pw_had_timeout_or_block = True
            else:
                pw_status_str = pw_rescue_status
                pw_had_timeout_or_block = True

    parsed_final = urlparse(final_url)
    scheme = parsed_final.scheme or 'https'
    clean_website_url = f'{scheme}://{canonical_domain}/'
    normalized_final_redirect = clean_url_port(final_url) or clean_website_url
    canonical_kv_key = sanitize_kv_key(canonical_domain)
    input_kv_key = sanitize_kv_key(domain_key)
    evergreen_kv_key = f'evergreen_{canonical_kv_key}'

    all_alias_items = list(initial_aliases)
    if canonical_domain not in all_alias_items:
        all_alias_items.append(canonical_domain)
    aliases_str = '; '.join(all_alias_items)

    non_canonical_aliases = [a for a in all_alias_items if a != canonical_domain]
    if domain_key == canonical_domain and not non_canonical_aliases:
        was_redirected = False
        redirect_chain_str = None
    elif domain_key != canonical_domain:
        was_redirected = True
        redirect_chain_str = f'{domain_key} → {canonical_domain}'
    elif non_canonical_aliases and non_canonical_aliases[0] != canonical_domain:
        was_redirected = True
        redirect_chain_str = f'{non_canonical_aliases[0]} → {canonical_domain}'
    else:
        was_redirected = False
        redirect_chain_str = None

    # Якщо сайт заблокований WAF, перед поверненням помилки пробуємо Lateral SAN / Wayback Machine CDX bypass (v23.1)
    if (status == 0 or status >= 400 or not html) and not is_non_recoverable_net_err and enable_deep_osint:
        try:
            tls_pre = await extract_tls_x509_der_intel(canonical_domain, timeout=1.8)
            wb_html, wb_src = await fetch_waf_bypass_or_wayback_legal(
                client, canonical_domain, tls_pre.get('prioritized_bypass_hosts') or []
            )
            if wb_html and len(wb_html) > 600:
                Actor.log.info(f'[WAF BYPASS RECOVERY] {canonical_domain} recovered via {wb_src}')
                html = wb_html
                status = 200
        except Exception:
            pass

    if status == 0 or status >= 400 or not html:
        fail_status = classify_failure_status(status, err_msg)
        seed_match = manual_seeds.get(canonical_domain) or manual_seeds.get(domain_key)
        if isinstance(seed_match, dict) and max_cache_age_days > 0:
            _seed_hint = detect_country_hint(
                canonical_domain,
                seed_match.get('page_title') or '',
                seed_match.get('meta_description') or '',
                seed_match.get('primary_phone'),
                ''
            )
            _seed_jur = derive_gdpr_jurisdiction(canonical_domain, seed_match.get('primary_phone'), _seed_hint, '')
            _seed_is_eu = _seed_jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')
            seeded_rec = build_manual_seed_record(
                seed_match, domain_key, canonical_domain, aliases_str, clean_website_url,
                normalized_final_redirect, was_redirected, redirect_chain_str, _seed_is_eu,
                fail_status, short_err_msg, checked_at, is_playwright_available()
            )
            _seed_tech_count = len([x.strip() for x in (seeded_rec.get('detected_technologies') or '').split(';') if x.strip()])
            seeded_rec['has_google_ads_confidence'] = compute_google_ads_confidence(
                seeded_rec.get('has_google_ads'), seeded_rec.get('tech_scan_completeness', 'full'),
                _seed_tech_count, bool(seeded_rec.get('consent_mode_likely')), True
            )
            seeded_rec['contact_quality_tier_human'] = derive_human_contact_tier(
                seeded_rec.get('contact_quality_tier'), seeded_rec.get('company_category', '')
            )
            seeded_rec['sales_actionability_class'] = derive_sales_actionability_class(
                seeded_rec.get('sales_readiness_verdict'), seeded_rec.get('company_category', '')
            )
            seeded_rec['gdpr_jurisdiction'] = _seed_jur
            seeded_rec['legal_basis_for_processing'] = derive_legal_basis_for_processing(
                canonical_domain,
                _seed_hint,
                bool(seeded_rec.get('best_email') or seeded_rec.get('decision_maker_name') or seeded_rec.get('primary_phone')),
            )
            seeded_rec['data_subject_can_request_deletion'] = True
            seeded_rec['data_retention_policy_days'] = 365
            seeded_rec['personal_data_fields_in_record'] = derive_pii_fields(
                seeded_rec.get('best_email'), seeded_rec.get('best_email_type'),
                seeded_rec.get('decision_maker_name'), seeded_rec.get('primary_phone'),
                seeded_rec.get('decision_maker_linkedin_url')
            )
            seeded_rec['compliance_note'] = build_compliance_note(canonical_domain, _seed_hint)
            seeded_rec.setdefault('all_ga4_ids_count', 1 if seeded_rec.get('all_ga4_ids') else None)
            return seeded_rec

        is_tier1_marketplace = canonical_domain in KNOWN_MARKETPLACE_DOMAINS
        cache_keys_order = (
            (evergreen_kv_key, canonical_kv_key, input_kv_key)
            if is_tier1_marketplace
            else (canonical_kv_key, input_kv_key, evergreen_kv_key)
        )
        if allow_cache_reads:
            for candidate_key in cache_keys_order:
                try:
                    cached_record = await cache_store.get_value(candidate_key)
                    is_evergreen = (candidate_key == evergreen_kv_key)
                    if not isinstance(cached_record, dict):
                        continue
                    if not is_evergreen and cached_record.get('_schema', 0) < MIN_COMPATIBLE_CACHE_SCHEMA:
                        continue
                    if cached_record.get('status') not in ('success', 'no_contacts_found'):
                        continue

                    cached_record = heal_poisoned_cache_record(canonical_domain, cached_record) or cached_record

                    prev_time = cached_record.get('last_checked_at', '')
                    age_days = compute_snapshot_age_days(prev_time)
                    effective_max_age = min(max_cache_age_days, EVERGREEN_MAX_AGE_DAYS)
                    if age_days is not None and age_days > effective_max_age:
                        Actor.log.info(
                            f'[CACHE EXPIRED] {canonical_domain} snapshot age={age_days}d exceeds maxCacheAgeDays={effective_max_age}d'
                        )
                        continue

                    cached_copy = {k: v for k, v in cached_record.items() if not k.startswith('_')}
                    _cached_eff_reg = resolve_effective_phone_region(canonical_domain, default_region, '')
                    c_p, c_e164, c_all_p = sanitize_cached_phones(
                        cached_copy.get('primary_phone'),
                        cached_copy.get('all_phones'),
                        _cached_eff_reg,
                    )
                    cached_copy['primary_phone'] = c_p
                    cached_copy['e164_phone'] = c_e164
                    cached_copy['all_phones'] = c_all_p
                    if not c_p:
                        cached_copy['phone_source_url'] = None

                    cached_copy['input_domain'] = domain_key
                    cached_copy['canonical_domain'] = canonical_domain
                    cached_copy['aliases'] = aliases_str
                    cached_copy['input_was_redirected'] = was_redirected
                    cached_copy['redirect_chain'] = redirect_chain_str
                    base_st = 'success' if (cached_copy.get('best_email') or c_p) else 'no_contacts_found'
                    cached_copy['status'] = f"cached_{base_st} (live_{fail_status})"
                    cached_copy['cached_snapshot_source'] = 'evergreen_cache' if is_evergreen else 'versioned_cache'
                    cached_copy['cached_snapshot_age_days'] = age_days if age_days is not None else 0
                    cached_copy['error_message'] = truncate_error_msg(
                        f'Live {short_err_msg}; snapshot from {prev_time or "prior run"}'
                    )
                    cached_copy['data_confidence_warning'] = (
                        f'Note: Tech stack recovered from verified cache; live scan blocked ({short_err_msg}) — '
                        f'do not cite as current state (source={cached_copy["cached_snapshot_source"]}, age={cached_copy["cached_snapshot_age_days"]}d).'
                    )
                    cached_copy['playwright_available'] = is_playwright_available()
                    cached_copy['playwright_used'] = False
                    cached_copy['playwright_status'] = (
                        pw_status_str if (pw_attempts_count > 0 or is_pw_hopeless) else 'not_attempted_cached_fallback'
                    )
                    cached_copy['playwright_attempts_count'] = pw_attempts_count
                    cached_copy['playwright_paths_attempted'] = (
                        '; '.join(pw_attempted_paths) if pw_attempted_paths else None
                    )
                    cached_copy['phone_availability'] = 'public' if cached_copy.get('primary_phone') else 'not_public'

                    c_fallback_src = cached_copy.get('decision_maker_source_url') or clean_website_url
                    c_dm_name, c_dm_role, c_dms_str = sanitize_cached_dms(
                        cached_copy.get('decision_maker_name'),
                        cached_copy.get('decision_maker_role'),
                        cached_copy.get('decision_makers_found'),
                        brand_root,
                        cached_copy.get('decision_maker_linkedin_url'),
                        fallback_source_url=c_fallback_src,
                    )
                    cached_copy['decision_maker_name'] = c_dm_name
                    cached_copy['decision_maker_role'] = c_dm_role
                    cached_copy['decision_makers_found'] = c_dms_str
                    cached_copy['decision_makers_json'] = build_decision_makers_json_from_summary(
                        c_dms_str, cached_copy.get('decision_maker_linkedin_url'), c_fallback_src
                    )

                    cached_copy.setdefault('detected_cms', None)
                    cached_copy.setdefault('consent_mode_likely', None)
                    cached_copy.setdefault('ga4_detection_confidence', None)
                    cached_copy.setdefault('all_ga4_ids_count', None)
                    cached_copy.setdefault('tech_scan_completeness', 'partial_cached')
                    cached_copy.setdefault('category_confidence', 'high')
                    _c_is_mp = is_marketplace_platform(
                        canonical_domain,
                        cached_copy.get('page_title') or '',
                        cached_copy.get('meta_description') or ''
                    )
                    cached_copy['marketplace_platform'] = _c_is_mp
                    cached_copy.setdefault('marketplace_platform_pollution_detected', False)
                    cached_copy.setdefault('email_source_type', None)
                    cached_copy.setdefault('email_source_note', None)
                    raw_c_dm_src_type = classify_dm_source_type(c_fallback_src) if c_dm_name else None
                    if raw_c_dm_src_type and not raw_c_dm_src_type.endswith('_cached'):
                        raw_c_dm_src_type = f'{raw_c_dm_src_type}_cached'
                    cached_copy['decision_maker_source_type'] = raw_c_dm_src_type
                    cached_copy.setdefault('named_email_owner_role_hint', None)

                    normalize_cached_record_booleans(cached_copy)
                    cached_copy['technology_evidence_summary'] = build_summary_from_cached_record(cached_copy)
                    cached_copy['technology_evidence_json'] = build_evidence_json_from_cached_record(cached_copy, source_label='cache')

                    _cached_all_emails = (cached_copy.get('all_emails') or cached_copy.get('best_email') or '').split(';')
                    _cached_emails_list = [e.strip() for e in _cached_all_emails if e.strip()]
                    if _cached_emails_list:
                        cached_copy['best_email_type'] = classify_email_type(cached_copy.get('best_email'), brand_root)
                        cached_copy['all_emails_classification'] = '; '.join(
                            f'{em} ({classify_email_type(em, brand_root)})' for em in _cached_emails_list
                        )
                        _deliv = cached_copy.get('email_deliverability_check') or 'not_checked'
                        _existing_all_deliv = cached_copy.get('all_emails_deliverability') or ''
                        if _existing_all_deliv and '@' in _existing_all_deliv and ': ' in _existing_all_deliv:
                            cached_copy['all_emails_deliverability'] = _existing_all_deliv
                        else:
                            cached_copy['all_emails_deliverability'] = '; '.join(
                                f'{em}: {_deliv}' for em in _cached_emails_list[:3]
                            )
                    else:
                        cached_copy['all_emails_classification'] = None
                        cached_copy['all_emails_deliverability'] = None

                    has_cached_tech = bool(cached_copy.get('has_gtm') or cached_copy.get('has_ga4'))
                    cached_copy['tech_rescan_needed'] = True

                    if cached_copy.get('tech_scan_completeness', 'full') == 'full':
                        cached_copy['tech_scan_completeness'] = 'partial_cached'

                    _cached_tech_list = [x.strip() for x in (cached_copy.get('detected_technologies') or '').split(';') if x.strip()]
                    _cached_tech_count = len(_cached_tech_list)
                    cached_copy['has_google_ads_confidence'] = compute_google_ads_confidence(
                        cached_copy.get('has_google_ads'),
                        cached_copy.get('tech_scan_completeness', 'partial_cached'),
                        _cached_tech_count,
                        bool(cached_copy.get('consent_mode_likely')),
                        False
                    )

                    _c_hint = detect_country_hint(
                        canonical_domain, cached_copy.get('page_title') or '',
                        cached_copy.get('meta_description') or '', cached_copy.get('primary_phone'), ''
                    )
                    _jur = derive_gdpr_jurisdiction(canonical_domain, cached_copy.get('primary_phone'), _c_hint, '')
                    cached_copy['gdpr_jurisdiction'] = _jur
                    cached_copy['gdpr_eu_domain'] = _jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')
                    _cat, _cat_conf = classify_company_category(
                        canonical_domain,
                        cached_copy.get('page_title') or '',
                        cached_copy.get('meta_description') or '',
                        _cached_tech_list,
                        ''
                    )
                    cached_copy['company_category'] = _cat
                    cached_copy['category_confidence'] = _cat_conf

                    _c_tech_info = {
                        'detected_technologies_list': _cached_tech_list,
                        'detected_cms_list': [x.strip() for x in (cached_copy.get('detected_cms') or '').split(';') if x.strip()],
                        'detected_cms': cached_copy.get('detected_cms'),
                        'has_gtm': cached_copy.get('has_gtm'),
                        'has_sgtm': cached_copy.get('has_sgtm'),
                        'has_ga4': cached_copy.get('has_ga4'),
                        'has_meta_pixel': cached_copy.get('has_meta_pixel'),
                        'has_google_ads': cached_copy.get('has_google_ads'),
                        'has_tiktok_pixel': cached_copy.get('has_tiktok_pixel'),
                        'has_linkedin_pixel': cached_copy.get('has_linkedin_pixel'),
                        'has_pinterest_tag': cached_copy.get('has_pinterest_tag'),
                        'has_hubspot': cached_copy.get('has_hubspot'),
                        'has_klaviyo': cached_copy.get('has_klaviyo'),
                        'has_cookie_banner': cached_copy.get('consent_mode_likely'),
                        'tech_scan_completeness': cached_copy.get('tech_scan_completeness', 'partial_cached'),
                    }
                    (
                        _c_verdict, _c_icp, _c_tech_sig, _c_contact_tier,
                        _c_enrich_st, _, _c_det_sig, _c_opp, _c_next_act
                    ) = evaluate_qualification_v180(
                        _cat, _c_tech_info, cached_copy.get('best_email'), cached_copy.get('best_email_type'),
                        cached_copy.get('primary_phone'), c_dm_name, c_dm_role,
                        cached_copy.get('decision_maker_linkedin_url'), False,
                        cached_copy.get('decision_maker_source_type'), cached_copy.get('linkedin_url'),
                        bool(cached_copy.get('marketplace_platform_pollution_detected')),
                        cached_copy['playwright_status'],
                        is_mp_platform=_c_is_mp,
                    )
                    cached_copy['sales_readiness_verdict'] = _c_verdict
                    cached_copy['icp_fit_tier'] = _c_icp
                    cached_copy['technical_signal_strength'] = _c_tech_sig
                    cached_copy['contact_quality_tier'] = _c_contact_tier
                    cached_copy['contact_enrichment_status'] = _c_enrich_st
                    cached_copy['detected_signals'] = _c_det_sig
                    cached_copy['sales_opportunity'] = _c_opp
                    cached_copy['next_best_action'] = _c_next_act

                    cached_copy['contact_quality_tier_human'] = derive_human_contact_tier(
                        cached_copy.get('contact_quality_tier'), _cat
                    )
                    cached_copy['sales_actionability_class'] = derive_sales_actionability_class(
                        cached_copy.get('sales_readiness_verdict'), _cat
                    )
                    cached_copy['data_quality_score'] = compute_data_quality_score(
                        cached_copy.get('contact_quality_tier'), _cached_tech_count,
                        cached_copy.get('decision_maker_name'), cached_copy.get('decision_maker_linkedin_url'),
                        cached_copy.get('primary_phone'), cached_copy.get('tech_scan_completeness', 'partial_cached'),
                        True, company_category=_cat, is_manual_seed=False,
                        is_same_person_email=verify_person_email_match(cached_copy.get('decision_maker_name'), cached_copy.get('best_email'))
                    )
                    cached_copy['sales_hook'] = build_sales_hook(
                        canonical_domain, _cat, _c_tech_info,
                        cached_copy.get('decision_maker_name'), cached_copy.get('decision_maker_role'),
                        cached_copy.get('decision_maker_linkedin_url'), cached_copy.get('best_email'),
                        is_eu_gdpr=cached_copy['gdpr_eu_domain'],
                        pw_used=False,
                        best_email_type=cached_copy.get('best_email_type'),
                    )
                    cached_copy['legal_basis_for_processing'] = derive_legal_basis_for_processing(
                        canonical_domain,
                        _c_hint,
                        bool(cached_copy.get('best_email') or cached_copy.get('decision_maker_name') or cached_copy.get('primary_phone')),
                    )
                    cached_copy['data_subject_can_request_deletion'] = True
                    cached_copy['data_retention_policy_days'] = 365
                    cached_copy['personal_data_fields_in_record'] = derive_pii_fields(
                        cached_copy.get('best_email'), cached_copy.get('best_email_type'),
                        cached_copy.get('decision_maker_name'), cached_copy.get('primary_phone'),
                        cached_copy.get('decision_maker_linkedin_url')
                    )
                    cached_copy['compliance_note'] = build_compliance_note(canonical_domain, _c_hint)

                    if not has_cached_tech and (cached_copy.get('best_email') or cached_copy.get('primary_phone')):
                        c_contact = cached_copy.get('best_email') or cached_copy.get('primary_phone')
                        cached_copy['next_best_action'] = (
                            f'Cached contact ({c_contact}) available, but tech stack unverified due to live {short_err_msg}; '
                            f'retry with residential proxy to confirm GA4/GTM or start warm gatekeeper outreach now'
                        )
                    return cached_copy
                except Exception:
                    pass

        return _build_early_abort_record(
            domain_key, canonical_domain, aliases_str, clean_website_url,
            fail_status, short_err_msg, checked_at,
            pw_status_str=pw_status_str if (pw_attempts_count > 0 or is_pw_hopeless) else 'not_attempted_site_blocked'
        )

    effective_region = resolve_effective_phone_region(canonical_domain, default_region, html)
    is_pw_hopeless = (
        is_fast_http_only
        or (
            not bypass_hopeless_waf
            and (
                canonical_domain in KNOWN_PW_HOPELESS
                or domain_key in KNOWN_PW_HOPELESS
                or is_dynamic_hopeless_waf(err_msg)
            )
        )
    )

    (
        page_title, meta_desc, main_text, email_sources,
        phones_with_source, socials_with_source, contact_links
    ) = await loop.run_in_executor(
        thread_pool, parse_html_sync, html, normalized_final_redirect, effective_region
    )

    homepage_was_soft_404 = is_soft_404_page(html, page_title)
    if homepage_was_soft_404:
        page_title = ''
        meta_desc = ''

    async with semaphore:
        if unpack_gtm:
            gtm_ids, gtm_js = await fetch_gtm_scripts(client, html)
        else:
            gtm_ids = sorted({m.upper() for m in GTM_ID_REGEX.findall(html) if is_valid_gtm_id(m)})
            gtm_js = ''

        tech_info = detect_tech_with_evidence(html, gtm_js, gtm_ids, normalized_final_redirect, 'full')

        phone_map: dict[str, tuple[int, str]] = {}
        for p, sc, src in phones_with_source:
            if p not in phone_map or sc > phone_map[p][0]:
                phone_map[p] = (sc, src)

        pages_with_urls = [(normalized_final_redirect, html, main_text)]
        base_root = f"{scheme}://{re.sub(r':\d+$', '', parsed_final.netloc) or canonical_domain}"
        disallowed_paths, crawl_delay = await load_robots_rules(client, base_root)

        if scan_contacts and not contact_links:
            contact_links = await discover_links_from_sitemap(client, base_root)

        if scan_contacts and effective_region in ('DE', 'AT', 'CH'):
            if not any('impressum' in u.lower() for u in contact_links):
                contact_links = [f'{base_root}/impressum'] + list(contact_links)

        if scan_contacts and contact_links:
            allowed_sub_links = sorted(
                [u for u in contact_links if is_allowed_by_robots(u, disallowed_paths) and not DM_SOURCE_BLACKLIST.search(urlparse(u).path)],
                key=contact_link_priority
            )
            impressum_403_triggered = False
            for sub_url in allowed_sub_links[:4]:
                await asyncio.sleep(crawl_delay)
                sub_status, sub_html, sub_final_url, _ = await fetch_html_safely(
                    client, sub_url, proxy_config=proxy_config, timeout=8.0, retries=2
                )
                if 200 <= sub_status < 400 and sub_html:
                    sub_title, sub_desc, sub_text, sub_e, sub_p, sub_s, _ = await loop.run_in_executor(
                        thread_pool, parse_html_sync, sub_html, sub_final_url, effective_region
                    )
                    if is_soft_404_page(sub_html, sub_title):
                        continue
                    if homepage_was_soft_404:
                        page_title = page_title or sub_title
                        meta_desc = meta_desc or sub_desc
                    pages_with_urls.append((sub_final_url, sub_html, sub_text))
                    for em, src in sub_e.items():
                        email_sources.setdefault(em, src)
                    for p, sc, src in sub_p:
                        if p not in phone_map or sc > phone_map[p][0]:
                            phone_map[p] = (sc, src)
                    for k, v in sub_s.items():
                        socials_with_source.setdefault(k, v)
                elif 'impressum' in sub_url.lower() and not impressum_403_triggered:
                    impressum_403_triggered = True
                    sitemap_links = await discover_links_from_sitemap(client, base_root)
                    for sm_u in sitemap_links:
                        if sm_u not in allowed_sub_links and is_allowed_by_robots(sm_u, disallowed_paths):
                            s_st, s_ht, s_fin, _ = await fetch_html_safely(
                                client, sm_u, proxy_config=proxy_config, timeout=7.0, retries=1
                            )
                            if 200 <= s_st < 400 and s_ht:
                                st_t, _, st_txt, st_e, st_p, st_s, _ = await loop.run_in_executor(
                                    thread_pool, parse_html_sync, s_ht, s_fin, effective_region
                                )
                                if not is_soft_404_page(s_ht, st_t):
                                    pages_with_urls.append((s_fin, s_ht, st_txt))
                                    for em, src in st_e.items():
                                        email_sources.setdefault(em, src)
                                    for p, sc, src in st_p:
                                        if p not in phone_map or sc > phone_map[p][0]:
                                            phone_map[p] = (sc, src)
                                    for k, v in st_s.items():
                                        socials_with_source.setdefault(k, v)
                                    break

    prelim_clean_emails, _ = rank_and_clean_emails(email_sources, canonical_domain)
    has_actionable_contacts = bool(prelim_clean_emails or phone_map)
    needs_pw_tech = bool(tech_info['has_cookie_banner'] and not tech_info['has_gtm'] and not tech_info['has_ga4'])
    needs_pw_empty_shell = bool(not page_title and not tech_info['detected_technologies_list'])
    needs_pw_no_tech_at_all = bool(
        not tech_info['detected_technologies_list'] and not tech_info['has_gtm']
        and not tech_info['has_ga4'] and bool(page_title)
    )
    remaining_pw_budget = max(0, PW_GLOBAL_MAX_ATTEMPTS_PER_DOMAIN - pw_attempts_count)

    if is_playwright_available() and not pw_used_flag and remaining_pw_budget > 0 and (
        not has_actionable_contacts or needs_pw_tech or needs_pw_empty_shell or needs_pw_no_tech_at_all
    ):
        if is_pw_hopeless:
            pw_status_str = 'skipped_fast_http_only' if is_fast_http_only else 'skipped_hopeless_waf'
            if not (tech_info['has_ga4'] and tech_info['has_gtm']):
                pw_had_timeout_or_block = True
            Actor.log.info(f'[PW SKIP] {canonical_domain} ({pw_status_str}); skipping Playwright fallback')
        else:
            pw_proxy = await _get_playwright_proxy_url(proxy_config, canonical_domain)
            pw_locale = pw_locale_for_region(effective_region)
            pw_attempted_paths.append(normalized_final_redirect)
            (
                pw_html, pw_url, pw_status_str, pw_incomplete, pw_main_attempts
            ) = await fetch_html_playwright_fallback(
                normalized_final_redirect, proxy_url=pw_proxy, locale=pw_locale, max_attempts=remaining_pw_budget
            )
            pw_attempts_count += pw_main_attempts
            pw_status_str = normalize_pw_empty_status(pw_status_str, pw_html)
            if pw_incomplete or pw_status_str == 'launched_empty_shell':
                pw_had_timeout_or_block = True
            if pw_status_str == 'rendered' and pw_html:
                pw_used_flag = True
                html = pw_html
                pw_title, pw_desc, pw_text, pw_e, pw_p, pw_s, pw_sub_links = await loop.run_in_executor(
                    thread_pool, parse_html_sync, pw_html, pw_url, effective_region
                )
                if not page_title and pw_title and not is_soft_404_page(pw_html, pw_title):
                    page_title = pw_title
                meta_desc = meta_desc or pw_desc
                pages_with_urls.append((pw_url, pw_html, pw_text))
                for em, src in pw_e.items():
                    email_sources.setdefault(em, src)
                for p, sc, src in pw_p:
                    if p not in phone_map or sc > phone_map[p][0]:
                        phone_map[p] = (sc, src)
                for k, v in pw_s.items():
                    socials_with_source.setdefault(k, v)
                if needs_pw_tech or needs_pw_empty_shell or needs_pw_no_tech_at_all:
                    async with semaphore:
                        pw_gtm_ids, pw_gtm_js = await fetch_gtm_scripts(client, pw_html) if unpack_gtm else ([], '')
                    pw_comp = 'partial_timeout' if pw_incomplete else 'full'
                    tech_info = detect_tech_with_evidence(pw_html, pw_gtm_js or gtm_js, pw_gtm_ids or gtm_ids, pw_url, pw_comp)

                after_pw_emails, _ = rank_and_clean_emails(email_sources, canonical_domain)
                remaining_sub_budget = max(0, PW_GLOBAL_MAX_ATTEMPTS_PER_DOMAIN - pw_attempts_count)
                if scan_contacts and not (after_pw_emails or phone_map) and remaining_sub_budget > 0:
                    semantic_pw_links = await loop.run_in_executor(
                        thread_pool, extract_semantic_contact_links_from_html, pw_html, pw_url, canonical_domain
                    )
                    fallback_pw_paths = [
                        f'{base_root}/impressum/', f'{base_root}/kontakt/', f'{base_root}/contacts/',
                        f'{base_root}/en/contact-us/', f'{base_root}/ua/kontakty/', f'{base_root}/about/'
                    ]
                    combined_pw_subs = sorted(
                        list(dict.fromkeys(
                            u for u in (semantic_pw_links + pw_sub_links + fallback_pw_paths)
                            if u != normalized_final_redirect
                        )),
                        key=contact_link_priority
                    )
                    for pw_sub_u in combined_pw_subs[:remaining_sub_budget]:
                        if is_allowed_by_robots(pw_sub_u, disallowed_paths):
                            pw_attempted_paths.append(pw_sub_u)
                            sub_pw_html, sub_pw_final, sub_pw_st, _, sub_pw_tries = await fetch_html_playwright_fallback(
                                pw_sub_u, proxy_url=pw_proxy, locale=pw_locale, accept_consent=False, max_attempts=1
                            )
                            pw_attempts_count += sub_pw_tries
                            if sub_pw_st == 'rendered' and sub_pw_html:
                                s_t, s_d, s_txt, s_e, s_p, s_s, _ = await loop.run_in_executor(
                                    thread_pool, parse_html_sync, sub_pw_html, sub_pw_final, effective_region
                                )
                                if not is_soft_404_page(sub_pw_html, s_t):
                                    page_title = page_title or s_t
                                    meta_desc = meta_desc or s_d
                                    pages_with_urls.append((sub_pw_final, sub_pw_html, s_txt))
                                    for em, src in s_e.items():
                                        email_sources.setdefault(em, src)
                                    for p, sc, src in s_p:
                                        if p not in phone_map or sc > phone_map[p][0]:
                                            phone_map[p] = (sc, src)
                                    for k, v in s_s.items():
                                        socials_with_source.setdefault(k, v)
                                    chk_em, _ = rank_and_clean_emails(email_sources, canonical_domain)
                                    if chk_em or phone_map:
                                        break

    if pw_had_timeout_or_block and not (tech_info['has_ga4'] and tech_info['has_gtm']):
        scan_comp_flag = 'partial_timeout' if ('timeout' in pw_status_str.lower() or 'exceeded' in pw_status_str.lower()) else 'partial_blocked'
        tech_info['tech_scan_completeness'] = scan_comp_flag

    # Двохвильовий OSINT DAG (v23.1 Complete) — опціональний розширений збір з жорстким бюджетом часу
    osint_wave1: dict = {}
    osint_wave2: dict = {}
    if enable_deep_osint:
        w1_budget = 2.2 if is_fast_http_only else 3.2
        osint_wave1 = await run_osint_tasks_with_time_budget(
            {
                'tls': extract_tls_x509_der_intel(canonical_domain, timeout=1.8),
                'dns_intel': run_unified_dns_intelligence_v23(
                    client, canonical_domain, query_doh_json, extract_etld_plus_one, probe_dkim=(not is_fast_http_only)
                ),
                'well_known': fetch_store_and_well_known_bundle(client, canonical_domain, html),
                'ads_rpc': fetch_google_ads_transparency_intel_v23_1(
                    client, canonical_domain, extract_etld_plus_one, INFRA_SAN_DENYLIST
                ),
                'rdap': fetch_rdap_domain_maturity_v23(client, canonical_domain),
            },
            budget_seconds=w1_budget,
        )
        dns_intel_res = osint_wave1.get('dns_intel') or {}
        for sh_tech in dns_intel_res.get('dns_shadow_tech') or []:
            if sh_tech in ('Klaviyo', 'HubSpot') and sh_tech not in tech_info['detected_technologies_list']:
                tech_info['detected_technologies_list'].append(sh_tech)
                tech_info['has_esp_retention'] = True

        wk_res = osint_wave1.get('well_known') or {}
        if wk_res.get('apple_pay_raw'):
            ap_dec = decode_apple_pay_merchant_association_safe(wk_res['apple_pay_raw'])
            for gw in ap_dec.get('psp_gateways') or []:
                if gw not in (tech_info.get('payment_gateways') or []):
                    tech_info.setdefault('payment_gateways', []).append(gw)

    cache_tech_recovered = False
    cache_sources_count = 0
    has_ga4_live_before_cache = bool(tech_info.get('has_ga4'))
    prior_cached_for_safe_write: dict | None = None

    if allow_cache_reads:
        for c_key in (evergreen_kv_key, canonical_kv_key):
            try:
                c_rec = await cache_store.get_value(c_key)
                if _is_cache_record_fresh(c_rec, max_cache_age_days) or canonical_domain in KNOWN_POISONED_CACHE_RECOVERY:
                    c_rec = heal_poisoned_cache_record(canonical_domain, c_rec)
                    if isinstance(c_rec, dict) and (c_rec.get('has_ga4') or c_rec.get('detected_technologies') or c_rec.get('detected_cms')):
                        prior_cached_for_safe_write = c_rec
                        tech_info, cache_tech_recovered, cache_sources_count = merge_missing_techs_from_cache(
                            tech_info, c_rec, pw_used_flag, pw_had_timeout_or_block
                        )
                        break
            except Exception:
                pass
    elif canonical_domain in KNOWN_POISONED_CACHE_RECOVERY and max_cache_age_days > 0:
        healed = heal_poisoned_cache_record(canonical_domain, None)
        if isinstance(healed, dict):
            tech_info, cache_tech_recovered, cache_sources_count = merge_missing_techs_from_cache(
                tech_info, healed, pw_used_flag, pw_had_timeout_or_block
            )

    normalize_tech_info_booleans(tech_info)
    detected_tech_list = tech_info['detected_technologies_list']

    Actor.log.info(
        f"[CACHE DEBUG] {canonical_domain}: has_ga4_live={has_ga4_live_before_cache}, "
        f"comp={tech_info['tech_scan_completeness']}, cache_sources={cache_sources_count}, "
        f"pw_used={pw_used_flag}, pw_had_timeout={pw_had_timeout_or_block}"
    )

    google_ads_conf = compute_google_ads_confidence(
        tech_info.get('has_google_ads'), tech_info.get('tech_scan_completeness', 'full'),
        len(detected_tech_list), bool(tech_info.get('has_cookie_banner')),
        pw_used_flag and not pw_had_timeout_or_block
    )

    ranked_emails_with_src, had_marketplace_pollution = rank_and_clean_emails(email_sources, canonical_domain)
    live_email_set = {em for em, _ in ranked_emails_with_src}

    prelim_best_type = classify_email_type(ranked_emails_with_src[0][0], brand_root) if ranked_emails_with_src else None
    if (not ranked_emails_with_src or prelim_best_type in LOW_VALUE_LIVE_EMAIL_TYPES or not phone_map) and allow_cache_reads:
        for c_key in (canonical_kv_key, evergreen_kv_key, input_kv_key):
            try:
                c_rec = await cache_store.get_value(c_key)
                if _is_cache_record_fresh(c_rec, max_cache_age_days) and (c_rec.get('best_email') or c_rec.get('primary_phone')):
                    if c_rec.get('best_email') and (not ranked_emails_with_src or prelim_best_type in LOW_VALUE_LIVE_EMAIL_TYPES):
                        c_em = clean_escaped_email_prefix(str(c_rec['best_email']))
                        c_src = str(c_rec.get('email_source_url') or clean_website_url)
                        if c_em:
                            email_sources.setdefault(c_em, c_src)
                        for extra_em in str(c_rec.get('all_emails') or '').split(';'):
                            clean_extra = clean_escaped_email_prefix(extra_em)
                            if clean_extra:
                                email_sources.setdefault(clean_extra, c_src)
                        ranked_emails_with_src, had_marketplace_pollution = rank_and_clean_emails(email_sources, canonical_domain)
                    if not phone_map and c_rec.get('primary_phone'):
                        clean_c_phone, _, _ = sanitize_cached_phones(
                            c_rec.get('primary_phone'),
                            c_rec.get('all_phones'),
                            effective_region,
                        )
                        if clean_c_phone:
                            phone_map[clean_c_phone] = (50, str(c_rec.get('phone_source_url') or clean_website_url))
                    break
            except Exception:
                pass

    sorted_phones_with_src = sorted(phone_map.items(), key=lambda item: -item[1][0])[:3]
    best_email = ranked_emails_with_src[0][0] if ranked_emails_with_src else None
    email_source_url = ranked_emails_with_src[0][1] if ranked_emails_with_src else None
    best_email_type = classify_email_type(best_email, brand_root)
    email_source_type, email_source_note = classify_email_source_type_and_note(
        best_email, best_email_type, email_source_url, pages_with_urls
    )
    if best_email and best_email not in live_email_set:
        if email_source_type and not email_source_type.endswith('_cached'):
            email_source_type = f'{email_source_type}_cached'
        if email_source_note and 'cached' not in email_source_note.lower():
            email_source_note = f'{email_source_note} (recovered from prior verified cache)'

    owner_role_hint = extract_named_email_owner_hint(best_email, best_email_type, pages_with_urls)

    email_domain = None
    if best_email and '@' in best_email:
        raw_em_dom = best_email.split('@', 1)[1].lower()
        normalized_em_local = re.sub(r'[._+-]', '', best_email.split('@', 1)[0].lower())
        if raw_em_dom == canonical_domain or raw_em_dom.endswith(f'.{canonical_domain}'):
            email_domain = f'{raw_em_dom} (matches_site)'
        elif raw_em_dom in PUBLIC_WEBMAIL_DOMAINS:
            email_domain = f'{raw_em_dom} (brand_webmail)' if (brand_root and brand_root in normalized_em_local) else f'{raw_em_dom} (public_webmail)'
        elif brand_root and (raw_em_dom.split('.')[0] == brand_root or brand_root in raw_em_dom.split('.')[0]):
            email_domain = f'{raw_em_dom} (brand_alias_domain)'
        else:
            email_domain = f'{raw_em_dom} (external_domain)'

    non_legal_pairs = [(em, src) for em, src in ranked_emails_with_src if classify_email_type(em, brand_root) != 'legal_or_hr_inbox']
    selected_email_pairs = (non_legal_pairs or ranked_emails_with_src)[:5]
    all_emails_list = [em for em, _ in selected_email_pairs]

    _, compliance_dpo_email = filter_poisoned_and_compliance_emails(
        [em for em, _ in ranked_emails_with_src], set()
    )

    top3_pairs = selected_email_pairs[:3]
    if top3_pairs:
        async with semaphore:
            top3_checks = await asyncio.gather(*(verify_email_deliverability_deep(client, em, src) for em, src in top3_pairs))
        deliverability_check = top3_checks[0]
        all_emails_deliverability_str = '; '.join(f'{em}: {chk}' for (em, _), chk in zip(top3_pairs, top3_checks) if chk)
    else:
        deliverability_check = None
        all_emails_deliverability_str = None

    all_emails_classification_str = (
        '; '.join(f'{em} ({classify_email_type(em, brand_root)})' for em in all_emails_list)
        if all_emails_list else None
    )

    primary_phone = sorted_phones_with_src[0][0] if sorted_phones_with_src else None
    e164_phone = re.sub(r'[\s\-()]', '', primary_phone) if primary_phone else None
    phone_availability = 'public' if primary_phone else 'not_public'
    phone_source_url = sorted_phones_with_src[0][1][1] if sorted_phones_with_src else None

    social_source_url = next(
        (socials_with_source[p][1] for p in ('linkedin', 'instagram', 'facebook', 'telegram', 'tiktok', 'youtube') if p in socials_with_source),
        None
    )

    company_category, category_confidence = classify_company_category(
        canonical_domain, page_title, meta_desc, detected_tech_list, html
    )
    is_mp_platform = is_marketplace_platform(canonical_domain, page_title, meta_desc)

    (
        dm_name, dm_role, dm_linkedin_url, dm_source_url, dm_source_is_legal,
        dm_source_type, decision_makers_found_str, decision_makers_json_str
    ) = await loop.run_in_executor(thread_pool, extract_decision_maker_deep, pages_with_urls)

    live_dm_name = dm_name
    dm_was_from_cache = False

    if allow_cache_reads:
        for c_key in (canonical_kv_key, input_kv_key, evergreen_kv_key):
            try:
                c_rec = await cache_store.get_value(c_key)
                if _is_cache_record_fresh(c_rec, max_cache_age_days) and (c_rec.get('decision_maker_name') or c_rec.get('decision_makers_found')):
                    c_dm_li = c_rec.get('decision_maker_linkedin_url') or dm_linkedin_url
                    c_dm_src = c_rec.get('decision_maker_source_url') or dm_source_url or clean_website_url
                    c_dm_name, c_dm_role, c_dms_str = sanitize_cached_dms(
                        c_rec.get('decision_maker_name'), c_rec.get('decision_maker_role'),
                        c_rec.get('decision_makers_found'), brand_root, c_dm_li,
                        fallback_source_url=c_dm_src,
                    )
                    if not c_dm_name and not c_dms_str:
                        continue
                    c_dm_src_type = c_rec.get('decision_maker_source_type') or classify_dm_source_type(c_dm_src)
                    curr_dms_count = (decision_makers_found_str or '').count(';') + (1 if decision_makers_found_str else 0)
                    cached_dms_count = (c_dms_str or '').count(';') + (1 if c_dms_str else 0)

                    if c_dm_li and not dm_linkedin_url and c_dm_name:
                        if not live_dm_name or live_dm_name.lower() != c_dm_name.lower():
                            dm_was_from_cache = True
                        dm_name, dm_role, dm_linkedin_url = c_dm_name, c_dm_role, c_dm_li
                        dm_source_url, dm_source_type = c_dm_src, c_dm_src_type
                        if cached_dms_count >= curr_dms_count and c_dms_str:
                            decision_makers_found_str = c_dms_str
                        break
                    elif not dm_name or cached_dms_count > curr_dms_count:
                        if not live_dm_name or (c_dm_name and live_dm_name.lower() != c_dm_name.lower()):
                            dm_was_from_cache = True
                        decision_makers_found_str = c_dms_str or decision_makers_found_str
                        dm_name = c_dm_name or dm_name
                        dm_role = c_dm_role or dm_role
                        dm_linkedin_url = dm_linkedin_url or c_dm_li
                        dm_source_url = c_dm_src or dm_source_url
                        dm_source_type = c_dm_src_type or dm_source_type
                        break
            except Exception:
                pass

    country_hint = detect_country_hint(canonical_domain, page_title, meta_desc, primary_phone, html)
    dm_search_query = build_linkedin_xray_query(canonical_domain, company_category, country_hint)

    # Хвиля 2 OSINT (Wikidata SPARQL CEO fallback, VIES/GLEIF, ATS Jobs)
    if enable_deep_osint:
        tls_res = osint_wave1.get('tls') or {}
        dns_res = osint_wave1.get('dns_intel') or {}
        w2_tasks: dict = {}
        if not dm_name:
            w2_tasks['wikidata'] = query_wikidata_holding_and_ceo(
                client, canonical_domain, tls_res.get('corporate_sans') or []
            )
        if dns_res.get('detected_ats_provider') == 'Greenhouse':
            w2_tasks['ats'] = fetch_public_ats_hiring_intel(client, 'Greenhouse', brand_root)
        if w2_tasks:
            osint_wave2 = await run_osint_tasks_with_time_budget(
                w2_tasks, budget_seconds=(1.8 if is_fast_http_only else 2.5)
            )
            wd_res = osint_wave2.get('wikidata') or {}
            if not dm_name and wd_res.get('wikidata_current_ceo'):
                dm_name = wd_res['wikidata_current_ceo']
                dm_role = 'Chief Executive Officer (CEO)' if wd_res.get('decision_maker_scope') != 'founder_fallback' else 'Founder'
                dm_source_url = 'https://www.wikidata.org/'
                dm_source_type = 'wikidata_sparql'
                decision_makers_found_str = f'{dm_name} ({dm_role}) [https://www.wikidata.org/]'

    if not dm_name or (not is_marketing_or_digital_role(dm_role) and not dm_linkedin_url):
        async with semaphore:
            serp_name, serp_role, serp_li, serp_found_str = await fetch_dm_via_serp_fallback(
                client, dm_search_query, brand_root, serper_api_key
            )
        if serp_name:
            dm_name = serp_name
            dm_role = serp_role
            dm_linkedin_url = serp_li
            dm_source_url = serp_li
            dm_source_type = 'serp_linkedin_xray'
            dm_was_from_cache = False
            if decision_makers_found_str:
                decision_makers_found_str = f'{serp_found_str}; {decision_makers_found_str}'
            else:
                decision_makers_found_str = serp_found_str

    dm_fallback_url = dm_source_url or clean_website_url
    dm_name, dm_role, decision_makers_found_str = sanitize_cached_dms(
        dm_name, dm_role, decision_makers_found_str, brand_root, dm_linkedin_url,
        fallback_source_url=dm_fallback_url,
    )
    if not dm_name:
        dm_source_url = None
        dm_source_type = None
        dm_linkedin_url = None
    decision_makers_json_str = build_decision_makers_json_from_summary(
        decision_makers_found_str, dm_linkedin_url, dm_fallback_url
    )
    if decision_makers_json_str:
        try:
            _parsed_dms = json.loads(decision_makers_json_str)
            if _parsed_dms and _parsed_dms[0].get('source_url'):
                dm_source_url = _parsed_dms[0]['source_url']
                dm_source_type = _parsed_dms[0].get('source_type') or classify_dm_source_type(dm_source_url)
        except Exception:
            pass

    if dm_name and dm_was_from_cache and dm_source_type and not dm_source_type.endswith('_cached'):
        dm_source_type = f'{dm_source_type}_cached'

    gdpr_jurisdiction = derive_gdpr_jurisdiction(canonical_domain, primary_phone, country_hint, html)
    is_eu_gdpr = gdpr_jurisdiction in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')

    seed_match = manual_seeds.get(canonical_domain) or manual_seeds.get(domain_key)
    if isinstance(seed_match, dict) and max_cache_age_days > 0:
        seed_tech_count = len([x.strip() for x in (seed_match.get('detected_technologies') or '').split(';') if x.strip()])
        seed_has_dm = bool(seed_match.get('decision_maker_name'))
        if (seed_has_dm and not dm_name) or (len(detected_tech_list) < seed_tech_count) or (not best_email and bool(seed_match.get('best_email'))):
            seeded_rec = build_manual_seed_record(
                seed_match, domain_key, canonical_domain, aliases_str, clean_website_url,
                normalized_final_redirect, was_redirected, redirect_chain_str, is_eu_gdpr,
                'success', 'live_scan_partial_enriched_by_seed', checked_at, is_playwright_available()
            )
            seeded_rec['status'] = 'success (seed_merged)'
            seeded_rec['playwright_used'] = pw_used_flag
            seeded_rec['playwright_status'] = pw_status_str
            seeded_rec['playwright_attempts_count'] = pw_attempts_count
            seeded_rec['playwright_paths_attempted'] = '; '.join(pw_attempted_paths) if pw_attempted_paths else None
            seeded_rec['error_message'] = ''
            seeded_rec['data_confidence_warning'] = 'Note: Live scan augmented with verified manual_seed (B2B partnership channel + executive & full stack).'
            seeded_rec['has_google_ads_confidence'] = compute_google_ads_confidence(
                seeded_rec.get('has_google_ads'), seeded_rec.get('tech_scan_completeness', 'full'),
                seed_tech_count, bool(seeded_rec.get('consent_mode_likely')), True
            )
            seeded_rec['contact_quality_tier_human'] = derive_human_contact_tier(
                seeded_rec.get('contact_quality_tier'), seeded_rec.get('company_category', '')
            )
            seeded_rec['sales_actionability_class'] = derive_sales_actionability_class(
                seeded_rec.get('sales_readiness_verdict'), seeded_rec.get('company_category', '')
            )
            seeded_rec['gdpr_jurisdiction'] = gdpr_jurisdiction
            seeded_rec['legal_basis_for_processing'] = derive_legal_basis_for_processing(
                canonical_domain,
                country_hint,
                bool(seeded_rec.get('best_email') or seeded_rec.get('decision_maker_name') or seeded_rec.get('primary_phone')),
            )
            seeded_rec['data_subject_can_request_deletion'] = True
            seeded_rec['data_retention_policy_days'] = 365
            seeded_rec['personal_data_fields_in_record'] = derive_pii_fields(
                seeded_rec.get('best_email'), seeded_rec.get('best_email_type'),
                seeded_rec.get('decision_maker_name'), seeded_rec.get('primary_phone'),
                seeded_rec.get('decision_maker_linkedin_url')
            )
            seeded_rec['compliance_note'] = build_compliance_note(canonical_domain, country_hint)
            seeded_rec.setdefault('all_ga4_ids_count', 1 if seeded_rec.get('all_ga4_ids') else None)
            return seeded_rec

    predicted_dm_email = None
    if dm_name and not verify_person_email_match(dm_name, best_email):
        dm_email_hyps = generate_dm_email_pattern_candidates(dm_name, canonical_domain, all_emails_list)
        is_mx_configured = bool(
            not deliverability_check
            or 'domain_mail_configured' in deliverability_check
            or 'domain_accepts_email' in deliverability_check
        )
        if dm_email_hyps and is_mx_configured:
            async with semaphore:
                verified_dm_em, verified_dm_note = await verify_predicted_emails_via_api(
                    client, dm_email_hyps, reoon_api_key=reoon_api_key, millionverifier_api_key=millionverifier_api_key
                )
            if not verified_dm_em and enable_deep_osint:
                dns_res = osint_wave1.get('dns_intel') or {}
                p443_res = await verify_ceo_email_cascade_port443_v23_1(
                    client,
                    canonical_domain,
                    dm_email_hyps,
                    dns_res.get('mx_records_raw') or (deliverability_check or ''),
                    bool(dns_res.get('email_security_gateway')),
                )
                if p443_res.get('verified_email') and p443_res.get('email_verification_confidence') == 'HIGH_IDENTITY_AND_MX':
                    verified_dm_em = p443_res['verified_email']
                    verified_dm_note = p443_res['verification_status']
            if verified_dm_em:
                best_email = verified_dm_em
                best_email_type = 'personal_or_named_inbox'
                email_domain = f'{canonical_domain} (matches_site)'
                email_source_type = 'pattern_verified_api'
                email_source_note = f'Verified DM personal email via API ({verified_dm_note})'
                deliverability_check = f'{deliverability_check}; {verified_dm_note}' if deliverability_check else verified_dm_note
                if verified_dm_em not in all_emails_list:
                    all_emails_list.insert(0, verified_dm_em)
            else:
                predicted_dm_email = dm_email_hyps[0]
                hyp_str = ', '.join(dm_email_hyps[:2])
                hyp_note = f'DM Email Pattern Hypothesis (MX Valid): {hyp_str}'
                email_source_note = f'{email_source_note} | {hyp_note}' if email_source_note else hyp_note

    linkedin_url = socials_with_source.get('linkedin', (None, None))[0]
    (
        sales_readiness_verdict, icp_fit_tier, technical_signal_strength,
        contact_quality_tier, enrichment_status, confidence_warning,
        detected_signals, sales_opportunity, next_best_action
    ) = evaluate_qualification_v180(
        company_category, tech_info, best_email, best_email_type, primary_phone,
        dm_name, dm_role, dm_linkedin_url, dm_source_is_legal, dm_source_type,
        linkedin_url, had_marketplace_pollution, pw_status_str,
        predicted_dm_email=predicted_dm_email,
        is_mp_platform=is_mp_platform,
    )

    red_flags = detect_broken_attribution_red_flags(
        tech_info, company_category, is_eu_gdpr=is_eu_gdpr, pw_used=pw_used_flag
    )
    if red_flags and company_category != 'Non-Profit / Education / Institution':
        rf_summary = '; '.join(red_flags[:2])
        sales_opportunity = f'Red Flag: {rf_summary} | {sales_opportunity}'

    if cache_tech_recovered and cache_sources_count > 0:
        cache_warn = (
            f'Note: {cache_sources_count} tech(s) recovered from verified cache; '
            f'live scan partial — do not cite as current state.'
        )
        confidence_warning = f'{confidence_warning} | {cache_warn}' if (confidence_warning and confidence_warning != 'None' and 'recovered from verified cache' not in confidence_warning) else cache_warn
    elif tech_info.get('tech_scan_completeness') == 'partial_empty_render':
        empty_warn = 'Note: Zero tracking tags observed in HTML/JS shell (consent-gated or custom loader — tag absence unverified).'
        confidence_warning = f'{confidence_warning} | {empty_warn}' if (confidence_warning and confidence_warning != 'None' and 'tag absence unverified' not in confidence_warning) else empty_warn

    sales_hook = build_sales_hook(
        canonical_domain, company_category, tech_info, dm_name, dm_role, dm_linkedin_url, best_email,
        is_eu_gdpr=is_eu_gdpr, pw_used=pw_used_flag, best_email_type=best_email_type,
    )

    if best_email and deliverability_check and any(
        err_tok in deliverability_check.lower() for err_tok in ('dns_error', 'lookup_failed', 'dns_timeout', 'invalid_no_mx')
    ):
        dns_warn = f'Warning: DNS lookup failed for {best_email} (temporary DoH failure or domain has no MX). Verify manually before outbound.'
        confidence_warning = f'{dns_warn} | {confidence_warning}' if (confidence_warning and confidence_warning != 'None') else dns_warn

    has_actionable_final = bool(best_email or primary_phone)
    final_status = 'success' if has_actionable_final else 'no_contacts_found'
    needs_rescan = bool(
        tech_info['tech_scan_completeness'] != 'full' or not detected_tech_list
        or (not tech_info['has_gtm'] and not tech_info['has_ga4'] and pw_had_timeout_or_block)
    )

    all_phones_list = [p for p, _ in sorted_phones_with_src]
    human_tier = derive_human_contact_tier(contact_quality_tier, company_category)
    actionability_cls = derive_sales_actionability_class(sales_readiness_verdict, company_category)
    legal_basis = derive_legal_basis_for_processing(
        canonical_domain,
        country_hint,
        bool(best_email or dm_name or primary_phone),
    )
    pii_fields_str = derive_pii_fields(best_email, best_email_type, dm_name, primary_phone, dm_linkedin_url)
    dq_score = compute_data_quality_score(
        contact_quality_tier, len(detected_tech_list), dm_name, dm_linkedin_url,
        primary_phone, tech_info['tech_scan_completeness'], cache_tech_recovered,
        company_category=company_category, is_manual_seed=False,
        is_same_person_email=verify_person_email_match(dm_name, best_email)
    )

    # Системний інваріант #3: Поле detected_technologies завжди зберігається як плоский рядок із роздільником "; "
    result_record = {
        'input_domain': domain_key,
        'canonical_domain': canonical_domain,
        'aliases': aliases_str,
        'input_was_redirected': was_redirected,
        'redirect_chain': redirect_chain_str,
        'website_url': clean_website_url,
        'final_redirect_url': normalized_final_redirect,
        'status': final_status,
        'cached_snapshot_source': 'live',
        'cached_snapshot_age_days': 0,
        'error_message': '',
        'data_quality_score': dq_score,
        'sales_readiness_verdict': sales_readiness_verdict,
        'sales_actionability_class': actionability_cls,
        'company_category': company_category,
        'category_confidence': category_confidence,
        'marketplace_platform': is_mp_platform,
        'marketplace_platform_pollution_detected': had_marketplace_pollution,
        'icp_fit_tier': icp_fit_tier,
        'technical_signal_strength': technical_signal_strength,
        'tech_scan_completeness': tech_info['tech_scan_completeness'],
        'tech_rescan_needed': needs_rescan,
        'contact_quality_tier': contact_quality_tier,
        'contact_quality_tier_human': human_tier,
        'contact_enrichment_status': enrichment_status,
        'data_confidence_warning': confidence_warning,
        'gdpr_eu_domain': is_eu_gdpr,
        'gdpr_jurisdiction': gdpr_jurisdiction,
        'legal_basis_for_processing': legal_basis,
        'data_subject_can_request_deletion': True,
        'data_retention_policy_days': 365,
        'personal_data_fields_in_record': pii_fields_str,
        'compliance_note': build_compliance_note(canonical_domain, country_hint),
        'playwright_available': is_playwright_available(),
        'playwright_used': pw_used_flag,
        'playwright_status': pw_status_str,
        'playwright_attempts_count': pw_attempts_count,
        'playwright_paths_attempted': '; '.join(pw_attempted_paths) if pw_attempted_paths else None,
        'page_title': page_title or None,
        'meta_description': meta_desc or None,
        'best_email': best_email,
        'email_domain': email_domain,
        'best_email_type': best_email_type,
        'email_source_type': email_source_type,
        'email_source_note': email_source_note,
        'named_email_owner_role_hint': owner_role_hint,
        'email_deliverability_check': deliverability_check,
        'all_emails_deliverability': all_emails_deliverability_str,
        'all_emails_classification': all_emails_classification_str,
        'email_source_url': email_source_url,
        'primary_phone': primary_phone,
        'e164_phone': e164_phone,
        'phone_availability': phone_availability,
        'phone_source_url': phone_source_url,
        'decision_maker_name': dm_name,
        'decision_maker_role': dm_role,
        'decision_maker_source_url': dm_source_url,
        'decision_maker_source_type': dm_source_type,
        'decision_makers_found': decision_makers_found_str,
        'decision_makers_json': decision_makers_json_str,
        'decision_maker_linkedin_url': dm_linkedin_url,
        'decision_maker_search_query': dm_search_query,
        'linkedin_url': linkedin_url,
        'instagram_url': socials_with_source.get('instagram', (None, None))[0],
        'facebook_url': socials_with_source.get('facebook', (None, None))[0],
        'telegram_url': socials_with_source.get('telegram', (None, None))[0],
        'tiktok_url': socials_with_source.get('tiktok', (None, None))[0],
        'youtube_url': socials_with_source.get('youtube', (None, None))[0],
        'social_source_url': social_source_url,
        'detected_signals': detected_signals,
        'detected_cms': tech_info['detected_cms'],
        'consent_mode_likely': tech_info['has_cookie_banner'],
        'ga4_detection_confidence': tech_info['ga4_detection_confidence'],
        'has_google_ads_confidence': google_ads_conf,
        'sales_hook': sales_hook,
        'sales_opportunity': sales_opportunity,
        'next_best_action': next_best_action,
        'technology_evidence_summary': tech_info['technology_evidence_summary'],
        'technology_evidence': tech_info['technology_evidence'],
        'technology_evidence_json': tech_info.get('technology_evidence_json'),
        'has_meta_pixel': tech_info['has_meta_pixel'],
        'has_tiktok_pixel': tech_info['has_tiktok_pixel'],
        'has_google_ads': tech_info['has_google_ads'],
        'has_linkedin_pixel': tech_info['has_linkedin_pixel'],
        'has_pinterest_tag': tech_info['has_pinterest_tag'],
        'has_hubspot': tech_info['has_hubspot'],
        'has_klaviyo': tech_info['has_klaviyo'],
        'has_ga4': tech_info['has_ga4'],
        'has_gtm': tech_info['has_gtm'],
        'has_sgtm': tech_info.get('has_sgtm'),
        'all_ga4_ids': tech_info['all_ga4_ids'],
        'all_ga4_ids_count': tech_info.get('all_ga4_ids_count'),
        'detected_technologies': '; '.join(detected_tech_list) if detected_tech_list else None,
        'all_emails': '; '.join(all_emails_list) if all_emails_list else None,
        'all_phones': '; '.join(all_phones_list) if all_phones_list else None,
        'last_checked_at': checked_at
    }

    if compliance_dpo_email and not result_record.get('best_email'):
        result_record['email_source_note'] = f'Compliance/DPO address isolated ({compliance_dpo_email}); excluded from cold sales'

    if cache_store is not None and final_status in ('success', 'no_contacts_found'):
        cache_payload = build_safe_cache_payload(result_record, prior_cached_for_safe_write)
        try:
            await cache_store.set_value(canonical_kv_key, cache_payload)
            if input_kv_key != canonical_kv_key:
                await cache_store.set_value(input_kv_key, cache_payload)
            if final_status == 'success' and cache_payload.get('detected_technologies') and not cache_payload.get('_partial_write'):
                await cache_store.set_value(evergreen_kv_key, cache_payload)
        except Exception:
            pass

    return result_record


async def guarded(coro, domain_key: str, aliases: list[str]) -> dict:
    rem = remaining_run_seconds()
    budget = max(45.0, rem - 30.0) if rem is not None else 900.0
    if rem is not None and rem <= 20.0:
        coro.close()
        return build_timeout_stub(domain_key, aliases)
    try:
        return await asyncio.wait_for(coro, timeout=budget)
    except Exception:
        return build_timeout_stub(domain_key, aliases)


async def main() -> None:
    async with Actor:
        remaining_run_seconds()
        run_startup_regression_gate(
            log_fn=Actor.log.info,
            normalize_tech_fn=normalize_tech_info_booleans,
            resolve_cache_comp_fn=resolve_cache_merged_completeness,
        )

        actor_input = await Actor.get_input() or {}
        raw_domains = actor_input.get('domains', [])
        scan_contacts = actor_input.get('scanContactPages', True)
        unpack_gtm = actor_input.get('unpackGtmContainers', True)
        default_region = actor_input.get('defaultPhoneRegion', 'US').upper().strip()
        max_concurrency = max(30, int(actor_input.get('maxConcurrency', 30)))
        proxy_settings = actor_input.get('proxyConfiguration')
        output_view = str(actor_input.get('outputView') or 'full_audit').strip()
        scan_mode = str(actor_input.get('scanMode') or 'full_audit').strip()
        enable_deep_osint = bool(actor_input.get('enableDeepOsint', False))
        serper_api_key = actor_input.get('serperApiKey') or actor_input.get('serper_api_key')
        reoon_api_key = actor_input.get('reoonApiKey') or actor_input.get('reoon_api_key')
        millionverifier_api_key = actor_input.get('millionVerifierApiKey') or actor_input.get('millionverifier_api_key')

        force_fresh_scan = bool(actor_input.get('forceFreshScan', False))
        raw_max_cache_age = actor_input.get('maxCacheAgeDays', 30)
        max_cache_age_days = 0 if force_fresh_scan else max(0, int(raw_max_cache_age if raw_max_cache_age is not None else 30))
        bypass_hopeless_waf = bool(actor_input.get('bypassHopelessWaf', False))
        webhook_url = actor_input.get('webhookUrl') or actor_input.get('webhook_url')

        user_seeds = actor_input.get('manualSeeds') or actor_input.get('manual_seeds') or {}
        manual_seeds = {**DEFAULT_MANUAL_SEEDS}
        if isinstance(user_seeds, dict):
            for k, v in user_seeds.items():
                if isinstance(v, dict):
                    manual_seeds[k.lower().strip().replace('www.', '')] = v

        cache_store = None
        try:
            cache_store = await Actor.open_key_value_store(name='b2b-domain-cache-v1')
        except Exception:
            cache_store = None

        proxy_config = None
        primary_proxy_url = None
        try:
            if proxy_settings and proxy_settings.get('useApifyProxy'):
                proxy_config = await Actor.create_proxy_configuration(actor_proxy_input=proxy_settings)
                if proxy_config:
                    primary_proxy_url = await proxy_config.new_url()
            else:
                proxy_config = await Actor.create_proxy_configuration()
        except Exception:
            proxy_config = None

        res_cfg = None
        try:
            res_cfg = await Actor.create_proxy_configuration(groups=['RESIDENTIAL'])
        except Exception:
            res_cfg = None
        configure_pw(escalation_proxy=res_cfg, max_concurrent=actor_input.get('maxBrowserConcurrency', 3))

        semaphore = asyncio.Semaphore(max_concurrency)
        thread_pool = ThreadPoolExecutor(max_workers=max(16, max_concurrency * 2))

        if os.environ.get('APIFY_META_ORIGIN') == 'STANDBY' and not raw_domains:
            async def _enrich_single_standby(dom: str, mode: str) -> dict:
                prep = prepare_domains([dom])
                if not prep:
                    return {'error': 'Invalid domain', 'input_domain': dom}
                d_key, r_url, aliases = prep[0]
                async with AsyncSession(impersonate='chrome', allow_redirects=True, proxy=primary_proxy_url) as st_client:
                    return await process_domain(
                        st_client, d_key, r_url, aliases,
                        scan_contacts, unpack_gtm, default_region, proxy_config,
                        cache_store, manual_seeds, thread_pool, semaphore,
                        serper_api_key=serper_api_key,
                        reoon_api_key=reoon_api_key,
                        millionverifier_api_key=millionverifier_api_key,
                        max_cache_age_days=max_cache_age_days,
                        bypass_hopeless_waf=bypass_hopeless_waf,
                        scan_mode=mode,
                        enable_deep_osint=enable_deep_osint,
                    )
            await start_standby_http_server(_enrich_single_standby)
            return

        prepared_domains = sorted(prepare_domains(raw_domains), key=domain_weight)
        if not prepared_domains:
            Actor.log.warning('No valid domains provided in input!')
            return

        total_domains = len(prepared_domains)
        pushed_canonical_set: set[str] = set()
        pushed_formatted_records: list[dict] = []
        holding_deduplicator = SafeBatchHoldingDeduplicator()
        metrics_counter = Counter()

        try:
            async with AsyncSession(impersonate='chrome', allow_redirects=True, proxy=primary_proxy_url) as client:
                tasks = [
                    guarded(
                        process_domain(
                            client, domain_key, root_url, initial_aliases,
                            scan_contacts, unpack_gtm, default_region, proxy_config,
                            cache_store, manual_seeds, thread_pool, semaphore,
                            serper_api_key=serper_api_key,
                            reoon_api_key=reoon_api_key,
                            millionverifier_api_key=millionverifier_api_key,
                            max_cache_age_days=max_cache_age_days,
                            bypass_hopeless_waf=bypass_hopeless_waf,
                            scan_mode=scan_mode,
                            enable_deep_osint=enable_deep_osint,
                        ),
                        domain_key, initial_aliases,
                    )
                    for domain_key, root_url, initial_aliases in prepared_domains
                ]

                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    cd = result.get('canonical_domain') or result.get('input_domain')
                    if cd in pushed_canonical_set:
                        metrics_counter['deduped_canonical_aliases'] += 1
                        continue
                    pushed_canonical_set.add(cd)

                    _, b_root = extract_etld_plus_one(cd)
                    holding_status = holding_deduplicator.check_and_register(result, b_root or '')
                    if holding_status.startswith('HOLDING_DUPLICATE_SKIP_OUTREACH'):
                        prev_warn = result.get('data_confidence_warning') or ''
                        result['data_confidence_warning'] = (
                            f'{prev_warn} | {holding_status}' if (prev_warn and prev_warn != 'None') else holding_status
                        )

                    formatted_rec = format_record_for_output_view(result, output_view)
                    pushed_formatted_records.append(formatted_rec)
                    await Actor.push_data(formatted_rec)

                    st = result['status']
                    metrics_counter[f'status_{st}'] += 1
                    if result.get('playwright_used'):
                        metrics_counter['playwright_rendered'] += 1
                    if result.get('cached_snapshot_source') in ('versioned_cache', 'evergreen_cache', 'manual_seed'):
                        metrics_counter['cache_or_seed_fallbacks'] += 1

                    Actor.log.info(
                        f"[{st.upper()}] {result['canonical_domain']} (score={result['data_quality_score']}) | "
                        f"Class: {result['sales_actionability_class']} | "
                        f"Tier: {result['contact_quality_tier_human']} | "
                        f"PW: {result['playwright_status']} (tries={result['playwright_attempts_count']}) | "
                        f"GA4: {result['all_ga4_ids'] or ('True(dyn)' if result['has_ga4'] else '-')} | "
                        f"DM: {result['decision_maker_name'] or '-'} | "
                        f"Email: {result['best_email'] or '-'}"
                    )

                run_telemetry = {
                    'total_targets': total_domains,
                    'unique_canonical_domains_pushed': len(pushed_canonical_set),
                    'live_success_count': metrics_counter['status_success'] + metrics_counter['status_success (seed_merged)'],
                    'cache_or_seed_fallback_count': metrics_counter['cache_or_seed_fallbacks'],
                    'playwright_rendered_count': metrics_counter['playwright_rendered'],
                    'no_contacts_count': metrics_counter['status_no_contacts_found'],
                    'blocked_count': metrics_counter['status_blocked'],
                    'dns_error_count': metrics_counter['status_dns_error'],
                    'timeout_unfinished_count': metrics_counter['status_run_timeout_unfinished'],
                    'max_cache_age_days': max_cache_age_days,
                    'bypass_hopeless_waf': bypass_hopeless_waf,
                    'checked_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                }
                Actor.log.info(f'PIPELINE TELEMETRY SUMMARY: {json.dumps(run_telemetry)}')
                if cache_store is not None:
                    try:
                        await cache_store.set_value('LAST_RUN_METRICS', run_telemetry)
                    except Exception:
                        pass

                if webhook_url:
                    await _send_completion_webhook(client, webhook_url, run_telemetry, pushed_formatted_records)
        finally:
            await asyncio.sleep(0.05)
            await close_shared_playwright_browser()
            thread_pool.shutdown(wait=False)
