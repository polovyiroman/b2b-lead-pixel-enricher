import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import re
from urllib.parse import urlparse
from apify import Actor
from curl_cffi.requests import AsyncSession

from .config import (
    CACHE_SCHEMA_VERSION,
    DEFAULT_MANUAL_SEEDS,
    DM_SOURCE_BLACKLIST,
    EVERGREEN_MAX_AGE_DAYS,
    GTM_ID_REGEX,
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
    extract_decision_maker_deep,
    extract_named_email_owner_hint,
    rank_and_clean_emails,
    verify_email_deliverability_deep,
    verify_person_email_match,
)
from .domain_helpers import (
    KNOWN_PW_HOPELESS,
    PW_GLOBAL_MAX_ATTEMPTS_PER_DOMAIN,
    build_compliance_note,
    build_timeout_stub,
    compute_google_ads_confidence,
    contact_link_priority,
    derive_gdpr_jurisdiction,
    derive_human_contact_tier,
    derive_pii_fields,
    detect_country_hint,
    domain_weight,
    guess_region_from_domain,
    has_verified_sgtm_in_cache,
    normalize_cached_record_booleans,
    normalize_pw_empty_status,
    normalize_tech_info_booleans,
    remaining_run_seconds,
    resolve_cache_merged_completeness,
    resolve_effective_phone_region,
    sanitize_cached_dms,
    sanitize_stale_sgtm_strings,
)
from .qualifier import (
    build_linkedin_xray_query,
    build_manual_seed_record,
    build_sales_hook,
    classify_company_category,
    compute_data_quality_score,
    evaluate_qualification_v180,
    is_marketplace_platform,
)
from .regression_gate import run_startup_regression_gate
from .scraper import (
    classify_failure_status,
    close_shared_playwright_browser,
    configure_pw,
    discover_links_from_sitemap,
    extract_semantic_contact_links_from_html,
    fetch_gtm_scripts,
    fetch_html_playwright_fallback,
    fetch_html_safely,
    get_clean_canonical_domain,
    is_allowed_by_robots,
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
    detect_tech_with_evidence,
)


async def _get_playwright_proxy_url(proxy_config, domain_key: str) -> str | None:
    if proxy_config is None:
        return None
    try:
        return await proxy_config.new_url(
            session_id=f"pw_{abs(hash(domain_key)) % 100000}"
        )
    except Exception:
        return None


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
    semaphore: asyncio.Semaphore
) -> dict:
    checked_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    loop = asyncio.get_running_loop()
    pw_used_flag = False
    pw_status_str = 'not_needed' if is_playwright_available() else 'disabled'
    pw_attempts_count = 0
    pw_attempted_paths: list[str] = []
    pw_had_timeout_or_block = False

    async with semaphore:
        status, html, final_url, err_msg = await fetch_html_safely(
            client, root_url, proxy_config=proxy_config
        )
        short_err_msg = truncate_error_msg(err_msg)
        canonical_domain = get_clean_canonical_domain(final_url, domain_key)
        brand_root = canonical_domain.split('.')[0].lower() if canonical_domain else ''
        is_pw_hopeless = (canonical_domain in KNOWN_PW_HOPELESS or domain_key in KNOWN_PW_HOPELESS)

        if (status == 0 or status in (403, 429, 503)) and is_playwright_available():
            if is_pw_hopeless:
                pw_status_str = 'skipped_hopeless_waf'
                pw_had_timeout_or_block = True
                Actor.log.info(f'[PW SKIP] {canonical_domain} is in KNOWN_PW_HOPELESS; skipping Playwright rescue')
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
        else:
            was_redirected = True
            redirect_chain_str = f'{non_canonical_aliases[0]} → {canonical_domain}'

        if status == 0 or status >= 400 or not html:
            fail_status = classify_failure_status(status, err_msg)
            seed_match = manual_seeds.get(canonical_domain) or manual_seeds.get(domain_key)
            if isinstance(seed_match, dict):
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
                seeded_rec['gdpr_jurisdiction'] = _seed_jur
                seeded_rec['legal_basis_for_processing'] = (
                    'legitimate_interest_b2b'
                    if (seeded_rec.get('best_email') or seeded_rec.get('decision_maker_name') or seeded_rec.get('primary_phone'))
                    else None
                )
                seeded_rec['data_subject_can_request_deletion'] = True
                seeded_rec['data_retention_policy_days'] = 365
                seeded_rec['personal_data_fields_in_record'] = derive_pii_fields(
                    seeded_rec.get('best_email'), seeded_rec.get('best_email_type'),
                    seeded_rec.get('decision_maker_name'), seeded_rec.get('primary_phone'),
                    seeded_rec.get('decision_maker_linkedin_url')
                )
                seeded_rec['compliance_note'] = build_compliance_note(canonical_domain, _seed_hint)
                return seeded_rec

            is_tier1_marketplace = canonical_domain in KNOWN_MARKETPLACE_DOMAINS
            cache_keys_order = (
                (evergreen_kv_key, canonical_kv_key, input_kv_key)
                if is_tier1_marketplace
                else (canonical_kv_key, input_kv_key, evergreen_kv_key)
            )
            if cache_store is not None:
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

                        prev_time = cached_record.get('last_checked_at', '')
                        age_days = compute_snapshot_age_days(prev_time)
                        if is_evergreen and age_days is not None and age_days > EVERGREEN_MAX_AGE_DAYS:
                            continue

                        cached_copy = {k: v for k, v in cached_record.items() if k != '_schema'}
                        cached_copy['input_domain'] = domain_key
                        cached_copy['canonical_domain'] = canonical_domain
                        cached_copy['aliases'] = aliases_str
                        cached_copy['input_was_redirected'] = was_redirected
                        cached_copy['redirect_chain'] = redirect_chain_str
                        cached_copy['status'] = f"cached_{cached_copy['status']} (live_{fail_status})"
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

                        c_dm_name, c_dm_role, c_dms_str = sanitize_cached_dms(
                            cached_copy.get('decision_maker_name'),
                            cached_copy.get('decision_maker_role'),
                            cached_copy.get('decision_makers_found'),
                            brand_root,
                            cached_copy.get('decision_maker_linkedin_url'),
                        )
                        cached_copy['decision_maker_name'] = c_dm_name
                        cached_copy['decision_maker_role'] = c_dm_role
                        cached_copy['decision_makers_found'] = c_dms_str
                        cached_copy['decision_makers_json'] = build_decision_makers_json_from_summary(
                            c_dms_str, cached_copy.get('decision_maker_linkedin_url')
                        )

                        cached_copy.setdefault('detected_cms', None)
                        cached_copy.setdefault('consent_mode_likely', None)
                        cached_copy.setdefault('ga4_detection_confidence', None)
                        cached_copy.setdefault('tech_scan_completeness', 'partial_cached')
                        cached_copy.setdefault('category_confidence', 'high')
                        cached_copy.setdefault(
                            'marketplace_platform',
                            is_marketplace_platform(
                                canonical_domain,
                                cached_copy.get('page_title') or '',
                                cached_copy.get('meta_description') or ''
                            )
                        )
                        cached_copy.setdefault('marketplace_platform_pollution_detected', False)
                        cached_copy.setdefault('email_source_type', None)
                        cached_copy.setdefault('email_source_note', None)
                        cached_copy.setdefault('decision_maker_source_type', classify_dm_source_type(cached_copy.get('decision_maker_source_url')))
                        cached_copy.setdefault('named_email_owner_role_hint', None)

                        normalize_cached_record_booleans(cached_copy)
                        cached_copy['technology_evidence_summary'] = build_summary_from_cached_record(cached_copy)
                        cached_copy['technology_evidence_json'] = build_evidence_json_from_cached_record(cached_copy, source_label='cache')

                        _cached_all_emails = (cached_copy.get('all_emails') or cached_copy.get('best_email') or '').split(';')
                        _cached_emails_list = [e.strip() for e in _cached_all_emails if e.strip()]
                        if _cached_emails_list:
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
                        _cat = cached_copy.get('company_category', '')
                        cached_copy['contact_quality_tier_human'] = derive_human_contact_tier(
                            cached_copy.get('contact_quality_tier'), _cat
                        )
                        cached_copy['data_quality_score'] = compute_data_quality_score(
                            cached_copy.get('contact_quality_tier'), _cached_tech_count,
                            cached_copy.get('decision_maker_name'), cached_copy.get('decision_maker_linkedin_url'),
                            cached_copy.get('primary_phone'), cached_copy.get('tech_scan_completeness', 'partial_cached'),
                            True, company_category=_cat, is_manual_seed=False,
                            is_same_person_email=verify_person_email_match(cached_copy.get('decision_maker_name'), cached_copy.get('best_email'))
                        )
                        cached_copy['sales_hook'] = build_sales_hook(
                            canonical_domain, _cat,
                            {
                                'detected_technologies_list': _cached_tech_list,
                                'detected_cms': cached_copy.get('detected_cms'),
                                'has_gtm': cached_copy.get('has_gtm'),
                                'has_sgtm': cached_copy.get('has_sgtm'),
                                'has_ga4': cached_copy.get('has_ga4'),
                                'has_meta_pixel': cached_copy.get('has_meta_pixel'),
                                'has_google_ads': cached_copy.get('has_google_ads'),
                                'has_tiktok_pixel': cached_copy.get('has_tiktok_pixel'),
                                'has_linkedin_pixel': cached_copy.get('has_linkedin_pixel'),
                                'has_cookie_banner': cached_copy.get('consent_mode_likely'),
                            },
                            cached_copy.get('decision_maker_name'), cached_copy.get('decision_maker_role'),
                            cached_copy.get('decision_maker_linkedin_url'), cached_copy.get('best_email'),
                        )
                        cached_copy['legal_basis_for_processing'] = (
                            'legitimate_interest_b2b'
                            if (cached_copy.get('best_email') or cached_copy.get('decision_maker_name') or cached_copy.get('primary_phone'))
                            else None
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

            cat, cat_conf = classify_company_category(domain_key, '', '', [])
            c_hint = detect_country_hint(canonical_domain, '', '', None, '')
            blocked_jur = derive_gdpr_jurisdiction(canonical_domain, None, c_hint, '')
            blocked_is_eu = blocked_jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')
            return {
                'input_domain': domain_key,
                'canonical_domain': canonical_domain,
                'aliases': aliases_str,
                'input_was_redirected': was_redirected,
                'redirect_chain': redirect_chain_str,
                'website_url': clean_website_url,
                'final_redirect_url': normalized_final_redirect,
                'status': fail_status,
                'cached_snapshot_source': 'none (live_blocked)',
                'cached_snapshot_age_days': None,
                'error_message': short_err_msg,
                'data_quality_score': 0,
                'sales_readiness_verdict': 'Unverified (Scan Blocked by WAF)',
                'company_category': cat,
                'category_confidence': cat_conf,
                'marketplace_platform': canonical_domain in KNOWN_MARKETPLACE_DOMAINS,
                'marketplace_platform_pollution_detected': False,
                'icp_fit_tier': 'Unverified (Site Blocked / Unreachable)',
                'technical_signal_strength': None,
                'tech_scan_completeness': 'partial_blocked',
                'tech_rescan_needed': True,
                'contact_quality_tier': 'Tier F (Site Blocked)',
                'contact_quality_tier_human': 'No Contact',
                'contact_enrichment_status': 'scan_blocked_by_waf',
                'data_confidence_warning': 'Site blocked by WAF/Cloudflare and no prior cached snapshot available.',
                'gdpr_eu_domain': blocked_is_eu,
                'gdpr_jurisdiction': blocked_jur,
                'legal_basis_for_processing': None,
                'data_subject_can_request_deletion': True,
                'data_retention_policy_days': 365,
                'personal_data_fields_in_record': 'none (site_blocked)',
                'compliance_note': build_compliance_note(canonical_domain, c_hint),
                'playwright_available': is_playwright_available(),
                'playwright_used': False,
                'playwright_status': pw_status_str if (pw_attempts_count > 0 or is_pw_hopeless) else 'not_attempted_site_blocked',
                'playwright_attempts_count': pw_attempts_count,
                'playwright_paths_attempted': '; '.join(pw_attempted_paths) if pw_attempted_paths else None,
                'page_title': f'[Site blocked: {short_err_msg}]',
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
                'next_best_action': 'Retry with residential proxy or run decision_maker_search_query on LinkedIn',
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
                'detected_technologies': None,
                'all_emails': None,
                'all_phones': None,
                'last_checked_at': checked_at
            }

        effective_region = resolve_effective_phone_region(canonical_domain, default_region, html)
        is_pw_hopeless = (canonical_domain in KNOWN_PW_HOPELESS or domain_key in KNOWN_PW_HOPELESS)

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
                pw_status_str = 'skipped_hopeless_waf'
                pw_had_timeout_or_block = True
                Actor.log.info(f'[PW SKIP] {canonical_domain} is in KNOWN_PW_HOPELESS; skipping Playwright fallback')
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

        cache_tech_recovered = False
        if not tech_info['has_ga4'] and cache_store is not None:
            for c_key in (evergreen_kv_key, canonical_kv_key):
                try:
                    c_rec = await cache_store.get_value(c_key)
                    if isinstance(c_rec, dict) and (c_rec.get('has_ga4') or c_rec.get('detected_technologies')):
                        raw_t = c_rec.get('detected_technologies') or ''
                        valid_cached_sgtm = has_verified_sgtm_in_cache(c_rec)
                        cached_techs = [
                            x.strip() for x in raw_t.split(';')
                            if x.strip() and (x.strip() != 'Server-Side GTM (sGTM)' or valid_cached_sgtm)
                        ]
                        if not cached_techs:
                            continue
                        live_ev_json = json.loads(tech_info['technology_evidence_json']) if tech_info.get('technology_evidence_json') else {}
                        live_found_something = bool(live_ev_json) or bool(tech_info.get('detected_technologies_list'))
                        merged_techs = list(dict.fromkeys(tech_info['detected_technologies_list'] + cached_techs))
                        has_ga4_merged = bool(c_rec.get('has_ga4') or tech_info['has_ga4'])
                        merged_comp = resolve_cache_merged_completeness(
                            has_ga4_merged, pw_used_flag, pw_had_timeout_or_block,
                            live_found_something, tech_info['tech_scan_completeness']
                        )
                        for ct in cached_techs:
                            if ct not in live_ev_json:
                                live_ev_json[ct] = {'source': 'cache'}
                        raw_cached_ev = c_rec.get('technology_evidence') or tech_info['technology_evidence'] or 'Recovered from verified cache'
                        if not valid_cached_sgtm:
                            _, raw_cached_ev = sanitize_stale_sgtm_strings(None, raw_cached_ev)
                        tech_info = {
                            'has_meta_pixel': bool(c_rec.get('has_meta_pixel') or tech_info['has_meta_pixel']),
                            'has_tiktok_pixel': bool(c_rec.get('has_tiktok_pixel') or tech_info['has_tiktok_pixel']),
                            'has_google_ads': bool(c_rec.get('has_google_ads') or tech_info['has_google_ads']),
                            'has_linkedin_pixel': bool(c_rec.get('has_linkedin_pixel') or tech_info['has_linkedin_pixel']),
                            'has_pinterest_tag': bool(c_rec.get('has_pinterest_tag') or tech_info['has_pinterest_tag']),
                            'has_hubspot': bool(c_rec.get('has_hubspot') or tech_info['has_hubspot']),
                            'has_klaviyo': bool(c_rec.get('has_klaviyo') or tech_info['has_klaviyo']),
                            'has_ga4': has_ga4_merged,
                            'has_gtm': bool(c_rec.get('has_gtm') or tech_info['has_gtm']),
                            'has_sgtm': bool(valid_cached_sgtm or tech_info.get('has_sgtm')),
                            'all_ga4_ids': c_rec.get('all_ga4_ids') or tech_info.get('all_ga4_ids'),
                            'ga4_detection_confidence': c_rec.get('ga4_detection_confidence') or tech_info.get('ga4_detection_confidence'),
                            'detected_cms_list': [x.strip() for x in (c_rec.get('detected_cms') or '').split(';') if x.strip()] or tech_info['detected_cms_list'],
                            'detected_cms': c_rec.get('detected_cms') or tech_info['detected_cms'],
                            'has_cookie_banner': bool(c_rec.get('consent_mode_likely') or tech_info['has_cookie_banner']),
                            'detected_technologies_list': merged_techs,
                            'technology_evidence': raw_cached_ev,
                            'technology_evidence_summary': build_summary_from_cached_record({'detected_technologies': '; '.join(merged_techs), 'all_ga4_ids': c_rec.get('all_ga4_ids') or tech_info.get('all_ga4_ids'), 'technology_evidence': raw_cached_ev}),
                            'technology_evidence_json': json.dumps(live_ev_json, ensure_ascii=False) if live_ev_json else None,
                            'tech_scan_completeness': merged_comp
                        }
                        cache_tech_recovered = (merged_comp == 'partial_cached')
                        break
                except Exception:
                    pass

        normalize_tech_info_booleans(tech_info)
        detected_tech_list = tech_info['detected_technologies_list']

        google_ads_conf = compute_google_ads_confidence(
            tech_info.get('has_google_ads'), tech_info.get('tech_scan_completeness', 'full'),
            len(detected_tech_list), bool(tech_info.get('has_cookie_banner')),
            pw_used_flag and not pw_had_timeout_or_block
        )

        ranked_emails_with_src, had_marketplace_pollution = rank_and_clean_emails(email_sources, canonical_domain)

        if not ranked_emails_with_src and cache_store is not None:
            for c_key in (canonical_kv_key, evergreen_kv_key, input_kv_key):
                try:
                    c_rec = await cache_store.get_value(c_key)
                    if isinstance(c_rec, dict) and c_rec.get('best_email'):
                        c_em = str(c_rec['best_email']).strip()
                        c_src = str(c_rec.get('email_source_url') or clean_website_url)
                        email_sources[c_em] = c_src
                        for extra_em in str(c_rec.get('all_emails') or '').split(';'):
                            if extra_em.strip():
                                email_sources.setdefault(extra_em.strip(), c_src)
                        if not phone_map and c_rec.get('primary_phone'):
                            phone_map[str(c_rec['primary_phone']).strip()] = (50, str(c_rec.get('phone_source_url') or clean_website_url))
                        ranked_emails_with_src, had_marketplace_pollution = rank_and_clean_emails(email_sources, canonical_domain)
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

        top3_pairs = selected_email_pairs[:3]
        if top3_pairs:
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

        if cache_store is not None:
            for c_key in (canonical_kv_key, input_kv_key, evergreen_kv_key):
                try:
                    c_rec = await cache_store.get_value(c_key)
                    if isinstance(c_rec, dict) and (c_rec.get('decision_maker_name') or c_rec.get('decision_makers_found')):
                        c_dm_li = c_rec.get('decision_maker_linkedin_url') or dm_linkedin_url
                        c_dm_name, c_dm_role, c_dms_str = sanitize_cached_dms(
                            c_rec.get('decision_maker_name'), c_rec.get('decision_maker_role'),
                            c_rec.get('decision_makers_found'), brand_root, c_dm_li
                        )
                        if not c_dm_name and not c_dms_str:
                            continue
                        c_dm_src = c_rec.get('decision_maker_source_url')
                        c_dm_src_type = c_rec.get('decision_maker_source_type')
                        curr_dms_count = (decision_makers_found_str or '').count(';') + (1 if decision_makers_found_str else 0)
                        cached_dms_count = (c_dms_str or '').count(';') + (1 if c_dms_str else 0)

                        if c_dm_li and not dm_linkedin_url and c_dm_name:
                            dm_name, dm_role, dm_linkedin_url = c_dm_name, c_dm_role, c_dm_li
                            dm_source_url, dm_source_type = c_dm_src, c_dm_src_type
                            if cached_dms_count >= curr_dms_count and c_dms_str:
                                decision_makers_found_str = c_dms_str
                            break
                        elif not dm_name or cached_dms_count > curr_dms_count:
                            decision_makers_found_str = c_dms_str or decision_makers_found_str
                            dm_name = c_dm_name or dm_name
                            dm_role = c_dm_role or dm_role
                            dm_linkedin_url = dm_linkedin_url or c_dm_li
                            dm_source_url = c_dm_src or dm_source_url
                            dm_source_type = c_dm_src_type or dm_source_type
                            break
                except Exception:
                    pass

        dm_name, dm_role, decision_makers_found_str = sanitize_cached_dms(
            dm_name, dm_role, decision_makers_found_str, brand_root, dm_linkedin_url
        )
        decision_makers_json_str = build_decision_makers_json_from_summary(decision_makers_found_str, dm_linkedin_url)
        if decision_makers_json_str:
            try:
                _parsed_dms = json.loads(decision_makers_json_str)
                if _parsed_dms and _parsed_dms[0].get('source_url'):
                    dm_source_url = _parsed_dms[0]['source_url']
                    dm_source_type = _parsed_dms[0].get('source_type') or classify_dm_source_type(dm_source_url)
            except Exception:
                pass

        country_hint = detect_country_hint(canonical_domain, page_title, meta_desc, primary_phone, html)
        dm_search_query = build_linkedin_xray_query(canonical_domain, company_category, country_hint)
        gdpr_jurisdiction = derive_gdpr_jurisdiction(canonical_domain, primary_phone, country_hint, html)
        is_eu_gdpr = gdpr_jurisdiction in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')

        seed_match = manual_seeds.get(canonical_domain) or manual_seeds.get(domain_key)
        if isinstance(seed_match, dict):
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
                seeded_rec['gdpr_jurisdiction'] = gdpr_jurisdiction
                seeded_rec['legal_basis_for_processing'] = (
                    'legitimate_interest_b2b'
                    if (seeded_rec.get('best_email') or seeded_rec.get('decision_maker_name') or seeded_rec.get('primary_phone'))
                    else None
                )
                seeded_rec['data_subject_can_request_deletion'] = True
                seeded_rec['data_retention_policy_days'] = 365
                seeded_rec['personal_data_fields_in_record'] = derive_pii_fields(
                    seeded_rec.get('best_email'), seeded_rec.get('best_email_type'),
                    seeded_rec.get('decision_maker_name'), seeded_rec.get('primary_phone'),
                    seeded_rec.get('decision_maker_linkedin_url')
                )
                seeded_rec['compliance_note'] = build_compliance_note(canonical_domain, country_hint)
                return seeded_rec

        linkedin_url = socials_with_source.get('linkedin', (None, None))[0]
        (
            sales_readiness_verdict, icp_fit_tier, technical_signal_strength,
            contact_quality_tier, enrichment_status, confidence_warning,
            detected_signals, sales_opportunity, next_best_action
        ) = evaluate_qualification_v180(
            company_category, tech_info, best_email, best_email_type, primary_phone,
            dm_name, dm_role, dm_linkedin_url, dm_source_is_legal, dm_source_type,
            linkedin_url, had_marketplace_pollution, pw_status_str
        )

        if cache_tech_recovered or tech_info.get('tech_scan_completeness') == 'partial_cached':
            cache_warn = 'Note: Tech stack recovered from verified cache; live scan blocked — do not cite as current state.'
            confidence_warning = f'{confidence_warning} | {cache_warn}' if (confidence_warning and confidence_warning != 'None' and 'recovered from verified cache' not in confidence_warning) else cache_warn
        elif tech_info.get('tech_scan_completeness') == 'partial_empty_render':
            empty_warn = 'Note: Zero tracking tags observed in HTML/JS shell (consent-gated or custom loader — tag absence unverified).'
            confidence_warning = f'{confidence_warning} | {empty_warn}' if (confidence_warning and confidence_warning != 'None' and 'tag absence unverified' not in confidence_warning) else empty_warn

        sales_hook = build_sales_hook(
            canonical_domain, company_category, tech_info, dm_name, dm_role, dm_linkedin_url, best_email
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
        legal_basis = 'legitimate_interest_b2b' if (best_email or dm_name or primary_phone) else None
        pii_fields_str = derive_pii_fields(best_email, best_email_type, dm_name, primary_phone, dm_linkedin_url)
        dq_score = compute_data_quality_score(
            contact_quality_tier, len(detected_tech_list), dm_name, dm_linkedin_url,
            primary_phone, tech_info['tech_scan_completeness'], cache_tech_recovered,
            company_category=company_category, is_manual_seed=False,
            is_same_person_email=verify_person_email_match(dm_name, best_email)
        )

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
            'detected_technologies': '; '.join(detected_tech_list) if detected_tech_list else None,
            'all_emails': '; '.join(all_emails_list) if all_emails_list else None,
            'all_phones': '; '.join(all_phones_list) if all_phones_list else None,
            'last_checked_at': checked_at
        }

        if cache_store is not None and final_status in ('success', 'no_contacts_found'):
            cache_payload = {'_schema': CACHE_SCHEMA_VERSION, **result_record}
            try:
                await cache_store.set_value(canonical_kv_key, cache_payload)
                if input_kv_key != canonical_kv_key:
                    await cache_store.set_value(input_kv_key, cache_payload)
                if final_status == 'success' and tech_info['detected_technologies_list']:
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

        user_seeds = actor_input.get('manualSeeds') or actor_input.get('manual_seeds') or {}
        manual_seeds = {**DEFAULT_MANUAL_SEEDS}
        if isinstance(user_seeds, dict):
            for k, v in user_seeds.items():
                if isinstance(v, dict):
                    manual_seeds[k.lower().strip().replace('www.', '')] = v

        prepared_domains = sorted(prepare_domains(raw_domains), key=domain_weight)
        if not prepared_domains:
            Actor.log.warning('No valid domains provided in input!')
            return

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

        total_domains = len(prepared_domains)
        semaphore = asyncio.Semaphore(max_concurrency)
        thread_pool = ThreadPoolExecutor(max_workers=max(16, max_concurrency * 2))
        pushed_canonical_set: set[str] = set()
        metrics_counter = Counter()

        try:
            async with AsyncSession(impersonate='chrome', allow_redirects=True, verify=False, proxy=primary_proxy_url) as client:
                tasks = [
                    guarded(
                        process_domain(
                            client, domain_key, root_url, initial_aliases,
                            scan_contacts, unpack_gtm, default_region, proxy_config,
                            cache_store, manual_seeds, thread_pool, semaphore
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
                    await Actor.push_data(result)

                    st = result['status']
                    metrics_counter[f'status_{st}'] += 1
                    if result.get('playwright_used'):
                        metrics_counter['playwright_rendered'] += 1
                    if result.get('cached_snapshot_source') in ('versioned_cache', 'evergreen_cache', 'manual_seed'):
                        metrics_counter['cache_or_seed_fallbacks'] += 1

                    Actor.log.info(
                        f"[{st.upper()}] {result['canonical_domain']} (score={result['data_quality_score']}) | "
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
                'timeout_unfinished_count': metrics_counter['status_run_timeout_unfinished'],
                'checked_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            }
            Actor.log.info(f'PIPELINE TELEMETRY SUMMARY: {json.dumps(run_telemetry)}')
            if cache_store is not None:
                try:
                    await cache_store.set_value('LAST_RUN_METRICS', run_telemetry)
                except Exception:
                    pass
        finally:
            await close_shared_playwright_browser()
            thread_pool.shutdown(wait=False)
