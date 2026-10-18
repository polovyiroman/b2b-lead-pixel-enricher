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
    EU_GDPR_TLDS,
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
    classify_dm_source_type,
    classify_email_source_type_and_note,
    classify_email_type,
    extract_decision_maker_deep,
    extract_named_email_owner_hint,
    rank_and_clean_emails,
    verify_email_deliverability_deep,
)
from .qualifier import (
    build_linkedin_xray_query,
    build_manual_seed_record,
    classify_company_category,
    evaluate_qualification_v180,
    is_marketplace_platform,
)
from .scraper import (
    classify_failure_status,
    close_shared_playwright_browser,
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
)
from .tech_detector import (
    build_summary_from_cached_record,
    detect_tech_with_evidence,
)


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
    pw_avail = is_playwright_available()
    pw_used_flag = False
    pw_status_str = 'not_needed' if pw_avail else 'disabled'
    pw_attempts_count = 0
    pw_attempted_paths: list[str] = []
    pw_had_timeout_or_block = False

    async with semaphore:
        status, html, final_url, err_msg = await fetch_html_safely(
            client, root_url, proxy_config=proxy_config
        )
        short_err_msg = truncate_error_msg(err_msg)
        canonical_domain = get_clean_canonical_domain(final_url, domain_key)
        parsed_final = urlparse(final_url)
        scheme = parsed_final.scheme or 'https'
        clean_website_url = f'{scheme}://{canonical_domain}/'
        normalized_final_redirect = clean_url_port(final_url) or clean_website_url
        canonical_kv_key = sanitize_kv_key(canonical_domain)
        input_kv_key = sanitize_kv_key(domain_key)
        evergreen_kv_key = f'evergreen_{canonical_kv_key}'
        is_eu_gdpr = canonical_domain.endswith(EU_GDPR_TLDS)

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
                            f'Note: Live scan encountered {short_err_msg}; returning cached snapshot '
                            f'({cached_copy["cached_snapshot_source"]}, age={cached_copy["cached_snapshot_age_days"]}d) from {prev_time}.'
                        )
                        cached_copy.setdefault('playwright_available', pw_avail)
                        cached_copy['playwright_used'] = False
                        cached_copy['playwright_status'] = 'not_attempted_cached_fallback'
                        cached_copy['playwright_attempts_count'] = 0
                        cached_copy['playwright_paths_attempted'] = None
                        cached_copy['phone_availability'] = 'public' if cached_copy.get('primary_phone') else 'not_public'
                        cached_copy.setdefault('detected_cms', None)
                        cached_copy.setdefault('consent_mode_likely', None)
                        cached_copy.setdefault('ga4_detection_confidence', None)
                        cached_copy.setdefault('tech_scan_completeness', 'full')
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
                        cached_copy.setdefault('decision_makers_found', None)
                        cached_copy.setdefault('named_email_owner_role_hint', None)
                        cached_copy['technology_evidence_summary'] = build_summary_from_cached_record(cached_copy)

                        has_cached_tech = bool(cached_copy.get('has_gtm') or cached_copy.get('has_ga4'))
                        cached_copy['tech_rescan_needed'] = not has_cached_tech
                        if not has_cached_tech and (cached_copy.get('best_email') or cached_copy.get('primary_phone')):
                            c_contact = cached_copy.get('best_email') or cached_copy.get('primary_phone')
                            cached_copy['next_best_action'] = (
                                f'Cached contact ({c_contact}) available, but tech stack unverified due to live {short_err_msg}; '
                                f'retry with residential proxy to confirm GA4/GTM or start warm gatekeeper outreach now'
                            )
                        return cached_copy
                    except Exception:
                        pass

            seed_match = manual_seeds.get(canonical_domain) or manual_seeds.get(domain_key)
            if isinstance(seed_match, dict):
                return build_manual_seed_record(
                    seed_match,
                    domain_key,
                    canonical_domain,
                    aliases_str,
                    clean_website_url,
                    normalized_final_redirect,
                    was_redirected,
                    redirect_chain_str,
                    is_eu_gdpr,
                    fail_status,
                    short_err_msg,
                    checked_at,
                    pw_avail
                )

            cat, cat_conf = classify_company_category(domain_key, '', '', [])
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
                'contact_enrichment_status': 'scan_blocked_by_waf',
                'data_confidence_warning': 'Site blocked by WAF/Cloudflare and no prior cached snapshot available.',
                'gdpr_eu_domain': is_eu_gdpr,
                'playwright_available': pw_avail,
                'playwright_used': False,
                'playwright_status': 'not_attempted_site_blocked',
                'playwright_attempts_count': 0,
                'playwright_paths_attempted': None,
                'page_title': f'[Site blocked: {short_err_msg}]',
                'meta_description': None,
                'best_email': None,
                'email_domain': None,
                'best_email_type': None,
                'email_source_type': None,
                'email_source_note': None,
                'named_email_owner_role_hint': None,
                'email_deliverability_check': None,
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
                'decision_maker_linkedin_url': None,
                'decision_maker_search_query': build_linkedin_xray_query(canonical_domain, cat),
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
                'sales_opportunity': f'Scan {fail_status} ({short_err_msg}) — cannot verify stack without access',
                'next_best_action': 'Retry with residential proxy or run decision_maker_search_query on LinkedIn',
                'technology_evidence_summary': None,
                'technology_evidence': None,
                'has_meta_pixel': None,
                'has_tiktok_pixel': None,
                'has_google_ads': None,
                'has_linkedin_pixel': None,
                'has_pinterest_tag': None,
                'has_hubspot': None,
                'has_klaviyo': None,
                'has_ga4': None,
                'has_gtm': None,
                'all_ga4_ids': None,
                'detected_technologies': None,
                'all_emails': None,
                'all_phones': None,
                'last_checked_at': checked_at
            }

        (
            page_title,
            meta_desc,
            main_text,
            email_sources,
            phones_with_source,
            socials_with_source,
            contact_links
        ) = await loop.run_in_executor(
            thread_pool, parse_html_sync, html, normalized_final_redirect, default_region
        )

        homepage_was_soft_404 = is_soft_404_page(html, page_title)
        if homepage_was_soft_404:
            page_title = ''
            meta_desc = ''

        if unpack_gtm:
            gtm_ids, gtm_js = await fetch_gtm_scripts(client, html)
        else:
            gtm_ids = sorted({
                m.upper() for m in GTM_ID_REGEX.findall(html)
                if is_valid_gtm_id(m)
            })
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

        if scan_contacts and contact_links:
            allowed_sub_links = [
                u for u in contact_links
                if is_allowed_by_robots(u, disallowed_paths) and not DM_SOURCE_BLACKLIST.search(urlparse(u).path)
            ]
            for sub_url in allowed_sub_links[:4]:
                await asyncio.sleep(crawl_delay)
                sub_status, sub_html, sub_final_url, _ = await fetch_html_safely(
                    client, sub_url, proxy_config=proxy_config, timeout=8.0, retries=2
                )
                if 200 <= sub_status < 400 and sub_html:
                    sub_title, sub_desc, sub_text, sub_e, sub_p, sub_s, _ = await loop.run_in_executor(
                        thread_pool, parse_html_sync, sub_html, sub_final_url, default_region
                    )
                    if is_soft_404_page(sub_html, sub_title):
                        continue

                    if homepage_was_soft_404:
                        if not page_title and sub_title:
                            page_title = sub_title
                        if not meta_desc and sub_desc:
                            meta_desc = sub_desc

                    pages_with_urls.append((sub_final_url, sub_html, sub_text))
                    for em, src in sub_e.items():
                        email_sources.setdefault(em, src)
                    for p, sc, src in sub_p:
                        if p not in phone_map or sc > phone_map[p][0]:
                            phone_map[p] = (sc, src)
                    for k, v in sub_s.items():
                        socials_with_source.setdefault(k, v)

        prelim_clean_emails, _ = rank_and_clean_emails(email_sources, canonical_domain)
        has_actionable_contacts = bool(prelim_clean_emails or phone_map)
        needs_pw_tech = bool(tech_info['has_cookie_banner'] and not tech_info['has_gtm'] and not tech_info['has_ga4'])
        needs_pw_empty_shell = bool(not page_title and not tech_info['detected_technologies_list'])

        if is_playwright_available() and (not has_actionable_contacts or needs_pw_tech or needs_pw_empty_shell):
            Actor.log.info(
                f'Playwright triggered for {canonical_domain} '
                f'(no_actionable_contacts={not has_actionable_contacts}, consent_tech={needs_pw_tech}, empty_shell={needs_pw_empty_shell})'
            )
            pw_attempts_count += 1
            pw_attempted_paths.append(normalized_final_redirect)
            pw_html, pw_url, pw_status_str, pw_incomplete = await fetch_html_playwright_fallback(normalized_final_redirect)
            if pw_incomplete:
                pw_had_timeout_or_block = True
            Actor.log.info(
                f'Playwright result for {canonical_domain}: status={pw_status_str}, bytes={len(pw_html) if pw_html else 0}'
            )
            if pw_status_str == 'rendered' and pw_html:
                pw_used_flag = True
                pw_title, pw_desc, pw_text, pw_e, pw_p, pw_s, pw_sub_links = await loop.run_in_executor(
                    thread_pool, parse_html_sync, pw_html, pw_url, default_region
                )
                if not page_title and pw_title and not is_soft_404_page(pw_html, pw_title):
                    page_title = pw_title
                if not meta_desc and pw_desc:
                    meta_desc = pw_desc
                pages_with_urls.append((pw_url, pw_html, pw_text))
                for em, src in pw_e.items():
                    email_sources.setdefault(em, src)
                for p, sc, src in pw_p:
                    if p not in phone_map or sc > phone_map[p][0]:
                        phone_map[p] = (sc, src)
                for k, v in pw_s.items():
                    socials_with_source.setdefault(k, v)
                if needs_pw_tech or needs_pw_empty_shell:
                    pw_gtm_ids, pw_gtm_js = await fetch_gtm_scripts(client, pw_html) if unpack_gtm else ([], '')
                    tech_info = detect_tech_with_evidence(pw_html, pw_gtm_js or gtm_js, pw_gtm_ids or gtm_ids, pw_url, 'full')

                after_pw_emails, _ = rank_and_clean_emails(email_sources, canonical_domain)
                if scan_contacts and not (after_pw_emails or phone_map):
                    semantic_pw_links = await loop.run_in_executor(
                        thread_pool, extract_semantic_contact_links_from_html, pw_html, pw_url, canonical_domain
                    )
                    fallback_pw_paths = [
                        f'{base_root}/contacts/',
                        f'{base_root}/en/contact-us/',
                        f'{base_root}/ua/kontakty/',
                        f'{base_root}/about/'
                    ]
                    combined_pw_subs = []
                    for u in (semantic_pw_links + pw_sub_links + fallback_pw_paths):
                        if u not in combined_pw_subs and u != normalized_final_redirect:
                            combined_pw_subs.append(u)

                    for pw_sub_u in combined_pw_subs[:2]:
                        if is_allowed_by_robots(pw_sub_u, disallowed_paths):
                            pw_attempts_count += 1
                            pw_attempted_paths.append(pw_sub_u)
                            sub_pw_html, sub_pw_final, sub_pw_st, _ = await fetch_html_playwright_fallback(pw_sub_u)
                            if sub_pw_st == 'rendered' and sub_pw_html:
                                s_t, s_d, s_txt, s_e, s_p, s_s, _ = await loop.run_in_executor(
                                    thread_pool, parse_html_sync, sub_pw_html, sub_pw_final, default_region
                                )
                                if not is_soft_404_page(sub_pw_html, s_t):
                                    if not page_title and s_t:
                                        page_title = s_t
                                    if not meta_desc and s_d:
                                        meta_desc = s_d
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

        if not tech_info['has_ga4'] and cache_store is not None:
            for c_key in (evergreen_kv_key, canonical_kv_key):
                try:
                    c_rec = await cache_store.get_value(c_key)
                    if isinstance(c_rec, dict) and c_rec.get('has_ga4'):
                        raw_t = c_rec.get('detected_technologies') or ''
                        tech_info = {
                            'has_meta_pixel': bool(c_rec.get('has_meta_pixel')),
                            'has_tiktok_pixel': bool(c_rec.get('has_tiktok_pixel')),
                            'has_google_ads': bool(c_rec.get('has_google_ads')),
                            'has_linkedin_pixel': bool(c_rec.get('has_linkedin_pixel')),
                            'has_pinterest_tag': bool(c_rec.get('has_pinterest_tag')),
                            'has_hubspot': bool(c_rec.get('has_hubspot')),
                            'has_klaviyo': bool(c_rec.get('has_klaviyo')),
                            'has_ga4': True,
                            'has_gtm': bool(c_rec.get('has_gtm') or tech_info['has_gtm']),
                            'all_ga4_ids': c_rec.get('all_ga4_ids'),
                            'ga4_detection_confidence': c_rec.get('ga4_detection_confidence'),
                            'detected_cms_list': [x.strip() for x in (c_rec.get('detected_cms') or '').split(';') if x.strip()],
                            'detected_cms': c_rec.get('detected_cms'),
                            'has_cookie_banner': bool(c_rec.get('consent_mode_likely')),
                            'detected_technologies_list': [x.strip() for x in raw_t.split(';') if x.strip()],
                            'technology_evidence': c_rec.get('technology_evidence') or 'Recovered from verified cache',
                            'technology_evidence_summary': build_summary_from_cached_record(c_rec),
                            'tech_scan_completeness': 'full'
                        }
                        break
                except Exception:
                    pass

        if pw_had_timeout_or_block and not (tech_info['has_ga4'] or tech_info['has_gtm']):
            scan_comp_flag = 'partial_timeout' if 'timeout' in pw_status_str.lower() else 'partial_blocked'
            tech_info = detect_tech_with_evidence(html, gtm_js, gtm_ids, normalized_final_redirect, scan_comp_flag)

        ranked_emails_with_src, had_marketplace_pollution = rank_and_clean_emails(email_sources, canonical_domain)

        sorted_phones_with_src = sorted(
            phone_map.items(),
            key=lambda item: -item[1][0]
        )[:3]

        brand_token = canonical_domain.split('.')[0].lower()
        best_email = ranked_emails_with_src[0][0] if ranked_emails_with_src else None
        email_source_url = ranked_emails_with_src[0][1] if ranked_emails_with_src else None
        best_email_type = classify_email_type(best_email, brand_token)
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
                if brand_token and brand_token in normalized_em_local:
                    email_domain = f'{raw_em_dom} (brand_webmail)'
                else:
                    email_domain = f'{raw_em_dom} (public_webmail)'
            elif brand_token and (raw_em_dom.split('.')[0] == brand_token or brand_token in raw_em_dom.split('.')[0]):
                email_domain = f'{raw_em_dom} (brand_alias_domain)'
            else:
                email_domain = f'{raw_em_dom} (external_domain)'

        deliverability_check = (
            await verify_email_deliverability_deep(client, best_email, email_source_url)
            if best_email else None
        )

        primary_phone = sorted_phones_with_src[0][0] if sorted_phones_with_src else None
        e164_phone = re.sub(r'[\s\-()]', '', primary_phone) if primary_phone else None
        phone_availability = 'public' if primary_phone else 'not_public'
        phone_source_url = sorted_phones_with_src[0][1][1] if sorted_phones_with_src else None

        social_source_url = None
        for platform in ('linkedin', 'instagram', 'facebook', 'telegram', 'tiktok', 'youtube'):
            if platform in socials_with_source:
                social_source_url = socials_with_source[platform][1]
                break

        detected_tech_list = tech_info['detected_technologies_list']
        company_category, category_confidence = classify_company_category(
            canonical_domain, page_title, meta_desc, detected_tech_list, html
        )
        is_mp_platform = is_marketplace_platform(canonical_domain, page_title, meta_desc)

        (
            dm_name,
            dm_role,
            dm_linkedin_url,
            dm_source_url,
            dm_source_is_legal,
            dm_source_type,
            decision_makers_found_str
        ) = await loop.run_in_executor(
            thread_pool, extract_decision_maker_deep, pages_with_urls
        )

        dm_search_query = build_linkedin_xray_query(canonical_domain, company_category)

        linkedin_url = socials_with_source.get('linkedin', (None, None))[0]
        (
            sales_readiness_verdict,
            icp_fit_tier,
            technical_signal_strength,
            contact_quality_tier,
            enrichment_status,
            confidence_warning,
            detected_signals,
            sales_opportunity,
            next_best_action
        ) = evaluate_qualification_v180(
            company_category,
            tech_info,
            best_email,
            best_email_type,
            primary_phone,
            dm_name,
            dm_role,
            dm_linkedin_url,
            dm_source_is_legal,
            dm_source_type,
            linkedin_url,
            had_marketplace_pollution,
            pw_status_str
        )

        has_actionable_final = bool(best_email or primary_phone)
        final_status = 'success' if has_actionable_final else 'no_contacts_found'
        needs_rescan = bool(tech_info['tech_scan_completeness'] != 'full' or (not tech_info['has_gtm'] and not tech_info['has_ga4'] and pw_had_timeout_or_block))

        non_legal_emails = [
            em for em, _ in ranked_emails_with_src
            if classify_email_type(em, brand_token) != 'legal_or_hr_inbox'
        ]
        all_emails_list = (non_legal_emails or [em for em, _ in ranked_emails_with_src])[:5]
        all_phones_list = [p for p, _ in sorted_phones_with_src]

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
            'contact_enrichment_status': enrichment_status,
            'data_confidence_warning': confidence_warning,
            'gdpr_eu_domain': is_eu_gdpr,
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
            'sales_opportunity': sales_opportunity,
            'next_best_action': next_best_action,
            'technology_evidence_summary': tech_info['technology_evidence_summary'],
            'technology_evidence': tech_info['technology_evidence'],
            'has_meta_pixel': tech_info['has_meta_pixel'],
            'has_tiktok_pixel': tech_info['has_tiktok_pixel'],
            'has_google_ads': tech_info['has_google_ads'],
            'has_linkedin_pixel': tech_info['has_linkedin_pixel'],
            'has_pinterest_tag': tech_info['has_pinterest_tag'],
            'has_hubspot': tech_info['has_hubspot'],
            'has_klaviyo': tech_info['has_klaviyo'],
            'has_ga4': tech_info['has_ga4'],
            'has_gtm': tech_info['has_gtm'],
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
                if final_status == 'success':
                    await cache_store.set_value(evergreen_kv_key, cache_payload)
            except Exception:
                pass

        return result_record


async def main() -> None:
    async with Actor:
        if not is_playwright_available():
            Actor.log.warning(
                'PLAYWRIGHT NOT INSTALLED: Browser SPA fallback disabled. '
                'Update Dockerfile to `FROM apify/actor-python-playwright:3.12` to enable.'
            )

        actor_input = await Actor.get_input() or {}
        raw_domains = actor_input.get('domains', [])
        scan_contacts = actor_input.get('scanContactPages', True)
        unpack_gtm = actor_input.get('unpackGtmContainers', True)
        default_region = actor_input.get('defaultPhoneRegion', 'US').upper().strip()
        max_concurrency = actor_input.get('maxConcurrency', 15)
        proxy_settings = actor_input.get('proxyConfiguration')

        user_seeds = actor_input.get('manualSeeds') or actor_input.get('manual_seeds') or {}
        manual_seeds = {**DEFAULT_MANUAL_SEEDS}
        if isinstance(user_seeds, dict):
            for k, v in user_seeds.items():
                if isinstance(v, dict):
                    manual_seeds[k.lower().strip().replace('www.', '')] = v

        prepared_domains = prepare_domains(raw_domains)
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

        total_domains = len(prepared_domains)
        Actor.log.info(
            f'Processing {total_domains} pre-deduped canonical targets '
            f'(concurrency: {max_concurrency}, GTM unpack: {unpack_gtm}, '
            f'playwright_available: {is_playwright_available()}, cache schema: v{CACHE_SCHEMA_VERSION}, '
            f'manual_seeds: {len(manual_seeds)})...'
        )
        semaphore = asyncio.Semaphore(max_concurrency)
        thread_pool = ThreadPoolExecutor(max_workers=max(16, max_concurrency * 2))

        pushed_canonical_set: set[str] = set()
        metrics_counter = Counter()

        try:
            async with AsyncSession(
                impersonate='chrome',
                allow_redirects=True,
                verify=False,
                proxy=primary_proxy_url
            ) as client:
                tasks = [
                    process_domain(
                        client,
                        domain_key,
                        root_url,
                        initial_aliases,
                        scan_contacts,
                        unpack_gtm,
                        default_region,
                        proxy_config,
                        cache_store,
                        manual_seeds,
                        thread_pool,
                        semaphore
                    )
                    for domain_key, root_url, initial_aliases in prepared_domains
                ]

                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    cd = result.get('canonical_domain') or result.get('input_domain')
                    inp_dom = result.get('input_domain', '')

                    if cd in pushed_canonical_set:
                        metrics_counter['deduped_canonical_aliases'] += 1
                        Actor.log.info(f'[DEDUPED LATE REDIRECT] {inp_dom} skipped because {cd} already pushed.')
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
                        f"[{st.upper()}] {result['canonical_domain']} (aliases={result['aliases']}) | "
                        f"PW: {result['playwright_status']} (tries={result['playwright_attempts_count']}) | "
                        f"GA4: {result['all_ga4_ids'] or ('True(dyn)' if result['has_ga4'] else '-')} | "
                        f"DM: {result['decision_maker_name'] or '-'} | "
                        f"Email: {result['best_email'] or '-'}"
                    )

            run_telemetry = {
                'total_targets': total_domains,
                'unique_canonical_domains_pushed': len(pushed_canonical_set),
                'live_success_count': metrics_counter['status_success'],
                'cache_or_seed_fallback_count': metrics_counter['cache_or_seed_fallbacks'],
                'playwright_rendered_count': metrics_counter['playwright_rendered'],
                'no_contacts_count': metrics_counter['status_no_contacts_found'],
                'blocked_count': metrics_counter['status_blocked'],
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


if __name__ == '__main__':
    asyncio.run(main())
