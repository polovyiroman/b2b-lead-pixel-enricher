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
    KNOWN_JURISDICTION_HINTS,
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

TECH_FLAG_TO_NAME_MAP = (
    ('has_meta_pixel', 'Meta Pixel'),
    ('has_tiktok_pixel', 'TikTok Pixel'),
    ('has_google_ads', 'Google Ads Conversion'),
    ('has_linkedin_pixel', 'LinkedIn Insight Tag'),
    ('has_pinterest_tag', 'Pinterest Tag'),
    ('has_hubspot', 'HubSpot'),
    ('has_klaviyo', 'Klaviyo'),
    ('has_ga4', 'Google Analytics (GA4)'),
    ('has_gtm', 'Google Tag Manager'),
)

AD_PIXEL_LABELS = {
    'Meta Pixel',
    'TikTok Pixel',
    'Google Ads Conversion',
    'LinkedIn Insight Tag',
    'Pinterest Tag',
}

COMPLIANCE_DEFAULT_NOTE = (
    'Enriched for legitimate B2B interest; public site data; deletion on request via support'
)

EU_PHONE_PREFIXES = (
    '+49', '+33', '+39', '+34', '+31', '+32', '+43', '+48', '+46',
    '+45', '+358', '+351', '+420', '+36', '+40', '+421', '+353',
    '+30', '+359', '+385', '+370', '+371', '+372', '+386', '+352'
)

KNOWN_DOMAIN_COUNTRY_HINTS: dict[str, str] = {
    'bol.com': 'NL',
    'coolblue.nl': 'NL',
    'liki24.com': 'UA',
    'ringostat.com': 'UA',
    'cher17.com': 'UA',
    'ottogroup.com': 'DE',
    'aboutyou.de': 'DE',
    'zalando.de': 'DE',
    'otto.de': 'DE',
    'docmorris.de': 'DE',
    'asos.com': 'GB',
    'laredoute.fr': 'FR',
    'unicredit.it': 'IT',
}


def _contact_link_priority(url: str) -> tuple[int, int]:
    path = urlparse(url).path.lower()
    if any(k in path for k in ('impressum', 'mentions-legales', 'aviso-legal')):
        return (0, len(path))
    if any(k in path for k in ('contact', 'kontakt', 'kontakty', 'contatti', 'contacto', 'get-in-touch')):
        return (1, len(path))
    if any(k in path for k in ('team', 'komanda', 'leadership', 'management', 'founders', 'zespol', 'equipe')):
        return (2, len(path))
    if any(k in path for k in ('about', 'ueber-uns', 'uber-uns', 'pro-nas', 'o-nas', 'qui-sommes-nous', 'chi-siamo', 'over-ons')):
        return (3, len(path))
    return (4, len(path))


def _guess_region_from_domain(canonical_domain: str, html_sample: str = '') -> str | None:
    dom_low = (canonical_domain or '').lower()
    if dom_low in KNOWN_DOMAIN_COUNTRY_HINTS:
        return KNOWN_DOMAIN_COUNTRY_HINTS[dom_low]
    if dom_low.endswith('.ua'):
        return 'UA'
    if dom_low.endswith('.de'):
        return 'DE'
    if dom_low.endswith('.at'):
        return 'AT'
    if dom_low.endswith('.ch'):
        return 'CH'
    if dom_low.endswith('.it'):
        return 'IT'
    if dom_low.endswith('.fr'):
        return 'FR'
    if dom_low.endswith('.es'):
        return 'ES'
    if dom_low.endswith('.nl'):
        return 'NL'
    if dom_low.endswith('.be'):
        return 'BE'
    if dom_low.endswith('.pl'):
        return 'PL'
    if dom_low.endswith('.pt'):
        return 'PT'
    if dom_low.endswith('.se'):
        return 'SE'
    if dom_low.endswith('.no'):
        return 'NO'
    if dom_low.endswith('.dk'):
        return 'DK'
    if dom_low.endswith('.fi'):
        return 'FI'
    if dom_low.endswith('.cz'):
        return 'CZ'
    if dom_low.endswith('.ro'):
        return 'RO'
    if dom_low.endswith('.hu'):
        return 'HU'
    if dom_low.endswith('.ie'):
        return 'IE'
    if dom_low.endswith(('.uk', '.co.uk')):
        return 'GB'

    if html_sample:
        html_head = html_sample[:2000].lower()
        lang_match = re.search(r'<html[^>]+lang=["\']([a-z]{2})(?:[-_]([a-z]{2}))?', html_head)
        if lang_match:
            lang = lang_match.group(1).upper()
            country_sub = (lang_match.group(2) or '').upper()
            if country_sub in ('UA', 'DE', 'AT', 'CH', 'IT', 'FR', 'ES', 'NL', 'BE', 'PL', 'PT', 'SE', 'NO', 'DK', 'FI', 'GB', 'US'):
                return country_sub
            if lang in ('UK', 'UA'):
                return 'UA'
            if lang == 'DE':
                return 'DE'
            if lang == 'IT':
                return 'IT'
            if lang == 'FR':
                return 'FR'
            if lang == 'ES':
                return 'ES'
            if lang == 'NL':
                return 'NL'
            if lang == 'PL':
                return 'PL'
            if lang == 'PT':
                return 'PT'
            if lang == 'SV':
                return 'SE'
    return None


def _resolve_effective_phone_region(
    canonical_domain: str,
    default_region: str,
    html_sample: str = ''
) -> str:
    guessed = _guess_region_from_domain(canonical_domain, html_sample)
    if guessed:
        return guessed
    return default_region if default_region else 'US'


def _derive_gdpr_jurisdiction(
    canonical_domain: str,
    phone: str | None = None,
    content_lang_hint: str = '',
    html_sample: str = ''
) -> str:
    """
    Patch D (Issue 19 Fix): Визначає юрисдикцію з підтримкою KNOWN_JURISDICTION_HINTS
    на першому кроці, щоб bol.com -> EU_EEA_GDPR та liki24.com -> UA_PDP працювали навіть при WAF-блокуванні.
    """
    dom_low = (canonical_domain or '').lower()
    if dom_low in KNOWN_JURISDICTION_HINTS:
        return KNOWN_JURISDICTION_HINTS[dom_low]
    if dom_low.endswith(('.uk', '.co.uk')):
        return 'UK_GDPR'
    if dom_low.endswith('.ch'):
        return 'CH_FADP'
    if dom_low.endswith(EU_GDPR_TLDS):
        return 'EU_EEA_GDPR'
    if dom_low.endswith('.ua'):
        return 'UA_PDP'

    phone_str = (phone or '').strip()
    if phone_str.startswith('+44'):
        return 'UK_GDPR'
    if phone_str.startswith('+41'):
        return 'CH_FADP'
    if phone_str.startswith(EU_PHONE_PREFIXES):
        return 'EU_EEA_GDPR'
    if phone_str.startswith('+380'):
        return 'UA_PDP'

    hint_up = (content_lang_hint or '').upper().strip()
    if hint_up in ('DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'AT', 'PL', 'PT', 'SE', 'NO', 'DK', 'FI', 'CZ', 'RO', 'HU', 'SK', 'IE'):
        return 'EU_EEA_GDPR'
    if hint_up in ('GB', 'UK'):
        return 'UK_GDPR'
    if hint_up == 'CH':
        return 'CH_FADP'
    if hint_up == 'UA':
        return 'UA_PDP'

    if html_sample:
        html_low = html_sample[:25000].lower()
        if any(m in html_low for m in ('registered in england', 'london, uk', 'england and wales', 'asos.com limited')):
            return 'UK_GDPR'
        if any(m in html_low for m in ('impressum', 'handelsregister', 'amtsgericht', 'umsatzsteuer-id', 'gmbh & co. kg', 'otto group')):
            return 'EU_EEA_GDPR'

    return 'NON_EU_GLOBAL'


def _derive_pii_fields(
    best_email: str | None,
    best_email_type: str | None,
    dm_name: str | None,
    primary_phone: str | None,
    dm_linkedin_url: str | None
) -> str:
    fields = []
    if dm_name:
        fields.append('decision_maker_name')
    if dm_linkedin_url:
        fields.append('decision_maker_linkedin_url')
    if best_email and best_email_type == 'personal_or_named_inbox':
        fields.append('best_email (named_staff)')
    if primary_phone:
        fields.append('primary_phone (public_b2b)')
    return '; '.join(fields) if fields else 'none (corporate_role_contacts_only)'


def _derive_human_contact_tier(contact_quality_tier: str | None) -> str:
    if not contact_quality_tier:
        return 'No Contact'
    t_str = contact_quality_tier
    if 'Tier A' in t_str:
        return 'Hot'
    if 'Tier B' in t_str:
        return 'Warm'
    if 'Tier C' in t_str:
        return 'Cold'
    if 'Tier D' in t_str:
        return 'Do Not Contact'
    return 'No Contact'


def compute_google_ads_confidence(
    has_ads: bool | None,
    scan_completeness: str,
    techs_found_count: int = 0
) -> str:
    if has_ads is True:
        return 'verified_present'
    if has_ads is None:
        return 'unknown'
    if scan_completeness != 'full':
        return 'unknown'
    if techs_found_count > 0:
        return 'verified_absent'
    return 'unknown'


def detect_country_hint(
    canonical_domain: str,
    page_title: str,
    meta_desc: str,
    primary_phone: str | None,
    html_sample: str = ''
) -> str:
    dom_low = canonical_domain.lower()
    if dom_low in KNOWN_DOMAIN_COUNTRY_HINTS:
        return KNOWN_DOMAIN_COUNTRY_HINTS[dom_low]
    if dom_low.endswith('.ua'):
        return 'UA'
    if dom_low.endswith(('.de', '.at', '.ch')):
        return 'DE'
    if dom_low.endswith('.pl'):
        return 'PL'
    if dom_low.endswith('.fr'):
        return 'FR'
    if dom_low.endswith('.es'):
        return 'ES'
    if dom_low.endswith('.it'):
        return 'IT'
    if dom_low.endswith(('.nl', '.be')):
        return 'NL'
    if dom_low.endswith('.pt'):
        return 'PT'
    if dom_low.endswith(('.se', '.no', '.dk', '.fi')):
        return 'SE'
    if dom_low.endswith(('.uk', '.co.uk')):
        return 'GB'

    phone_str = primary_phone or ''
    if phone_str.startswith('+380'):
        return 'UA'
    if phone_str.startswith(('+49', '+43', '+41')):
        return 'DE'
    if phone_str.startswith('+48'):
        return 'PL'
    if phone_str.startswith('+33'):
        return 'FR'
    if phone_str.startswith('+34'):
        return 'ES'
    if phone_str.startswith('+39'):
        return 'IT'
    if phone_str.startswith(('+31', '+32')):
        return 'NL'
    if phone_str.startswith('+44'):
        return 'GB'

    text_combined = f'{page_title} {meta_desc}'
    if re.search(r'[іїєґІЇЄҐ]', text_combined):
        return 'UA'
    if re.search(r'[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]', text_combined):
        return 'PL'

    html_head = html_sample[:2000].lower()
    lang_match = re.search(r'<html[^>]+lang=["\']([a-z]{2})', html_head)
    if lang_match:
        lang = lang_match.group(1).upper()
        if lang in ('UK', 'UA'):
            return 'UA'
        if lang == 'DE':
            return 'DE'
        if lang == 'PL':
            return 'PL'
        if lang == 'FR':
            return 'FR'
        if lang == 'ES':
            return 'ES'
        if lang == 'IT':
            return 'IT'
        if lang == 'NL':
            return 'NL'
        if lang == 'PT':
            return 'PT'
        if lang in ('SV', 'NO', 'NB', 'NN', 'DA', 'FI'):
            return 'SE'

    return ''


def normalize_tech_info_booleans(tech_info: dict) -> None:
    techs_list = tech_info.get('detected_technologies_list') or []
    techs_set = {t.strip() for t in techs_list if t and t.strip()}

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = (tech_label in techs_set) or bool(tech_info.get(flag_key))
        if flag_key == 'has_ga4' and tech_info.get('all_ga4_ids'):
            is_found = True
        if is_found and tech_label not in techs_set:
            techs_list.append(tech_label)
            techs_set.add(tech_label)

    has_any_ad_pixel = bool(techs_set & AD_PIXEL_LABELS)
    if (
        tech_info.get('ga4_detection_confidence') in (
            'Medium (GTM Single Macro)',
            'Low (Script Endpoint Only — ID Dynamic)',
        )
        and tech_info.get('tech_scan_completeness') == 'full'
        and not has_any_ad_pixel
    ):
        tech_info['tech_scan_completeness'] = 'partial_gtm'
    elif tech_info.get('tech_scan_completeness') == 'partial_gtm' and has_any_ad_pixel:
        tech_info['tech_scan_completeness'] = 'full'

    scan_comp = tech_info.get('tech_scan_completeness', 'full')
    is_hard_partial = scan_comp in ('partial_timeout', 'partial_blocked')

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = tech_label in techs_set
        tech_info[flag_key] = True if is_found else (None if is_hard_partial else False)

    tech_info['detected_technologies_list'] = techs_list


def normalize_cached_record_booleans(cached_copy: dict) -> None:
    raw_tech_str = cached_copy.get('detected_technologies') or ''
    techs_list = [x.strip() for x in raw_tech_str.split(';') if x.strip()]
    techs_set = set(techs_list)

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = (tech_label in techs_set) or bool(cached_copy.get(flag_key))
        if flag_key == 'has_ga4' and cached_copy.get('all_ga4_ids'):
            is_found = True
        if is_found and tech_label not in techs_set:
            techs_list.append(tech_label)
            techs_set.add(tech_label)

    has_any_ad_pixel = bool(techs_set & AD_PIXEL_LABELS)
    if (
        cached_copy.get('ga4_detection_confidence') in (
            'Medium (GTM Single Macro)',
            'Low (Script Endpoint Only — ID Dynamic)',
        )
        and cached_copy.get('tech_scan_completeness', 'full') == 'full'
        and not has_any_ad_pixel
    ):
        cached_copy['tech_scan_completeness'] = 'partial_gtm'
    elif cached_copy.get('tech_scan_completeness') == 'partial_gtm' and has_any_ad_pixel:
        cached_copy['tech_scan_completeness'] = 'full'

    scan_comp = cached_copy.get('tech_scan_completeness', 'full')
    is_hard_partial = scan_comp in ('partial_timeout', 'partial_blocked')

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = tech_label in techs_set
        cached_copy[flag_key] = True if is_found else (None if is_hard_partial else False)

    cached_copy['detected_technologies'] = '; '.join(techs_list) if techs_list else None


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

        if status == 0 and is_playwright_available():
            rescue_url = clean_url_port(root_url) or root_url
            Actor.log.info(
                f'Curl tunnel/connection failed for {canonical_domain} ({short_err_msg}); '
                f'attempting Playwright rescue on {rescue_url}'
            )
            pw_attempts_count += 1
            pw_attempted_paths.append(rescue_url)
            pw_rescue_html, pw_rescue_url, pw_rescue_status, pw_rescue_inc = await fetch_html_playwright_fallback(rescue_url)
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
            else:
                pw_status_str = pw_rescue_status
                if pw_rescue_inc:
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
                            f'Note: Live scan encountered {short_err_msg}; returning cached snapshot '
                            f'({cached_copy["cached_snapshot_source"]}, age={cached_copy["cached_snapshot_age_days"]}d) from {prev_time}.'
                        )
                        cached_copy['playwright_available'] = is_playwright_available()
                        cached_copy['playwright_used'] = False
                        cached_copy['playwright_status'] = (
                            pw_status_str if pw_attempts_count > 0 else 'not_attempted_cached_fallback'
                        )
                        cached_copy['playwright_attempts_count'] = pw_attempts_count
                        cached_copy['playwright_paths_attempted'] = (
                            '; '.join(pw_attempted_paths) if pw_attempted_paths else None
                        )
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

                        normalize_cached_record_booleans(cached_copy)
                        cached_copy['technology_evidence_summary'] = build_summary_from_cached_record(cached_copy)

                        _cached_all_emails = (
                            cached_copy.get('all_emails') or cached_copy.get('best_email') or ''
                        ).split(';')
                        _cached_emails_list = [e.strip() for e in _cached_all_emails if e.strip()]
                        if _cached_emails_list:
                            _brand = canonical_domain.split('.')[0].lower()
                            cached_copy['all_emails_classification'] = '; '.join(
                                f'{em} ({classify_email_type(em, _brand)})' for em in _cached_emails_list
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
                        cached_copy['tech_rescan_needed'] = not has_cached_tech

                        if cached_copy['tech_rescan_needed'] and cached_copy.get('tech_scan_completeness') == 'full':
                            cached_copy['tech_scan_completeness'] = 'partial_cached'

                        _cached_tech_count = len(
                            [x.strip() for x in (cached_copy.get('detected_technologies') or '').split(';') if x.strip()]
                        )
                        cached_copy['has_google_ads_confidence'] = compute_google_ads_confidence(
                            cached_copy.get('has_google_ads'),
                            cached_copy.get('tech_scan_completeness', 'full'),
                            _cached_tech_count
                        )

                        _c_hint = detect_country_hint(
                            canonical_domain,
                            cached_copy.get('page_title') or '',
                            cached_copy.get('meta_description') or '',
                            cached_copy.get('primary_phone'),
                            ''
                        )
                        _jur = _derive_gdpr_jurisdiction(
                            canonical_domain,
                            cached_copy.get('primary_phone'),
                            _c_hint,
                            ''
                        )
                        cached_copy['gdpr_jurisdiction'] = _jur
                        cached_copy['gdpr_eu_domain'] = _jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')
                        cached_copy['contact_quality_tier_human'] = _derive_human_contact_tier(
                            cached_copy.get('contact_quality_tier')
                        )
                        cached_copy['legal_basis_for_processing'] = (
                            'legitimate_interest_b2b'
                            if (cached_copy.get('best_email') or cached_copy.get('decision_maker_name') or cached_copy.get('primary_phone'))
                            else None
                        )
                        cached_copy['data_subject_can_request_deletion'] = True
                        cached_copy['data_retention_policy_days'] = 365
                        cached_copy['personal_data_fields_in_record'] = _derive_pii_fields(
                            cached_copy.get('best_email'),
                            cached_copy.get('best_email_type'),
                            cached_copy.get('decision_maker_name'),
                            cached_copy.get('primary_phone'),
                            cached_copy.get('decision_maker_linkedin_url')
                        )
                        cached_copy['compliance_note'] = COMPLIANCE_DEFAULT_NOTE

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
                _seed_hint = detect_country_hint(
                    canonical_domain,
                    seed_match.get('page_title') or '',
                    seed_match.get('meta_description') or '',
                    seed_match.get('primary_phone'),
                    ''
                )
                _seed_jur = _derive_gdpr_jurisdiction(
                    canonical_domain,
                    seed_match.get('primary_phone'),
                    _seed_hint,
                    ''
                )
                _seed_is_eu = _seed_jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')
                seeded_rec = build_manual_seed_record(
                    seed_match,
                    domain_key,
                    canonical_domain,
                    aliases_str,
                    clean_website_url,
                    normalized_final_redirect,
                    was_redirected,
                    redirect_chain_str,
                    _seed_is_eu,
                    fail_status,
                    short_err_msg,
                    checked_at,
                    is_playwright_available()
                )
                _seed_tech_count = len(
                    [x.strip() for x in (seeded_rec.get('detected_technologies') or '').split(';') if x.strip()]
                )
                seeded_rec['has_google_ads_confidence'] = compute_google_ads_confidence(
                    seeded_rec.get('has_google_ads'),
                    seeded_rec.get('tech_scan_completeness', 'full'),
                    _seed_tech_count
                )
                seeded_rec['contact_quality_tier_human'] = _derive_human_contact_tier(
                    seeded_rec.get('contact_quality_tier')
                )
                seeded_rec['gdpr_jurisdiction'] = _seed_jur
                seeded_rec['legal_basis_for_processing'] = (
                    'legitimate_interest_b2b'
                    if (seeded_rec.get('best_email') or seeded_rec.get('decision_maker_name') or seeded_rec.get('primary_phone'))
                    else None
                )
                seeded_rec['data_subject_can_request_deletion'] = True
                seeded_rec['data_retention_policy_days'] = 365
                seeded_rec['personal_data_fields_in_record'] = _derive_pii_fields(
                    seeded_rec.get('best_email'),
                    seeded_rec.get('best_email_type'),
                    seeded_rec.get('decision_maker_name'),
                    seeded_rec.get('primary_phone'),
                    seeded_rec.get('decision_maker_linkedin_url')
                )
                seeded_rec['compliance_note'] = COMPLIANCE_DEFAULT_NOTE
                return seeded_rec

            cat, cat_conf = classify_company_category(domain_key, '', '', [])
            c_hint = detect_country_hint(canonical_domain, '', '', None, '')
            blocked_jur = _derive_gdpr_jurisdiction(canonical_domain, None, c_hint, '')
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
                'compliance_note': COMPLIANCE_DEFAULT_NOTE,
                'playwright_available': is_playwright_available(),
                'playwright_used': False,
                'playwright_status': pw_status_str if pw_attempts_count > 0 else 'not_attempted_site_blocked',
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

        effective_region = _resolve_effective_phone_region(canonical_domain, default_region, html)

        (
            page_title,
            meta_desc,
            main_text,
            email_sources,
            phones_with_source,
            socials_with_source,
            contact_links
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

        if scan_contacts and effective_region in ('DE', 'AT', 'CH'):
            has_impressum_link = any('impressum' in u.lower() for u in contact_links)
            if not has_impressum_link:
                contact_links = [f'{base_root}/impressum'] + list(contact_links)

        if scan_contacts and contact_links:
            allowed_sub_links = [
                u for u in contact_links
                if is_allowed_by_robots(u, disallowed_paths) and not DM_SOURCE_BLACKLIST.search(urlparse(u).path)
            ]
            allowed_sub_links = sorted(allowed_sub_links, key=_contact_link_priority)

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
        needs_pw_no_tech_at_all = bool(
            not tech_info['detected_technologies_list']
            and not tech_info['has_gtm']
            and not tech_info['has_ga4']
            and bool(page_title)
        )

        if is_playwright_available() and not pw_used_flag and (
            not has_actionable_contacts
            or needs_pw_tech
            or needs_pw_empty_shell
            or needs_pw_no_tech_at_all
        ):
            Actor.log.info(
                f'Playwright triggered for {canonical_domain} '
                f'(no_actionable_contacts={not has_actionable_contacts}, consent_tech={needs_pw_tech}, '
                f'empty_shell={needs_pw_empty_shell}, zero_static_tech={needs_pw_no_tech_at_all})'
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
                    thread_pool, parse_html_sync, pw_html, pw_url, effective_region
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
                if needs_pw_tech or needs_pw_empty_shell or needs_pw_no_tech_at_all:
                    pw_gtm_ids, pw_gtm_js = await fetch_gtm_scripts(client, pw_html) if unpack_gtm else ([], '')
                    tech_info = detect_tech_with_evidence(pw_html, pw_gtm_js or gtm_js, pw_gtm_ids or gtm_ids, pw_url, 'full')

                after_pw_emails, _ = rank_and_clean_emails(email_sources, canonical_domain)
                if scan_contacts and not (after_pw_emails or phone_map):
                    semantic_pw_links = await loop.run_in_executor(
                        thread_pool, extract_semantic_contact_links_from_html, pw_html, pw_url, canonical_domain
                    )
                    fallback_pw_paths = [
                        f'{base_root}/impressum/',
                        f'{base_root}/kontakt/',
                        f'{base_root}/contacts/',
                        f'{base_root}/en/contact-us/',
                        f'{base_root}/ua/kontakty/',
                        f'{base_root}/about/'
                    ]
                    combined_pw_subs = []
                    for u in (semantic_pw_links + pw_sub_links + fallback_pw_paths):
                        if u not in combined_pw_subs and u != normalized_final_redirect:
                            combined_pw_subs.append(u)
                    combined_pw_subs = sorted(combined_pw_subs, key=_contact_link_priority)

                    for pw_sub_u in combined_pw_subs[:2]:
                        if is_allowed_by_robots(pw_sub_u, disallowed_paths):
                            pw_attempts_count += 1
                            pw_attempted_paths.append(pw_sub_u)
                            sub_pw_html, sub_pw_final, sub_pw_st, _ = await fetch_html_playwright_fallback(pw_sub_u)
                            if sub_pw_st == 'rendered' and sub_pw_html:
                                s_t, s_d, s_txt, s_e, s_p, s_s, _ = await loop.run_in_executor(
                                    thread_pool, parse_html_sync, sub_pw_html, sub_pw_final, effective_region
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

        normalize_tech_info_booleans(tech_info)
        detected_tech_list = tech_info['detected_technologies_list']

        google_ads_conf = compute_google_ads_confidence(
            tech_info.get('has_google_ads'),
            tech_info.get('tech_scan_completeness', 'full'),
            len(detected_tech_list)
        )

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

        non_legal_pairs = [
            (em, src) for em, src in ranked_emails_with_src
            if classify_email_type(em, brand_token) != 'legal_or_hr_inbox'
        ]
        selected_email_pairs = (non_legal_pairs or ranked_emails_with_src)[:5]
        all_emails_list = [em for em, _ in selected_email_pairs]

        top3_pairs = selected_email_pairs[:3]
        if top3_pairs:
            top3_checks = await asyncio.gather(
                *(verify_email_deliverability_deep(client, em, src) for em, src in top3_pairs)
            )
            deliverability_check = top3_checks[0]
            all_emails_deliverability_str = '; '.join(
                f'{em}: {chk}' for (em, _), chk in zip(top3_pairs, top3_checks) if chk
            )
        else:
            deliverability_check = None
            all_emails_deliverability_str = None

        all_emails_classification_str = (
            '; '.join(f'{em} ({classify_email_type(em, brand_token)})' for em in all_emails_list)
            if all_emails_list else None
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

        country_hint = detect_country_hint(canonical_domain, page_title, meta_desc, primary_phone, html)
        dm_search_query = build_linkedin_xray_query(canonical_domain, company_category, country_hint)

        gdpr_jurisdiction = _derive_gdpr_jurisdiction(canonical_domain, primary_phone, country_hint, html)
        is_eu_gdpr = gdpr_jurisdiction in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')

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

        if best_email and deliverability_check and any(
            err_tok in deliverability_check.lower()
            for err_tok in ('dns_error', 'lookup_failed', 'dns_timeout', 'invalid_no_mx')
        ):
            dns_warn = (
                f'Warning: DNS lookup failed for {best_email} '
                f'(temporary DoH failure or domain has no MX). Verify manually before outbound.'
            )
            if confidence_warning and confidence_warning != 'None':
                confidence_warning = f'{dns_warn} | {confidence_warning}'
            else:
                confidence_warning = dns_warn

        has_actionable_final = bool(best_email or primary_phone)
        final_status = 'success' if has_actionable_final else 'no_contacts_found'
        needs_rescan = bool(
            tech_info['tech_scan_completeness'] != 'full'
            or (not tech_info['has_gtm'] and not tech_info['has_ga4'] and pw_had_timeout_or_block)
        )

        all_phones_list = [p for p, _ in sorted_phones_with_src]
        human_tier = _derive_human_contact_tier(contact_quality_tier)
        legal_basis = 'legitimate_interest_b2b' if (best_email or dm_name or primary_phone) else None
        pii_fields_str = _derive_pii_fields(
            best_email, best_email_type, dm_name, primary_phone, dm_linkedin_url
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
            'compliance_note': COMPLIANCE_DEFAULT_NOTE,
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
                if final_status == 'success' and tech_info['detected_technologies_list']:
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
                        f"Tier: {result['contact_quality_tier_human']} | "
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
