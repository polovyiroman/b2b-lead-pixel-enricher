import asyncio
import ipaddress
import json
import os
import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

from .config import (
    CACHE_SCHEMA_VERSION,
    EU_GDPR_TLDS,
    KNOWN_JURISDICTION_HINTS,
    KNOWN_MARKETPLACE_DOMAINS,
    MULTI_PART_TLDS,
    PRIMARY_CONTACT_KEYWORDS,
    SECONDARY_CONTACT_KEYWORDS,
    truncate_error_msg,
)
from .contacts import (
    build_decision_makers_json_from_summary,
    classify_dm_source_type,
    extract_valid_phones,
    is_valid_person_name,
    normalize_executive_role,
    split_clean_executive_name,
    strip_role_tokens_from_name,
)
from .tech_detector import (
    build_evidence_json_from_cached_record,
    build_summary_from_cached_record,
)

_RUN_START_MONO = time.monotonic()

PW_GLOBAL_MAX_ATTEMPTS_PER_DOMAIN = 2

KNOWN_PW_HOPELESS: set[str] = {
    'zalando.de',
    'zalando.fr',
    'otto.de',
    'aboutyou.de',
    'coolblue.nl',
    'grammarly.com',
    'douglas.de',
}

KNOWN_POISONED_CACHE_RECOVERY: dict[str, dict[str, Any]] = {}

TECH_BOOL_FIELDS = (
    'has_meta_pixel',
    'has_tiktok_pixel',
    'has_google_ads',
    'has_linkedin_pixel',
    'has_pinterest_tag',
    'has_hubspot',
    'has_klaviyo',
    'has_ga4',
    'has_gtm',
    'has_sgtm',
)

EU_PHONE_PREFIXES = (
    '+49', '+43', '+41', '+33', '+31', '+32', '+48', '+420',
    '+39', '+34', '+351', '+46', '+45', '+358', '+353', '+30',
    '+36', '+40', '+421', '+359', '+385', '+386', '+370', '+371', '+372',
)

EU_VAT_BODY_RE = re.compile(
    r'\b(?:ATU|BE0?|DE|FR[A-Z0-9]{2}|NL|PL|CZ|IT|ES|SE|DK|FI|IE|PT)\d{8,12}\b'
)

UA_SPECIFIC_CYRILLIC_RE = re.compile(r'[іїєґІЇЄҐ]')


def remaining_run_seconds() -> float | None:
    raw_timeout = os.environ.get('ACTOR_TIMEOUT_AT') or os.environ.get('APIFY_TIMEOUT_AT')
    if raw_timeout:
        try:
            ts = float(raw_timeout)
            if ts > 1e12:
                ts /= 1000.0
            return max(0.0, ts - time.time())
        except Exception:
            pass
    raw_secs = os.environ.get('ACTOR_RUN_TIMEOUT_SECS')
    if raw_secs:
        try:
            elapsed = time.monotonic() - _RUN_START_MONO
            return max(0.0, float(raw_secs) - elapsed)
        except Exception:
            pass
    return None


def extract_etld_plus_one(host_or_url: str) -> tuple[str, str]:
    if not host_or_url:
        return '', ''
    raw = host_or_url.strip().lower()
    hostname = (urlparse(raw).hostname or '') if '://' in raw else raw.split('/')[0].split(':')[0]
    hostname = hostname.strip('.')
    while hostname.startswith('*.') or hostname.startswith('*. '):
        hostname = hostname[2:].strip()
    parts = [p for p in hostname.split('.') if p]
    if len(parts) < 2:
        return hostname, hostname
    last_two = f'{parts[-2]}.{parts[-1]}'
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return f'{parts[-3]}.{last_two}', parts[-3]
    return last_two, parts[-2]


async def check_hostname_ssrf_and_dns_async(hostname: str, timeout: float = 1.5) -> tuple[bool, str]:
    if not hostname:
        return False, 'empty_host'
    clean = hostname.strip().lower().rstrip('.')
    if clean in ('localhost', '0.0.0.0', 'broadcasthost') or clean.endswith(
        ('.local', '.internal', '.arpa', '.lan', '.localhost', '.home', '.corp', '.intranet')
    ):
        return False, 'ssrf_blocked'
    try:
        ip_lit = ipaddress.ip_address(clean)
        if (
            ip_lit.is_private
            or ip_lit.is_loopback
            or ip_lit.is_link_local
            or ip_lit.is_multicast
            or ip_lit.is_reserved
            or ip_lit.is_unspecified
        ):
            return False, 'ssrf_blocked'
        return True, 'ok'
    except ValueError:
        pass

    try:
        loop = asyncio.get_running_loop()
        addr_info = await asyncio.wait_for(loop.getaddrinfo(clean, None), timeout=timeout)
        if not addr_info:
            return False, 'dns_error'
        for item in addr_info:
            ip_obj = ipaddress.ip_address(item[4][0])
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False, 'ssrf_blocked'
        return True, 'ok'
    except (socket.gaierror, asyncio.TimeoutError):
        return False, 'dns_error'
    except Exception:
        return False, 'dns_error'


def guess_region_from_domain(domain: str) -> str | None:
    d = (domain or '').lower().strip().rstrip('.')
    if d.endswith('.ua'):
        return 'UA'
    if d.endswith('.de'):
        return 'DE'
    if d.endswith('.at'):
        return 'AT'
    if d.endswith('.ch'):
        return 'CH'
    if d.endswith('.pl'):
        return 'PL'
    if d.endswith('.fr'):
        return 'FR'
    if d.endswith('.es'):
        return 'ES'
    if d.endswith('.it'):
        return 'IT'
    if d.endswith('.nl'):
        return 'NL'
    if d.endswith('.be'):
        return 'BE'
    if d.endswith(('.uk', '.co.uk')):
        return 'GB'
    if d.endswith('.cz'):
        return 'CZ'
    if d.endswith('.se'):
        return 'SE'
    if d.endswith('.no'):
        return 'NO'
    if d.endswith('.dk'):
        return 'DK'
    if d.endswith('.fi'):
        return 'FI'
    if d.endswith('.pt'):
        return 'PT'
    return None


def resolve_effective_phone_region(canonical_domain: str, default_region: str, html: str = '') -> str:
    tld_reg = guess_region_from_domain(canonical_domain)
    if tld_reg:
        return tld_reg
    if html:
        sample = html[:25000]
        if '+380' in sample or 'ukraine' in sample.lower() or 'україна' in sample.lower() or UA_SPECIFIC_CYRILLIC_RE.search(sample):
            return 'UA'
        if '+49' in sample or 'impressum' in sample.lower():
            return 'DE'
        if '+44' in sample or 'united kingdom' in sample.lower():
            return 'GB'
    return (default_region or 'US').upper().strip()


def detect_country_hint(
    canonical_domain: str,
    page_title: str = '',
    meta_desc: str = '',
    primary_phone: str | None = None,
    html_sample: str = '',
) -> str:
    tld_reg = guess_region_from_domain(canonical_domain)
    if tld_reg:
        return tld_reg
    if primary_phone:
        p_clean = re.sub(r'[\s\-()]', '', primary_phone)
        if p_clean.startswith('+380'):
            return 'UA'
        if p_clean.startswith('+49'):
            return 'DE'
        if p_clean.startswith('+43'):
            return 'AT'
        if p_clean.startswith('+41'):
            return 'CH'
        if p_clean.startswith('+48'):
            return 'PL'
        if p_clean.startswith('+44'):
            return 'GB'
        if p_clean.startswith('+33'):
            return 'FR'
        if p_clean.startswith('+31'):
            return 'NL'
        if p_clean.startswith('+1'):
            return 'US'
    text_mix = f'{page_title} {meta_desc}'.lower()
    if UA_SPECIFIC_CYRILLIC_RE.search(f'{page_title} {meta_desc}') or any(
        w in text_mix for w in ('україн', 'київ', 'львів', 'доставка по україні', 'медіа про інтернет-маркетинг')
    ):
        return 'UA'
    if any(w in text_mix for w in ('versandkostenfrei', 'warenkorb', 'impressum', 'gmbh')):
        return 'DE'
    if html_sample:
        head_sample = html_sample[:30000]
        if UA_SPECIFIC_CYRILLIC_RE.search(head_sample):
            return 'UA'
        if EU_VAT_BODY_RE.search(head_sample):
            return 'DE'
    return 'US'


def derive_gdpr_jurisdiction(
    canonical_domain: str,
    primary_phone: str | None = None,
    country_hint: str = '',
    html_sample: str = '',
) -> str:
    """
    Виправлено (v24.1.1): Розпізнає українську кирилицю [іїєґІЇЄҐ] на .net/.com доменах
    (напр. netpeak.net) як UA_PDP, а європейські ціни/VAT на .com як EU_EEA_GDPR.
    """
    dom_low = (canonical_domain or '').lower().strip()
    if dom_low in KNOWN_JURISDICTION_HINTS:
        return KNOWN_JURISDICTION_HINTS[dom_low]

    if dom_low.endswith(('.uk', '.co.uk')):
        return 'UK_GDPR'
    if dom_low.endswith('.ch'):
        return 'CH_FADP'
    if dom_low.endswith('.ua'):
        return 'UA_PDP'
    if dom_low.endswith(EU_GDPR_TLDS):
        return 'EU_EEA_GDPR'

    p_clean = re.sub(r'[\s\-()]', '', primary_phone or '')
    if p_clean.startswith('+44'):
        return 'UK_GDPR'
    if p_clean.startswith('+41'):
        return 'CH_FADP'
    if p_clean.startswith('+380'):
        return 'UA_PDP'
    if any(p_clean.startswith(pref) for pref in EU_PHONE_PREFIXES):
        return 'EU_EEA_GDPR'

    hint_up = (country_hint or '').upper().strip()
    if hint_up in ('GB', 'UK'):
        return 'UK_GDPR'
    if hint_up == 'CH':
        return 'CH_FADP'
    if hint_up == 'UA':
        return 'UA_PDP'
    if hint_up in ('DE', 'AT', 'FR', 'IT', 'ES', 'NL', 'BE', 'PL', 'SE', 'NO', 'DK', 'FI', 'PT', 'CZ', 'RO', 'HU', 'SK', 'IE'):
        return 'EU_EEA_GDPR'

    if html_sample:
        head_sample = html_sample[:35000]
        if UA_SPECIFIC_CYRILLIC_RE.search(head_sample):
            return 'UA_PDP'
        if EU_VAT_BODY_RE.search(head_sample) or '€' in head_sample or '"EUR"' in head_sample:
            return 'EU_EEA_GDPR'
        if '£' in head_sample or '"GBP"' in head_sample:
            return 'UK_GDPR'

    return 'US_CAN_SPAM'


def derive_data_source_sensitivity(
    dm_source_type: str | None,
    email_source_type: str | None,
    gdpr_jurisdiction: str,
) -> str:
    dm_src = (dm_source_type or '').lower()
    em_src = (email_source_type or '').lower()
    if 'impressum' in dm_src or 'impressum' in em_src:
        if gdpr_jurisdiction in ('EU_EEA_GDPR', 'CH_FADP'):
            return 'impressum_statutory_disclosure_restricted'
        return 'statutory_legal_disclosure'
    if 'wikidata' in dm_src or 'serp_linkedin' in dm_src:
        return 'third_party_public_registry'
    if any(k in dm_src or k in em_src for k in ('contact_page', 'about_page', 'team_or_leadership', 'homepage')):
        return 'public_corporate_website'
    return 'none'


def derive_legal_basis_for_processing(
    canonical_domain: str,
    country_hint: str = '',
    has_personal_data: bool = False,
) -> str:
    jur = derive_gdpr_jurisdiction(canonical_domain, None, country_hint, '')
    dom_low = (canonical_domain or '').lower()
    if dom_low.endswith(('.de', '.at')) or (country_hint or '').upper() in ('DE', 'AT'):
        return (
            'gdpr_art_6_1_f_collection_only (DE_UWG_7_strict: unsolicited_cold_email_and_cold_calls_prohibited_without_consent; '
            'DSK_impressum_marketing_restriction_applies)'
        )
    if jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP'):
        return (
            'gdpr_art_6_1_f_legitimate_interest_b2b_research '
            '(verify_local_eprivacy_opt_in_rules_and_provide_opt_out)'
        )
    if jur == 'UA_PDP':
        return 'ua_pdp_public_corporate_contact_processing (opt_out_required)'
    return 'us_can_spam_b2b_commercial_outreach (physical_address_and_opt_out_required)'


def build_compliance_note(canonical_domain: str, country_hint: str = '') -> str:
    dom_low = (canonical_domain or '').lower()
    if dom_low.endswith(('.de', '.at')) or (country_hint or '').upper() in ('DE', 'AT'):
        return (
            '[Actor Retention Policy: 365d] DACH Compliance Notice: Under German §7 UWG and DSK guidance, '
            'contact details published solely to satisfy statutory Impressum obligations do not constitute '
            'consent for unsolicited cold email or cold telephone marketing. Verify prior opt-in or documented '
            'business relationship before initiating outreach.'
        )
    return (
        '[Actor Retention Policy: 365d] B2B Public Web Data: Collected from publicly accessible corporate pages '
        'for B2B account intelligence. Honor all data-subject opt-out and erasure requests under GDPR Art. 17 / CCPA.'
    )


def derive_pii_fields(
    best_email: str | None,
    best_email_type: str | None,
    dm_name: str | None,
    primary_phone: str | None,
    dm_linkedin_url: str | None,
) -> str:
    fields: list[str] = []
    if dm_name:
        fields.append('decision_maker_name')
    if dm_linkedin_url:
        fields.append('decision_maker_linkedin_url')
    if best_email:
        if best_email_type == 'personal_or_named_inbox':
            fields.append('personal_corporate_email')
        else:
            fields.append('generic_role_email')
    if primary_phone:
        fields.append('corporate_phone')
    return ', '.join(fields) if fields else 'none (corporate_tech_metadata_only)'


def derive_human_contact_tier(contact_quality_tier: str | None, company_category: str = '') -> str:
    if company_category == 'B2B Agency / Marketing Media':
        return 'Partner (Agency)'
    if company_category == 'Non-Profit / Education / Institution':
        return 'Do Not Contact'
    t = contact_quality_tier or ''
    if t.startswith('Tier A'):
        return 'Hot'
    if t.startswith('Tier B'):
        return 'Warm'
    if t.startswith('Tier C'):
        return 'Cold'
    if t.startswith('Tier D'):
        return 'Do Not Contact'
    return 'No Contact'


def derive_sales_actionability_class(sales_readiness_verdict: str | None, company_category: str = '') -> str:
    v = (sales_readiness_verdict or '').lower()
    if company_category == 'B2B Agency / Marketing Media' or 'partner pipeline' in v:
        return 'partner_agency'
    if 'disqualified' in v or 'unqualified' in v or 'unverified' in v:
        return 'unqualified'
    if 'sales-ready' in v:
        return 'sales_ready'
    if 'partnership-ready' in v:
        return 'partnership'
    if 'gatekeeper-ready' in v or 'contact-ready' in v:
        return 'gatekeeper'
    return 'tech_only'


def domain_weight(item: tuple[str, str, list[str]]) -> int:
    dom = item[0]
    if dom in KNOWN_PW_HOPELESS:
        return 2
    if dom in KNOWN_MARKETPLACE_DOMAINS:
        return 1
    return 0


def contact_link_priority(url: str) -> int:
    path = urlparse(url).path.lower()
    if any(k in path for k in ('impressum', 'mentions-legales', 'aviso-legal')):
        return 0
    if any(k in path for k in PRIMARY_CONTACT_KEYWORDS):
        return 1
    if any(k in path for k in ('about', 'team', 'leadership', 'management', 'founders')):
        return 2
    if any(k in path for k in SECONDARY_CONTACT_KEYWORDS):
        return 3
    return 4


def normalize_pw_empty_status(pw_status: str, pw_html: str) -> str:
    if pw_status == 'rendered' and (not pw_html or len(pw_html.strip()) < 1500):
        return 'launched_empty_shell'
    return pw_status


def compute_google_ads_confidence(
    has_google_ads: bool | None,
    scan_completeness: str,
    techs_count: int,
    has_cookie_banner: bool,
    pw_rendered_cleanly: bool,
) -> str:
    if has_google_ads is True:
        if scan_completeness == 'partial_csp_headers':
            return 'low_csp_allowlist_only'
        return 'verified_present'
    if scan_completeness in ('partial_blocked', 'partial_timeout', 'partial_csp_headers', 'partial_empty_render') or techs_count == 0:
        return 'unknown'
    if has_cookie_banner and not pw_rendered_cleanly:
        return 'unknown_consent_gated'
    return 'verified_absent'


def normalize_tech_info_booleans(tech_info: dict) -> None:
    comp = str(tech_info.get('tech_scan_completeness') or 'full')
    tech_list = tech_info.get('detected_technologies_list') or []
    is_hard_partial = (
        comp in ('partial_blocked', 'partial_timeout', 'partial_empty_render', 'partial_csp_headers')
        or (len(tech_list) == 0 and comp != 'full')
    )
    field_map = {
        'has_meta_pixel': 'Meta Pixel',
        'has_tiktok_pixel': 'TikTok Pixel',
        'has_google_ads': 'Google Ads Conversion',
        'has_linkedin_pixel': 'LinkedIn Insight Tag',
        'has_pinterest_tag': 'Pinterest Tag',
        'has_hubspot': 'HubSpot',
        'has_klaviyo': 'Klaviyo',
        'has_ga4': 'Google Analytics (GA4)',
        'has_gtm': 'Google Tag Manager',
        'has_sgtm': 'Server-Side GTM (sGTM)',
    }
    for bool_key, tech_label in field_map.items():
        val = tech_info.get(bool_key)
        if val is True or tech_label in tech_list:
            tech_info[bool_key] = True
        elif is_hard_partial:
            tech_info[bool_key] = None
        else:
            tech_info[bool_key] = False


def normalize_cached_record_booleans(rec: dict) -> None:
    tech_str = str(rec.get('detected_technologies') or '')
    tech_list = [x.strip() for x in tech_str.split(';') if x.strip()]
    rec['detected_technologies_list'] = tech_list
    normalize_tech_info_booleans(rec)
    rec.pop('detected_technologies_list', None)


def resolve_cache_merged_completeness(
    cache_sources_count: int,
    has_ga4_live: bool,
    pw_had_timeout_or_block: bool,
    live_found_something: bool = False,
    current_comp: str = 'full',
) -> str:
    if cache_sources_count > 0 and not has_ga4_live:
        return 'partial_cached'
    if pw_had_timeout_or_block and not live_found_something:
        return 'partial_blocked'
    return current_comp or 'full'


def heal_poisoned_cache_record(canonical_domain: str, c_rec: dict | None) -> dict | None:
    if canonical_domain in KNOWN_POISONED_CACHE_RECOVERY:
        patch = KNOWN_POISONED_CACHE_RECOVERY[canonical_domain]
        base = dict(c_rec) if isinstance(c_rec, dict) else {'status': 'success'}
        base.update(patch)
        return base
    return c_rec


def merge_missing_techs_from_cache(
    tech_info: dict,
    c_rec: dict,
    pw_used_flag: bool,
    pw_had_timeout_or_block: bool,
) -> tuple[dict, bool, int]:
    cached_techs = [x.strip() for x in str(c_rec.get('detected_technologies') or '').split(';') if x.strip()]
    if not cached_techs:
        return tech_info, False, 0

    live_list = list(tech_info.get('detected_technologies_list') or [])
    has_ga4_live = bool(tech_info.get('has_ga4'))
    live_found_something = len(live_list) > 0
    added_from_cache = 0

    for ct in cached_techs:
        if ct not in live_list:
            live_list.append(ct)
            added_from_cache += 1

    if added_from_cache > 0:
        tech_info['detected_technologies_list'] = live_list
        if not tech_info.get('all_ga4_ids') and c_rec.get('all_ga4_ids'):
            tech_info['all_ga4_ids'] = c_rec['all_ga4_ids']
            tech_info['all_ga4_ids_count'] = c_rec.get('all_ga4_ids_count')
            tech_info['ga4_detection_confidence'] = c_rec.get('ga4_detection_confidence') or 'Recovered from verified cache'
        if not tech_info.get('detected_cms') and c_rec.get('detected_cms'):
            tech_info['detected_cms'] = c_rec['detected_cms']
            tech_info['detected_cms_list'] = [x.strip() for x in str(c_rec['detected_cms']).split(';') if x.strip()]

        tech_info['tech_scan_completeness'] = resolve_cache_merged_completeness(
            added_from_cache,
            has_ga4_live,
            pw_had_timeout_or_block,
            live_found_something,
            str(tech_info.get('tech_scan_completeness') or 'full'),
        )
        tech_info['technology_evidence_summary'] = build_summary_from_cached_record(
            {'detected_technologies': '; '.join(live_list), 'all_ga4_ids': tech_info.get('all_ga4_ids')}
        )
        if not tech_info.get('technology_evidence_json'):
            tech_info['technology_evidence_json'] = build_evidence_json_from_cached_record(
                {'detected_technologies': '; '.join(live_list), 'all_ga4_ids': tech_info.get('all_ga4_ids')},
                source_label='cache_merged',
            )

    return tech_info, added_from_cache > 0, added_from_cache


def sanitize_cached_phones(
    primary_phone: str | None,
    all_phones: str | None,
    default_region: str = 'US',
) -> tuple[str | None, str | None, str | None]:
    raw_items: list[str] = []
    if primary_phone:
        raw_items.append(str(primary_phone))
    if all_phones:
        for p in str(all_phones).split(';'):
            if p.strip() and p.strip() not in raw_items:
                raw_items.append(p.strip())
    if not raw_items:
        return None, None, None

    valid_pairs = extract_valid_phones(' '.join(raw_items), [(r, '') for r in raw_items], default_region)
    if not valid_pairs:
        return None, None, None
    clean_list = [p for p, _ in valid_pairs]
    best_p = clean_list[0]
    e164_p = re.sub(r'[\s\-()]', '', best_p)
    return best_p, e164_p, '; '.join(clean_list)


def sanitize_cached_dms(
    dm_name: str | None,
    dm_role: str | None,
    dms_found_str: str | None,
    brand_root: str = '',
    dm_linkedin_url: str | None = None,
    fallback_source_url: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    clean_best_name: str | None = None
    clean_best_role: str | None = None

    if dm_name:
        stripped = strip_role_tokens_from_name(str(dm_name))
        if is_valid_person_name(stripped, brand_root):
            clean_best_name = stripped
            clean_best_role = normalize_executive_role(dm_role) or 'Executive / Decision Maker'

    valid_chunks: list[str] = []
    if dms_found_str:
        for chunk in str(dms_found_str).split(';'):
            chunk = chunk.strip()
            if not chunk:
                continue
            m = re.match(r'^(.+?)\s*\((.+?)\)\s*\[(.*?)\]$', chunk)
            if not m:
                continue
            c_n = strip_role_tokens_from_name(m.group(1))
            c_r = normalize_executive_role(m.group(2))
            c_u = m.group(3).strip() or (fallback_source_url or '')
            if is_valid_person_name(c_n, brand_root) and c_r:
                valid_chunks.append(f'{c_n} ({c_r}) [{c_u}]')
                if not clean_best_name:
                    clean_best_name = c_n
                    clean_best_role = c_r

    if clean_best_name and not valid_chunks:
        valid_chunks.append(f'{clean_best_name} ({clean_best_role}) [{fallback_source_url or ""}]')

    return clean_best_name, clean_best_role, ('; '.join(valid_chunks) if valid_chunks else None)


def build_safe_cache_payload(result_record: dict, prior_cached: dict | None = None) -> dict:
    payload = {k: v for k, v in result_record.items() if not k.startswith('_')}
    payload['_schema'] = CACHE_SCHEMA_VERSION
    comp = str(payload.get('tech_scan_completeness') or 'full')
    payload['_partial_write'] = (comp != 'full')
    if prior_cached and isinstance(prior_cached, dict):
        if not payload.get('detected_technologies') and prior_cached.get('detected_technologies'):
            payload['detected_technologies'] = prior_cached['detected_technologies']
            payload['all_ga4_ids'] = prior_cached.get('all_ga4_ids')
            payload['all_ga4_ids_count'] = prior_cached.get('all_ga4_ids_count')
    return payload


def build_timeout_stub(domain_key: str, aliases: list[str]) -> dict:
    aliases_str = '; '.join(aliases) if aliases else domain_key
    clean_url = f'https://{domain_key}/'
    return {
        'input_domain': domain_key,
        'canonical_domain': domain_key,
        'aliases': aliases_str,
        'input_was_redirected': False,
        'redirect_chain': None,
        'website_url': clean_url,
        'final_redirect_url': clean_url,
        'status': 'run_timeout_unfinished',
        'cached_snapshot_source': 'none (run_timeout)',
        'cached_snapshot_age_days': None,
        'error_message': 'Domain processing exceeded run time budget',
        'data_quality_score': 0,
        'account_opportunity_score': 0,
        'contactability_level': 'unreached',
        'actionable_priority_score': 0,
        'sales_readiness_verdict': 'Unverified (Run Time Budget Exceeded)',
        'sales_actionability_class': 'unqualified',
        'company_category': 'General Business / Corporate',
        'category_confidence': 'low',
        'marketplace_platform': domain_key in KNOWN_MARKETPLACE_DOMAINS,
        'marketplace_platform_pollution_detected': False,
        'icp_fit_tier': 'Unverified (Timeout)',
        'technical_signal_strength': None,
        'tech_scan_completeness': 'partial_timeout',
        'tech_rescan_needed': True,
        'contact_quality_tier': 'Tier F (Timeout)',
        'contact_quality_tier_human': 'No Contact',
        'contact_enrichment_status': 'run_timeout_unfinished',
        'data_confidence_warning': 'Run time budget exceeded before domain completed.',
        'gdpr_eu_domain': domain_key.endswith(EU_GDPR_TLDS),
        'gdpr_jurisdiction': derive_gdpr_jurisdiction(domain_key),
        'legal_basis_for_processing': None,
        'data_source_sensitivity': 'none',
        'data_subject_can_request_deletion': True,
        'data_retention_policy_days': 365,
        'personal_data_fields_in_record': 'none (timeout)',
        'compliance_note': build_compliance_note(domain_key),
        'playwright_available': True,
        'playwright_used': False,
        'playwright_status': 'skipped_timeout',
        'playwright_attempts_count': 0,
        'playwright_paths_attempted': None,
        'page_title': None,
        'meta_description': None,
        'best_email': None,
        'email_domain': None,
        'best_email_type': None,
        'best_email_confidence': 'NONE',
        'dm_predicted_email': None,
        'dm_predicted_email_status': 'not_generated',
        'email_source_type': None,
        'email_source_note': None,
        'named_email_owner_role_hint': None,
        'email_deliverability_check': None,
        'email_verification_confidence': 'NONE',
        'all_emails_deliverability': None,
        'all_emails_classification': None,
        'email_source_url': None,
        'compliance_dpo_email': None,
        'primary_phone': None,
        'e164_phone': None,
        'whatsapp_business_phone': None,
        'phone_availability': 'not_public',
        'phone_source_url': None,
        'decision_maker_name': None,
        'dm_first_name': None,
        'dm_last_name': None,
        'decision_maker_role': None,
        'decision_maker_scope': 'none',
        'decision_maker_source_url': None,
        'decision_maker_source_type': None,
        'decision_makers_found': None,
        'decision_makers_json': None,
        'decision_maker_linkedin_url': None,
        'company_linkedin_people_url': None,
        'decision_maker_search_query': None,
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
        'sales_opportunity': 'Timeout reached before stack analysis completed',
        'next_best_action': 'Re-run domain in a smaller batch',
        'primary_sales_gap': None,
        'sales_gap_confidence': None,
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
        'detected_payment_gateways': [],
        'martech_maturity_tier': 'Unverified / Minimal',
        'min_estimated_saas_spend_usd': 0,
        'estimated_saas_spend_min_usd': 0,
        'estimated_saas_spend_max_usd': 0,
        'spend_estimation_basis': [],
        'estimated_markets_count': 1,
        'detected_market_locales': [],
        'catalog_estimated_skus': None,
        'ecom_avg_price': None,
        'ecom_currency': None,
        'logistics_and_returns_stack': [],
        'ads_rpc_status': 'not_checked',
        'ads_active_last_30d': None,
        'active_ad_formats': [],
        'advertiser_sister_domains': [],
        'detected_marketing_agency': None,
        'open_positions_total': None,
        'hiring_departments': [],
        'hiring_marketing_or_data_roles': None,
        'dmarc_policy': None,
        'email_security_gateway': None,
        'plain_text_outreach_required': False,
        'tls_trust_status': 'not_checked',
        'prospect_iana_timezone': 'Europe/London',
        'recommended_outreach_lang': 'en',
        'corporate_lifecycle_status': 'UNREACHABLE',
        'outreach_dedup_status': 'PRIMARY_OUTREACH_TARGET',
        'recent_change_triggers': [],
        'compliance_ids': {},
        'provenance_meta': {},
        'all_emails': None,
        'all_phones': None,
        'last_checked_at': '',
    }
