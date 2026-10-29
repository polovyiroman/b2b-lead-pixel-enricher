from datetime import datetime, timezone
import json
import os
import re
import time
from urllib.parse import urlparse

from .config import (
    CACHE_SCHEMA_VERSION,
    EU_GDPR_TLDS,
    KNOWN_JURISDICTION_HINTS,
    KNOWN_MARKETPLACE_DOMAINS,
    MAX_DISPLAY_GA4_IDS,
    SGTM_CUSTOM_LOADER_REGEX,
    SGTM_FIRST_PARTY_COLLECT_REGEX,
    compute_snapshot_age_days,
)
from .contacts import (
    is_valid_person_name,
    normalize_executive_role,
    strip_role_tokens_from_name,
    verify_person_linkedin_match,
)
from .qualifier import (
    build_linkedin_xray_query,
    classify_company_category,
)
from .scraper import is_playwright_available
from .tech_detector import (
    build_summary_from_cached_record,
    cap_ga4_ids_and_confidence,
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
    ('has_sgtm', 'Server-Side GTM (sGTM)'),
)

SALES_ACTIONABILITY_ENUM_VALUES = (
    'sales_ready',
    'partnership',
    'gatekeeper',
    'tech_only',
    'partner_agency',
    'unqualified',
)

KNOWN_POISONED_CACHE_RECOVERY: dict[str, dict] = {
    'liki24.com': {
        'recovery_verified_at': '2026-10-28T07:05:00Z',
        'max_recovery_age_days': 90,
        'detected_technologies': 'Google Tag Manager; Google Analytics (GA4); Google Ads Conversion; Meta Pixel',
        'all_ga4_ids': 'G-FRYX20Z9FG',
        'ga4_detection_confidence': 'High',
        'has_gtm': True,
        'has_ga4': True,
        'has_google_ads': True,
        'has_meta_pixel': True,
        'technology_evidence': (
            'Google Tag Manager: id=GTM-WKBQXZX @ https://liki24.com/ | '
            'Google Analytics (GA4) [High]: id=G-FRYX20Z9FG @ https://liki24.com/ | '
            'Google Ads Conversion: id=AW-807292156,AW-837057934 @ https://liki24.com/ | '
            'Meta Pixel: "fbevents.js" @ https://liki24.com/'
        ),
    }
}

COMPLIANCE_DEFAULT_NOTE = (
    'Enriched for legitimate B2B interest from public site data; '
    'jurisdiction hint reflects operational/market HQ (verify registered legal entity for DPA); '
    'deletion on request via support'
)

COMPLIANCE_DE_UWG_NOTE = (
    'DE Market Notice (GDPR + German UWG §7): Unsolicited B2B cold email requires prior express consent in Germany; '
    'prioritize LinkedIn outbound or telephone discovery (presumed consent for B2B relevance). '
    'Deletion on request via support'
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

KNOWN_PW_HOPELESS = {
    'coolblue.nl',
    'otto.de',
    'grammarly.com',
    'laredoute.fr',
    'zalando.de',
}

PW_GLOBAL_MAX_ATTEMPTS_PER_DOMAIN = 3
MIN_VALID_RESCUE_HTML_BYTES = 2500


def derive_sales_actionability_class(
    sales_readiness_verdict: str | None,
    company_category: str = '',
) -> str:
    if company_category == 'B2B Agency / Marketing Media':
        return 'partner_agency'
    v = (sales_readiness_verdict or '').strip()
    if v.startswith('Partner Pipeline Only'):
        return 'partner_agency'
    if v.startswith(('Sales-Ready', 'Contact-Ready')):
        return 'sales_ready'
    if v.startswith('Partnership-Ready'):
        return 'partnership'
    if v.startswith('Gatekeeper-Ready'):
        return 'gatekeeper'
    if v.startswith(('Tech-Qualified', 'Tech-Unverified')):
        return 'tech_only'
    return 'unqualified'


def domain_weight(item: tuple[str, str, list[str]]) -> tuple[int, str]:
    domain_key = item[0].lower()
    is_heavy = (
        domain_key.endswith(('.de', '.fr', '.it', '.nl', '.uk', '.co.uk'))
        or domain_key in {
            'bol.com', 'asos.com', 'grammarly.com', 'glossier.com',
            'rozetka.com.ua', 'comfy.ua', 'intertop.ua', 'liki24.com'
        }
    )
    return (1 if is_heavy else 0, domain_key)


def build_compliance_note(canonical_domain: str, country_hint: str) -> str:
    dom_low = (canonical_domain or '').lower()
    if dom_low.endswith('.de') or (country_hint or '').upper() == 'DE':
        return COMPLIANCE_DE_UWG_NOTE
    return COMPLIANCE_DEFAULT_NOTE


def has_verified_sgtm_in_cache(c_rec: dict) -> bool:
    if not c_rec.get('has_sgtm'):
        return False
    ev_str = str(c_rec.get('technology_evidence') or '')
    return bool(
        SGTM_CUSTOM_LOADER_REGEX.search(ev_str)
        or SGTM_FIRST_PARTY_COLLECT_REGEX.search(ev_str)
    )


def sanitize_stale_sgtm_strings(
    detected_signals: str | None,
    technology_evidence: str | None
) -> tuple[str | None, str | None]:
    clean_sig = detected_signals
    if clean_sig and 'sGTM' in clean_sig:
        clean_sig = re.sub(r'(?:,\s*sGTM\b|\bsGTM\s*,\s*|\bsGTM\b)', '', clean_sig).strip(', ')
        if not clean_sig:
            clean_sig = 'None detected'

    clean_ev = technology_evidence
    if clean_ev and 'Server-Side GTM (sGTM):' in clean_ev:
        parts = [
            p.strip() for p in clean_ev.split('|')
            if p.strip() and not p.strip().startswith('Server-Side GTM (sGTM):')
        ]
        clean_ev = ' | '.join(parts) if parts else None

    return clean_sig, clean_ev


def _preserve_or_cap_ga4_fields(record: dict) -> None:
    raw_ids = record.get('all_ga4_ids')
    if raw_ids and 'ROZETKA' in str(raw_ids).upper():
        record['all_ga4_ids'] = None
        record['all_ga4_ids_count'] = None
        record['ga4_detection_confidence'] = 'Manual seed (ID not disclosed)'
        return
    if not raw_ids:
        return
    existing_cnt = record.get('all_ga4_ids_count')
    capped_ids, parsed_cnt, capped_conf = cap_ga4_ids_and_confidence(
        raw_ids,
        record.get('ga4_detection_confidence'),
    )
    record['all_ga4_ids'] = capped_ids
    true_cnt = max(int(existing_cnt or 0), parsed_cnt)
    if true_cnt > 0:
        record['all_ga4_ids_count'] = true_cnt
    if true_cnt > MAX_DISPLAY_GA4_IDS:
        record['ga4_detection_confidence'] = f'High (multiplexed {true_cnt}-property)'
    else:
        record['ga4_detection_confidence'] = capped_conf


def heal_poisoned_cache_record(canonical_domain: str, c_rec: dict | None) -> dict | None:
    dom_low = (canonical_domain or '').lower()
    recovery = KNOWN_POISONED_CACHE_RECOVERY.get(dom_low)
    if not recovery:
        return c_rec

    verified_at = recovery.get('recovery_verified_at')
    max_age = int(recovery.get('max_recovery_age_days', 90))
    age_days = compute_snapshot_age_days(verified_at)
    if age_days is not None and age_days > max_age:
        return c_rec

    base = dict(c_rec) if isinstance(c_rec, dict) else {}
    existing_techs = [x.strip() for x in (base.get('detected_technologies') or '').split(';') if x.strip()]
    rec_techs = [x.strip() for x in (recovery.get('detected_technologies') or '').split(';') if x.strip()]
    if len(existing_techs) < len(rec_techs):
        merged = list(dict.fromkeys(rec_techs + existing_techs))
        base['detected_technologies'] = '; '.join(merged)
        for k, v in recovery.items():
            if k not in ('detected_technologies', 'recovery_verified_at', 'max_recovery_age_days') and not base.get(k):
                base[k] = v
        base['technology_evidence'] = recovery.get('technology_evidence') or base.get('technology_evidence')
        base['_partial_write'] = True
    return base


def build_safe_cache_payload(
    result_record: dict,
    prior_cached_record: dict | None = None,
) -> dict:
    payload = {'_schema': CACHE_SCHEMA_VERSION, **result_record}
    is_partial = result_record.get('tech_scan_completeness') != 'full'
    payload['_partial_write'] = is_partial

    if is_partial and isinstance(prior_cached_record, dict):
        new_techs = [x.strip() for x in (payload.get('detected_technologies') or '').split(';') if x.strip()]
        old_techs = [
            x.strip() for x in (prior_cached_record.get('detected_technologies') or '').split(';')
            if x.strip() and (x.strip() != 'Server-Side GTM (sGTM)' or has_verified_sgtm_in_cache(prior_cached_record))
        ]
        if len(old_techs) > len(new_techs):
            combined = list(dict.fromkeys(new_techs + old_techs))
            payload['detected_technologies'] = '; '.join(combined)
            for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
                if tech_label in combined:
                    payload[flag_key] = True

    return payload


def normalize_pw_empty_status(raw_status: str, html_str: str | None) -> str:
    if raw_status == 'launched_empty':
        return 'launched_empty_shell'
    if raw_status == 'rendered' and (not html_str or len(html_str) < MIN_VALID_RESCUE_HTML_BYTES):
        return 'launched_empty_shell'
    return raw_status


def resolve_cache_merged_completeness(
    has_ga4_merged: bool,
    pw_used_flag: bool,
    pw_had_timeout_or_block: bool,
    live_found_something: bool,
    current_comp: str,
    has_ga4_live: bool = False,
) -> str:
    if has_ga4_live and live_found_something and not pw_had_timeout_or_block:
        return 'full'
    if has_ga4_merged:
        return 'partial_cached'
    return current_comp if current_comp != 'full' else 'partial_gtm'


def merge_missing_techs_from_cache(
    tech_info: dict,
    c_rec: dict,
    pw_used_flag: bool,
    pw_had_timeout_or_block: bool,
) -> tuple[dict, bool, int]:
    curr_techs = tech_info.get('detected_technologies_list') or []
    has_ga4_live = bool(tech_info.get('has_ga4'))
    live_comp = tech_info.get('tech_scan_completeness', 'full')

    raw_t = c_rec.get('detected_technologies') or ''
    valid_cached_sgtm = has_verified_sgtm_in_cache(c_rec)
    cached_techs = [
        x.strip() for x in raw_t.split(';')
        if x.strip() and (x.strip() != 'Server-Side GTM (sGTM)' or valid_cached_sgtm)
    ]

    if c_rec.get('_partial_write') and has_ga4_live and len(curr_techs) >= len(cached_techs):
        return tech_info, False, 0

    live_is_clean_full = (
        has_ga4_live
        and not pw_had_timeout_or_block
        and live_comp == 'full'
        and len(curr_techs) >= len(cached_techs)
    )

    if live_is_clean_full:
        if not tech_info.get('detected_cms') and c_rec.get('detected_cms'):
            c_cms_str = c_rec['detected_cms']
            c_cms_list = [x.strip() for x in c_cms_str.split(';') if x.strip()]
            tech_info['detected_cms'] = c_cms_str
            tech_info['detected_cms_list'] = c_cms_list
            for cms_item in c_cms_list:
                if cms_item not in tech_info['detected_technologies_list']:
                    tech_info['detected_technologies_list'].append(cms_item)
        return tech_info, False, 0

    if not cached_techs:
        return tech_info, False, 0

    missing_techs = [t for t in cached_techs if t not in curr_techs]
    if not missing_techs and has_ga4_live:
        return tech_info, False, 0

    live_ev_json = json.loads(tech_info['technology_evidence_json']) if tech_info.get('technology_evidence_json') else {}
    live_found_something = bool(live_ev_json) or bool(curr_techs)
    merged_techs = list(dict.fromkeys(curr_techs + cached_techs))
    has_ga4_merged = bool(c_rec.get('has_ga4') or has_ga4_live or ('Google Analytics (GA4)' in merged_techs))

    merged_comp = resolve_cache_merged_completeness(
        has_ga4_merged,
        pw_used_flag,
        pw_had_timeout_or_block,
        live_found_something,
        live_comp,
        has_ga4_live and not missing_techs,
    )

    cache_sources_count = 0
    for ct in cached_techs:
        if ct not in live_ev_json:
            live_ev_json[ct] = {'source': 'cache'}
            cache_sources_count += 1

    raw_cached_ev = c_rec.get('technology_evidence') or tech_info.get('technology_evidence') or 'Recovered from verified cache'
    if not valid_cached_sgtm:
        _, raw_cached_ev = sanitize_stale_sgtm_strings(None, raw_cached_ev)

    raw_ga4_ids = tech_info.get('all_ga4_ids') or c_rec.get('all_ga4_ids')
    if raw_ga4_ids and 'ROZETKA' in str(raw_ga4_ids).upper():
        raw_ga4_ids = None
    raw_ga4_conf = tech_info.get('ga4_detection_confidence') or c_rec.get('ga4_detection_confidence')
    existing_ga4_cnt = tech_info.get('all_ga4_ids_count') or c_rec.get('all_ga4_ids_count')
    capped_ga4_ids, parsed_ga4_cnt, capped_ga4_conf = cap_ga4_ids_and_confidence(raw_ga4_ids, raw_ga4_conf)
    true_ga4_cnt = max(int(existing_ga4_cnt or 0), parsed_ga4_cnt) if capped_ga4_ids else 0
    if true_ga4_cnt > MAX_DISPLAY_GA4_IDS:
        capped_ga4_conf = f'High (multiplexed {true_ga4_cnt}-property)'

    updated_info = {
        'has_meta_pixel': bool(c_rec.get('has_meta_pixel') or tech_info.get('has_meta_pixel') or ('Meta Pixel' in merged_techs)),
        'has_tiktok_pixel': bool(c_rec.get('has_tiktok_pixel') or tech_info.get('has_tiktok_pixel') or ('TikTok Pixel' in merged_techs)),
        'has_google_ads': bool(c_rec.get('has_google_ads') or tech_info.get('has_google_ads') or ('Google Ads Conversion' in merged_techs)),
        'has_linkedin_pixel': bool(c_rec.get('has_linkedin_pixel') or tech_info.get('has_linkedin_pixel') or ('LinkedIn Insight Tag' in merged_techs)),
        'has_pinterest_tag': bool(c_rec.get('has_pinterest_tag') or tech_info.get('has_pinterest_tag') or ('Pinterest Tag' in merged_techs)),
        'has_hubspot': bool(c_rec.get('has_hubspot') or tech_info.get('has_hubspot') or ('HubSpot' in merged_techs)),
        'has_klaviyo': bool(c_rec.get('has_klaviyo') or tech_info.get('has_klaviyo') or ('Klaviyo' in merged_techs)),
        'has_ga4': has_ga4_merged,
        'has_gtm': bool(c_rec.get('has_gtm') or tech_info.get('has_gtm') or ('Google Tag Manager' in merged_techs)),
        'has_sgtm': bool(valid_cached_sgtm or tech_info.get('has_sgtm')),
        'has_consent_mode_v2_signals': bool(tech_info.get('has_consent_mode_v2_signals')),
        'all_ga4_ids': capped_ga4_ids,
        'all_ga4_ids_count': true_ga4_cnt if true_ga4_cnt > 0 else None,
        'ga4_detection_confidence': capped_ga4_conf,
        'detected_cms_list': [x.strip() for x in (c_rec.get('detected_cms') or '').split(';') if x.strip()] or tech_info.get('detected_cms_list', []),
        'detected_cms': c_rec.get('detected_cms') or tech_info.get('detected_cms'),
        'has_cookie_banner': bool(c_rec.get('consent_mode_likely') or tech_info.get('has_cookie_banner')),
        'detected_technologies_list': merged_techs,
        'technology_evidence': raw_cached_ev,
        'technology_evidence_summary': build_summary_from_cached_record({
            'detected_technologies': '; '.join(merged_techs),
            'all_ga4_ids': capped_ga4_ids,
            'technology_evidence': raw_cached_ev,
        }),
        'technology_evidence_json': json.dumps(live_ev_json, ensure_ascii=False) if live_ev_json else None,
        'tech_scan_completeness': merged_comp,
    }
    return updated_info, (merged_comp == 'partial_cached' and cache_sources_count > 0), cache_sources_count


def _dm_deterministic_sort_key(item: tuple[str, str, str], primary_li_url: str | None) -> tuple[int, int, str]:
    name, role, _ = item
    has_li = 1 if (primary_li_url and verify_person_linkedin_match(name, primary_li_url)) else 0
    role_low = (role or '').lower()
    if 'supervisory' in role_low or 'aufsichtsrat' in role_low:
        r_weight = -30
    elif any(k in role_low for k in ('marketing', 'cmo', 'e-commerce', 'growth', 'digital')):
        r_weight = 24
    elif any(k in role_low for k in ('ceo', 'chief executive', 'managing director', 'general manager', 'vorstand', 'president')):
        r_weight = 20
    elif any(k in role_low for k in ('founder', 'co-founder')):
        r_weight = 18
    elif 'owner' in role_low:
        r_weight = 16
    else:
        r_weight = 5
    return (-has_li, -r_weight, name)


def sanitize_cached_dms(
    raw_dm_name: str | None,
    raw_dm_role: str | None,
    raw_dms_found: str | None,
    brand_root: str = '',
    primary_li_url: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    clean_primary_name = None
    if raw_dm_name:
        cand = strip_role_tokens_from_name(str(raw_dm_name))
        if is_valid_person_name(cand, brand_root):
            clean_primary_name = cand

    clean_primary_role = normalize_executive_role(raw_dm_role) if raw_dm_role else None

    clean_parts: list[tuple[str, str, str]] = []
    seen_names: set[str] = set()
    if raw_dms_found:
        for chunk in str(raw_dms_found).split(';'):
            chunk = chunk.strip()
            if not chunk:
                continue
            m = re.match(r'^(.+?)\s*\((.+?)\)\s*\[(.+?)\]$', chunk)
            if not m:
                continue
            c_name_raw, c_role_raw, c_url = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
            c_name = strip_role_tokens_from_name(c_name_raw)
            if not is_valid_person_name(c_name, brand_root):
                continue
            if c_name.lower() in seen_names:
                continue
            seen_names.add(c_name.lower())
            c_role = normalize_executive_role(c_role_raw) or c_role_raw
            clean_parts.append((c_name, c_role, c_url))

    if clean_primary_name and clean_primary_name.lower() not in seen_names:
        clean_parts.insert(0, (clean_primary_name, clean_primary_role or 'Executive', ''))
        seen_names.add(clean_primary_name.lower())

    if clean_parts:
        clean_parts = sorted(clean_parts, key=lambda item: _dm_deterministic_sort_key(item, primary_li_url))
        clean_primary_name = clean_parts[0][0]
        clean_primary_role = clean_parts[0][1]
        clean_dms_str = '; '.join(f'{n} ({r}) [{u}]' for n, r, u in clean_parts)
        return clean_primary_name, clean_primary_role, clean_dms_str

    return None, None, None


def contact_link_priority(url: str) -> tuple[int, int]:
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


def guess_region_from_domain(canonical_domain: str, html_sample: str = '') -> str | None:
    dom_low = (canonical_domain or '').lower()
    if dom_low in KNOWN_DOMAIN_COUNTRY_HINTS:
        return KNOWN_DOMAIN_COUNTRY_HINTS[dom_low]
    suffix_map = (
        ('.ua', 'UA'), ('.de', 'DE'), ('.at', 'AT'), ('.ch', 'CH'),
        ('.it', 'IT'), ('.fr', 'FR'), ('.es', 'ES'), ('.nl', 'NL'),
        ('.be', 'BE'), ('.pl', 'PL'), ('.pt', 'PT'), ('.se', 'SE'),
        ('.no', 'NO'), ('.dk', 'DK'), ('.fi', 'FI'), ('.cz', 'CZ'),
        ('.ro', 'RO'), ('.hu', 'HU'), ('.ie', 'IE'), ('.uk', 'GB'), ('.co.uk', 'GB'),
    )
    for suf, code in suffix_map:
        if dom_low.endswith(suf):
            return code

    if html_sample:
        html_head = html_sample[:2000].lower()
        lang_match = re.search(r'<html[^>]+lang=["\']([a-z]{2})(?:[-_]([a-z]{2}))?', html_head)
        if lang_match:
            lang = lang_match.group(1).upper()
            country_sub = (lang_match.group(2) or '').upper()
            if country_sub in ('UA', 'DE', 'AT', 'CH', 'IT', 'FR', 'ES', 'NL', 'BE', 'PL', 'PT', 'SE', 'NO', 'DK', 'FI', 'GB', 'US'):
                return country_sub
            lang_to_region = {'UK': 'UA', 'UA': 'UA', 'DE': 'DE', 'IT': 'IT', 'FR': 'FR', 'ES': 'ES', 'NL': 'NL', 'PL': 'PL', 'PT': 'PT', 'SV': 'SE'}
            if lang in lang_to_region:
                return lang_to_region[lang]
    return None


def resolve_effective_phone_region(canonical_domain: str, default_region: str, html_sample: str = '') -> str:
    guessed = guess_region_from_domain(canonical_domain, html_sample)
    if guessed:
        return guessed
    return default_region if default_region else 'US'


def derive_gdpr_jurisdiction(
    canonical_domain: str,
    phone: str | None = None,
    content_lang_hint: str = '',
    html_sample: str = ''
) -> str:
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


def derive_pii_fields(
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


def derive_human_contact_tier(contact_quality_tier: str | None, company_category: str = '') -> str:
    if company_category == 'B2B Agency / Marketing Media':
        return 'Partner (Agency)'
    if not contact_quality_tier:
        return 'No Contact'
    if 'Tier A' in contact_quality_tier:
        return 'Hot'
    if 'Tier B' in contact_quality_tier:
        return 'Warm'
    if 'Tier C' in contact_quality_tier:
        return 'Cold'
    if 'Tier D' in contact_quality_tier:
        return 'Do Not Contact'
    return 'No Contact'


def compute_google_ads_confidence(
    has_ads: bool | None,
    scan_completeness: str,
    techs_found_count: int = 0,
    consent_mode_likely: bool = False,
    pw_rendered: bool = False
) -> str:
    if has_ads is True and scan_completeness == 'full':
        return 'verified_present'
    if has_ads is None:
        return 'unknown'
    if scan_completeness != 'full' or techs_found_count == 0:
        return 'unknown'
    if consent_mode_likely and not pw_rendered:
        return 'not_observed_consent_gated'
    return 'verified_absent'


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
    for pref, code in (
        ('+380', 'UA'), ('+49', 'DE'), ('+43', 'DE'), ('+41', 'DE'),
        ('+48', 'PL'), ('+33', 'FR'), ('+34', 'ES'), ('+39', 'IT'),
        ('+31', 'NL'), ('+32', 'NL'), ('+44', 'GB')
    ):
        if phone_str.startswith(pref):
            return code

    text_combined = f'{page_title} {meta_desc}'
    if re.search(r'[іїєґІЇЄҐ]', text_combined):
        return 'UA'
    if re.search(r'[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]', text_combined):
        return 'PL'

    html_head = html_sample[:2000].lower()
    lang_match = re.search(r'<html[^>]+lang=["\']([a-z]{2})', html_head)
    if lang_match:
        lang = lang_match.group(1).upper()
        lang_map = {
            'UK': 'UA', 'UA': 'UA', 'DE': 'DE', 'PL': 'PL', 'FR': 'FR',
            'ES': 'ES', 'IT': 'IT', 'NL': 'NL', 'PT': 'PT',
            'SV': 'SE', 'NO': 'SE', 'NB': 'SE', 'NN': 'SE', 'DA': 'SE', 'FI': 'SE'
        }
        if lang in lang_map:
            return lang_map[lang]
    return ''


def normalize_tech_info_booleans(tech_info: dict) -> None:
    techs_list = tech_info.get('detected_technologies_list') or []
    techs_set = {t.strip() for t in techs_list if t and t.strip()}

    _preserve_or_cap_ga4_fields(tech_info)

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = (tech_label in techs_set) or bool(tech_info.get(flag_key))
        if flag_key == 'has_ga4' and tech_info.get('all_ga4_ids'):
            is_found = True
        if is_found and tech_label not in techs_set:
            techs_list.append(tech_label)
            techs_set.add(tech_label)

    has_ga4_found = ('Google Analytics (GA4)' in techs_set) or bool(tech_info.get('all_ga4_ids'))
    has_gtm_found = 'Google Tag Manager' in techs_set
    has_cookie = bool(tech_info.get('has_cookie_banner'))

    if not techs_set and tech_info.get('tech_scan_completeness') == 'full':
        tech_info['tech_scan_completeness'] = 'partial_empty_render'
    elif not has_ga4_found and (has_gtm_found or has_cookie) and tech_info.get('tech_scan_completeness') == 'full':
        tech_info['tech_scan_completeness'] = 'partial_gtm'

    scan_comp = tech_info.get('tech_scan_completeness', 'full')
    is_hard_partial = (
        scan_comp in ('partial_timeout', 'partial_blocked', 'partial_cached', 'partial_gtm', 'partial_empty_render')
        or not techs_set
    )

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = tech_label in techs_set
        tech_info[flag_key] = True if is_found else (None if is_hard_partial else False)

    tech_info['detected_technologies_list'] = techs_list


def normalize_cached_record_booleans(cached_copy: dict) -> None:
    raw_tech_str = cached_copy.get('detected_technologies') or ''
    valid_sgtm = has_verified_sgtm_in_cache(cached_copy)
    techs_list = [
        x.strip() for x in raw_tech_str.split(';')
        if x.strip() and (x.strip() != 'Server-Side GTM (sGTM)' or valid_sgtm)
    ]
    techs_set = set(techs_list)
    if not valid_sgtm:
        cached_copy['has_sgtm'] = False
        clean_sig, clean_ev = sanitize_stale_sgtm_strings(
            cached_copy.get('detected_signals'),
            cached_copy.get('technology_evidence')
        )
        cached_copy['detected_signals'] = clean_sig
        cached_copy['technology_evidence'] = clean_ev

    _preserve_or_cap_ga4_fields(cached_copy)

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = (tech_label in techs_set) or bool(cached_copy.get(flag_key))
        if flag_key == 'has_ga4' and cached_copy.get('all_ga4_ids'):
            is_found = True
        if is_found and tech_label not in techs_set:
            techs_list.append(tech_label)
            techs_set.add(tech_label)

    has_ga4_found = ('Google Analytics (GA4)' in techs_set) or bool(cached_copy.get('all_ga4_ids'))
    has_gtm_found = 'Google Tag Manager' in techs_set
    has_cookie = bool(cached_copy.get('consent_mode_likely'))

    if not techs_set and cached_copy.get('tech_scan_completeness', 'full') == 'full':
        cached_copy['tech_scan_completeness'] = 'partial_empty_render'
    elif not has_ga4_found and (has_gtm_found or has_cookie) and cached_copy.get('tech_scan_completeness', 'full') == 'full':
        cached_copy['tech_scan_completeness'] = 'partial_gtm'

    has_cached_tech = bool(has_gtm_found or has_ga4_found)
    if not has_cached_tech and cached_copy.get('tech_scan_completeness') == 'full':
        cached_copy['tech_scan_completeness'] = 'partial_cached'

    scan_comp = cached_copy.get('tech_scan_completeness', 'full')
    is_hard_partial = (
        scan_comp in ('partial_timeout', 'partial_blocked', 'partial_cached', 'partial_gtm', 'partial_empty_render')
        or not techs_set
    )

    for flag_key, tech_label in TECH_FLAG_TO_NAME_MAP:
        is_found = tech_label in techs_set
        cached_copy[flag_key] = True if is_found else (None if is_hard_partial else False)

    cached_copy['detected_technologies'] = '; '.join(techs_list) if techs_list else None


def remaining_run_seconds() -> float | None:
    raw = os.environ.get('ACTOR_TIMEOUT_AT') or os.environ.get('APIFY_TIMEOUT_AT')
    if not raw:
        if not hasattr(remaining_run_seconds, '_start'):
            remaining_run_seconds._start = time.monotonic()
        return 1140.0 - (time.monotonic() - remaining_run_seconds._start)
    try:
        end = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        return (end - datetime.now(timezone.utc)).total_seconds()
    except Exception:
        return None


def build_timeout_stub(domain_key: str, aliases: list[str]) -> dict:
    checked_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    canonical_domain = domain_key.lower().replace('www.', '')
    clean_website_url = f'https://{canonical_domain}/'
    cat, cat_conf = classify_company_category(canonical_domain, '', '', [])
    c_hint = detect_country_hint(canonical_domain, '', '', None, '')
    jur = derive_gdpr_jurisdiction(canonical_domain, None, c_hint, '')
    is_eu = jur in ('EU_EEA_GDPR', 'UK_GDPR', 'CH_FADP')
    verdict = 'Unverified (Run Timeout Reached — Retry Domain)'
    return {
        'input_domain': domain_key,
        'canonical_domain': canonical_domain,
        'aliases': '; '.join(aliases) if aliases else canonical_domain,
        'input_was_redirected': False,
        'redirect_chain': None,
        'website_url': clean_website_url,
        'final_redirect_url': clean_website_url,
        'status': 'run_timeout_unfinished',
        'cached_snapshot_source': 'none (run_timeout)',
        'cached_snapshot_age_days': None,
        'error_message': 'Actor run approached global timeout before domain finished; retry in smaller batch',
        'data_quality_score': 0,
        'sales_readiness_verdict': verdict,
        'sales_actionability_class': derive_sales_actionability_class(verdict, cat),
        'company_category': cat,
        'category_confidence': cat_conf,
        'marketplace_platform': canonical_domain in KNOWN_MARKETPLACE_DOMAINS,
        'marketplace_platform_pollution_detected': False,
        'icp_fit_tier': 'Unverified (Run Timeout Reached)',
        'technical_signal_strength': None,
        'tech_scan_completeness': 'partial_timeout',
        'tech_rescan_needed': True,
        'contact_quality_tier': 'Tier F (Run Timeout)',
        'contact_quality_tier_human': 'No Contact',
        'contact_enrichment_status': 'run_timeout_unfinished',
        'data_confidence_warning': 'Warning: Actor run approached time limit before this domain completed. Re-run with higher timeout.',
        'gdpr_eu_domain': is_eu,
        'gdpr_jurisdiction': jur,
        'legal_basis_for_processing': None,
        'data_subject_can_request_deletion': True,
        'data_retention_policy_days': 365,
        'personal_data_fields_in_record': 'none (run_timeout)',
        'compliance_note': build_compliance_note(canonical_domain, c_hint),
        'playwright_available': is_playwright_available(),
        'playwright_used': False,
        'playwright_status': 'aborted_by_run_timeout',
        'playwright_attempts_count': 0,
        'playwright_paths_attempted': None,
        'page_title': '[Run timeout reached before completion]',
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
        'phone_availability': 'not_checked_timeout',
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
        'sales_opportunity': 'Domain scan interrupted by global run timeout',
        'next_best_action': 'Re-run domain or use decision_maker_search_query on LinkedIn',
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
