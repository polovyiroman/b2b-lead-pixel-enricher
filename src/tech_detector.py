import json
import re
from .config import (
    AD_AND_ANALYTICS_SIGNATURES,
    CMS_HTML_ONLY_SIGNATURES,
    CONSENT_MODE_V2_GCD_REGEX,
    CONSENT_MODE_V2_GCS_REGEX,
    COOKIE_CONSENT_MARKERS,
    GA4_SCRIPT_SRC_REGEX,
    GA4_STRICT_10CHAR_REGEX,
    GA4_WIRE_REGEX,
    GOOGLE_ADS_REGEX,
    GTAG_CONFIG_GA4_REGEX,
    GTM_JSON_GA4_REGEX,
    MAX_DISPLAY_GA4_IDS,
    SGTM_CUSTOM_LOADER_REGEX,
    SGTM_FIRST_PARTY_COLLECT_REGEX,
)

SHORT_SUMMARY_LABELS = {
    'Google Tag Manager': 'GTM',
    'Server-Side GTM (sGTM)': 'sGTM',
    'Google Analytics (GA4)': 'GA4',
    'Google Ads Conversion': 'Google Ads',
    'Meta Pixel': 'Meta Pixel',
    'TikTok Pixel': 'TikTok Pixel',
    'LinkedIn Insight Tag': 'LinkedIn Tag',
    'Pinterest Tag': 'Pinterest Tag',
    'Microsoft Clarity': 'Clarity',
    'Hotjar': 'Hotjar',
    'HubSpot': 'HubSpot',
    'Intercom': 'Intercom',
    'Klaviyo': 'Klaviyo',
}

_PW_NET_REQ_REGEX = re.compile(r'<!--\s*pw_net_req:\s*(.+?)\s*-->', re.I)

ESP_RETENTION_SIGNATURES = (
    'static.klaviyo.com',
    'klaviyo.push',
    'js.hs-scripts.com',
    'hs-analytics',
    'esputnik.com',
    'sendpulse.com',
    'webpushs.com',
    'omnisend.com',
    'omnisnippet',
    'customer.io',
    'braze.com',
    'appboy.min.js',
    'bloomreach',
    'exponea',
    'insider.js',
    'useinsider.com',
    'emarsys',
    'scarabresearch.com',
    'retailrocket',
    'mindbox',
)


def extract_code_snippet(source_text: str, match_str: str, max_len: int = 80) -> str:
    idx = source_text.lower().find(match_str.lower())
    if idx == -1:
        return match_str[:max_len]
    start = max(0, idx - 12)
    end = min(len(source_text), idx + len(match_str) + 32)
    raw = ' '.join(source_text[start:end].split())
    if len(raw) > max_len:
        return raw[:max_len - 1] + '…'
    return raw


def _is_valid_cached_sgtm(rec: dict) -> bool:
    ev_str = str(rec.get('technology_evidence') or '')
    return bool(
        SGTM_CUSTOM_LOADER_REGEX.search(ev_str)
        or SGTM_FIRST_PARTY_COLLECT_REGEX.search(ev_str)
    )


def cap_ga4_ids_and_confidence(
    raw_ga4_ids_str: str | None,
    raw_confidence: str | None = None
) -> tuple[str | None, int, str | None]:
    if not raw_ga4_ids_str:
        return None, 0, raw_confidence
    ids_list = [x.strip() for x in raw_ga4_ids_str.split(';') if x.strip()]
    total_count = len(ids_list)
    if total_count == 0:
        return None, 0, raw_confidence
    capped_str = '; '.join(ids_list[:MAX_DISPLAY_GA4_IDS])
    conf = raw_confidence
    if total_count > MAX_DISPLAY_GA4_IDS:
        conf = f'High (multiplexed {total_count}-property)'
    return capped_str, total_count, conf


def build_summary_from_cached_record(rec: dict) -> str | None:
    parts = []
    raw_tech = rec.get('detected_technologies') or ''
    tech_list = [x.strip() for x in raw_tech.split(';') if x.strip()]
    ga4_ids_str = rec.get('all_ga4_ids') or ''
    first_ga4 = ga4_ids_str.split(';')[0].strip() if ga4_ids_str else ''

    for t in tech_list:
        if t == 'Server-Side GTM (sGTM)' and not _is_valid_cached_sgtm(rec):
            continue
        short = SHORT_SUMMARY_LABELS.get(t, t)
        if t == 'Google Analytics (GA4)':
            if first_ga4:
                parts.append(f'GA4 ({first_ga4})')
            else:
                parts.append('GA4 (dynamic)')
        elif short not in parts:
            parts.append(short)
    return ', '.join(parts) if parts else None


def build_evidence_json_from_cached_record(rec: dict, source_label: str = 'cache') -> str | None:
    raw_tech = rec.get('detected_technologies') or ''
    tech_list = [x.strip() for x in raw_tech.split(';') if x.strip()]
    if not tech_list:
        return None
    ga4_ids = [x.strip() for x in (rec.get('all_ga4_ids') or '').split(';') if x.strip()]
    evidence_map: dict[str, dict] = {}
    for t in tech_list:
        if t == 'Server-Side GTM (sGTM)' and not _is_valid_cached_sgtm(rec):
            continue
        entry: dict = {'source': source_label}
        if t == 'Google Analytics (GA4)' and ga4_ids:
            entry['ids'] = ga4_ids[:MAX_DISPLAY_GA4_IDS]
            if len(ga4_ids) > MAX_DISPLAY_GA4_IDS:
                entry['total_ids_count'] = len(ga4_ids)
        evidence_map[t] = entry
    return json.dumps(evidence_map, ensure_ascii=False) if evidence_map else None


def detect_broken_attribution_red_flags(
    tech_info: dict,
    company_category: str = '',
    is_eu_gdpr: bool = False,
    pw_used: bool = False,
) -> list[str]:
    """
    Killer Feature #3: Детектор 4 технічних проблем втрати рекламного трафіку (Red Flags):
    1. AdBlocker Signal Loss: Активні платні пікселі (Meta / Google Ads / TikTok) без Server-Side GTM (sGTM).
    2. EU Consent Mode v2 Risk: Домен у ЄС з активним Google Ads та CMP-банером/Playwright, але без сигналів gcs/gcd.
    3. Duplicate GA4 Tagging: Один і той самий G-XXXX ID зашитий одночасно в HTML сторінки та всередині GTM-контейнера.
    4. Abandoned Cart Retention Leak: E-commerce з платним трафіком без жодної ESP/Retention-системи (Klaviyo/HubSpot/SendPulse/eSputnik).
    """
    if tech_info.get('tech_scan_completeness') not in ('full', 'partial_cached'):
        return []

    flags: list[str] = []
    has_meta = bool(tech_info.get('has_meta_pixel'))
    has_gads = bool(tech_info.get('has_google_ads'))
    has_tiktok = bool(tech_info.get('has_tiktok_pixel'))
    has_sgtm = bool(tech_info.get('has_sgtm'))
    has_cm_v2 = bool(tech_info.get('has_consent_mode_v2_signals'))
    has_consent_banner = bool(tech_info.get('has_cookie_banner'))
    dup_ga4_ids = tech_info.get('duplicate_ga4_ids') or []
    has_esp = bool(
        tech_info.get('has_klaviyo')
        or tech_info.get('has_hubspot')
        or tech_info.get('has_esp_retention')
    )

    paid_count = sum(1 for x in (has_meta, has_gads, has_tiktok) if x)

    # Red Flag 3: Duplicate GA4 Tagging (найбільш конкретний технічний баг — ставимо першим)
    if dup_ga4_ids:
        dup_str = ', '.join(dup_ga4_ids[:2])
        flags.append(
            f'Duplicate GA4 Tagging ({dup_str} hardcoded in HTML and duplicated inside GTM container — risks double pageview/event counting)'
        )

    # Red Flag 2: EU Consent Mode v2 Risk
    if (
        is_eu_gdpr
        and has_gads
        and not has_cm_v2
        and tech_info.get('tech_scan_completeness') == 'full'
        and (pw_used or has_consent_banner)
    ):
        flags.append(
            'EU Consent Mode v2 Gap (Google Ads active in EEA jurisdiction without gcs/gcd consent signals observed)'
        )

    # Red Flag 1: AdBlocker / ITP Signal Loss
    if paid_count >= 2 and not has_sgtm:
        flags.append(
            'Client-Side AdBlocker & ITP Loss (Multi-pixel paid traffic running without Server-Side GTM — estimated 20-30% attribution loss)'
        )

    # Red Flag 4: Abandoned Cart Retention Leak
    if company_category == 'E-commerce / Retail Brand' and paid_count >= 1 and not has_esp:
        flags.append(
            'E-commerce Retention Gap (Paid acquisition active without observable ESP/Klaviyo/CRM cart-recovery pixel)'
        )

    return flags


def detect_tech_with_evidence(
    html: str,
    gtm_js: str,
    gtm_ids: list[str],
    page_url: str,
    scan_completeness: str = 'full'
) -> dict:
    pw_net_urls = _PW_NET_REQ_REGEX.findall(html)
    pw_net_combined = '\n'.join(pw_net_urls)
    pw_net_lower = pw_net_combined.lower()

    html_without_pw_comments = _PW_NET_REQ_REGEX.sub('', html)
    html_lower = html_without_pw_comments.lower()
    gtm_lower = gtm_js.lower() if gtm_js else ''
    combined_source = f'{html}\n{gtm_js}' if gtm_js else html

    found_tech = []
    detected_cms_list = []
    evidence_items = []
    summary_items = []
    evidence_json_map: dict[str, dict] = {}

    if gtm_ids:
        found_tech.append('Google Tag Manager')
        evidence_items.append(
            f"Google Tag Manager: id={','.join(gtm_ids)} @ {page_url}"
        )
        summary_items.append(f'GTM ({gtm_ids[0]})')
        evidence_json_map['Google Tag Manager'] = {
            'source': 'live_html',
            'ids': gtm_ids,
        }
    elif 'googletagmanager.com/gtm.js' in pw_net_lower or '/gtm.js?id=gtm-' in pw_net_lower:
        found_tech.append('Google Tag Manager')
        evidence_items.append(f'Google Tag Manager: network request gtm.js @ {page_url}')
        summary_items.append('GTM (net)')
        evidence_json_map['Google Tag Manager'] = {
            'source': 'pw_network',
            'ids': [],
        }

    sgtm_loader_match = SGTM_CUSTOM_LOADER_REGEX.search(combined_source)
    sgtm_collect_match = SGTM_FIRST_PARTY_COLLECT_REGEX.search(combined_source)
    sgtm_match = sgtm_loader_match or sgtm_collect_match
    has_sgtm = bool(sgtm_match)
    if has_sgtm and sgtm_match:
        found_tech.append('Server-Side GTM (sGTM)')
        sgtm_snip = sgtm_match.group(0)[:85]
        sgtm_src = 'pw_network' if (sgtm_collect_match and sgtm_snip.lower() in pw_net_lower) else 'live_html'
        evidence_items.append(f'Server-Side GTM (sGTM): custom endpoint "{sgtm_snip}" @ {page_url}')
        summary_items.append('sGTM')
        evidence_json_map['Server-Side GTM (sGTM)'] = {
            'source': sgtm_src,
            'endpoint': sgtm_snip,
        }

    gcs_match = CONSENT_MODE_V2_GCS_REGEX.search(combined_source)
    gcd_match = CONSENT_MODE_V2_GCD_REGEX.search(combined_source)
    has_consent_mode_v2_signals = bool(
        gcs_match
        or gcd_match
        or "gtag('consent'" in html_lower
        or 'gtag("consent"' in html_lower
        or "gtag('consent'" in gtm_lower
        or 'gtag("consent"' in gtm_lower
    )
    if gcd_match or gcs_match:
        cm_parts = []
        if gcs_match:
            cm_parts.append(f'gcs={gcs_match.group(1)}')
        if gcd_match:
            cm_parts.append(f'gcd={gcd_match.group(1)[:16]}')
        evidence_items.append(f"Google Consent Mode v2 signals ({', '.join(cm_parts)}) @ {page_url}")

    # Для детекції Duplicate GA4 Tagging розділяємо ID, знайдені прямо в статичному HTML, та ID всередині GTM-контейнера
    html_direct_ga4 = {m.upper() for m in GTAG_CONFIG_GA4_REGEX.findall(html_without_pw_comments)}
    html_direct_ga4.update(m.upper() for m in GA4_SCRIPT_SRC_REGEX.findall(html_without_pw_comments))

    high_conf_ga4 = set(GA4_STRICT_10CHAR_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GTAG_CONFIG_GA4_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GA4_SCRIPT_SRC_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GA4_WIRE_REGEX.findall(combined_source))

    gtm_macro_ga4 = {m.upper() for m in GTM_JSON_GA4_REGEX.findall(gtm_js)} if gtm_js else set()
    duplicate_ga4_ids = sorted(html_direct_ga4 & gtm_macro_ga4)

    all_ga4_set = sorted(high_conf_ga4 | gtm_macro_ga4)
    total_ga4_count = len(all_ga4_set)
    capped_ga4_list = all_ga4_set[:MAX_DISPLAY_GA4_IDS]

    has_ga4_endpoint_only = (
        not all_ga4_set and (
            'googletagmanager.com/gtag/js' in html_lower
            or 'googletagmanager.com/gtag/js' in gtm_lower
            or 'google-analytics.com/g/collect' in html_lower
            or 'google-analytics.com/g/collect' in gtm_lower
            or 'analytics.google.com/g/collect' in html_lower
            or 'analytics.google.com/g/collect' in gtm_lower
            or 'google-analytics.com/g/collect' in pw_net_lower
            or 'analytics.google.com/g/collect' in pw_net_lower
        )
    )

    ga4_confidence = None
    if all_ga4_set:
        found_tech.append('Google Analytics (GA4)')
        if total_ga4_count > MAX_DISPLAY_GA4_IDS:
            ga4_confidence = f'High (multiplexed {total_ga4_count}-property)'
        elif high_conf_ga4 or total_ga4_count >= 2:
            ga4_confidence = 'High'
        else:
            ga4_confidence = 'Medium (GTM Single Macro)'
        ga4_src_label = 'live_html' if any(gid in html_without_pw_comments for gid in all_ga4_set) else (
            'pw_network' if any(gid.lower() in pw_net_lower for gid in all_ga4_set) else 'gtm_container'
        )
        src_note = 'page HTML' if ga4_src_label == 'live_html' else (
            'Playwright network' if ga4_src_label == 'pw_network' else 'GTM container'
        )
        snip = extract_code_snippet(combined_source, capped_ga4_list[0])
        count_suffix = f' (showing {MAX_DISPLAY_GA4_IDS} of {total_ga4_count})' if total_ga4_count > MAX_DISPLAY_GA4_IDS else ''
        evidence_items.append(
            f"Google Analytics (GA4) [{ga4_confidence}]: id={';'.join(capped_ga4_list)}{count_suffix} in {src_note} (\"{snip}\")"
        )
        summary_items.append(f'GA4 ({capped_ga4_list[0]})')
        ga4_ev_entry: dict = {
            'source': ga4_src_label,
            'confidence': ga4_confidence,
            'ids': capped_ga4_list,
        }
        if total_ga4_count > MAX_DISPLAY_GA4_IDS:
            ga4_ev_entry['total_ids_count'] = total_ga4_count
        if duplicate_ga4_ids:
            ga4_ev_entry['duplicate_html_and_gtm_ids'] = duplicate_ga4_ids[:5]
        evidence_json_map['Google Analytics (GA4)'] = ga4_ev_entry
    elif has_ga4_endpoint_only:
        found_tech.append('Google Analytics (GA4)')
        ga4_confidence = 'Low (Script Endpoint Only — ID Dynamic)'
        ga4_src_label = 'pw_network' if ('g/collect' in pw_net_lower) else ('live_html' if 'gtag/js' in html_lower else 'gtm_container')
        evidence_items.append(
            f'Google Analytics (GA4) [{ga4_confidence}]: gtag/js or g/collect endpoint detected without static G-XXXXXXXXXX ID @ {page_url}'
        )
        summary_items.append('GA4 (dynamic)')
        evidence_json_map['Google Analytics (GA4)'] = {
            'source': ga4_src_label,
            'confidence': ga4_confidence,
            'ids': [],
        }

    aw_ids = sorted(set(GOOGLE_ADS_REGEX.findall(combined_source)))
    has_aw_sig = (
        bool(aw_ids)
        or 'googleadservices.com/pagead/conversion' in html_lower
        or 'googleadservices.com/pagead/conversion' in gtm_lower
        or 'googlesyndication.com' in html_lower
        or 'googleads.g.doubleclick.net' in html_lower
        or 'googleads.g.doubleclick.net' in gtm_lower
        or 'googleadservices.com' in pw_net_lower
        or 'googleads.g.doubleclick.net' in pw_net_lower
    )
    if has_aw_sig:
        found_tech.append('Google Ads Conversion')
        aw_src_label = 'live_html' if (
            any(a in html_without_pw_comments for a in aw_ids) or 'googleadservices.com' in html_lower
        ) else ('pw_network' if 'googlead' in pw_net_lower else 'gtm_container')
        if aw_ids:
            snip = extract_code_snippet(combined_source, aw_ids[0])
            evidence_items.append(
                f"Google Ads Conversion: id={','.join(aw_ids[:4])} (\"{snip}\")"
            )
            summary_items.append(f'Google Ads ({aw_ids[0]})')
        else:
            evidence_items.append(
                f'Google Ads Conversion: conversion_async.js / doubleclick endpoint @ {page_url}'
            )
            summary_items.append('Google Ads')
        evidence_json_map['Google Ads Conversion'] = {
            'source': aw_src_label,
            'ids': aw_ids[:4],
        }

    for tech_name, signatures in AD_AND_ANALYTICS_SIGNATURES.items():
        for sig in signatures:
            in_html = sig in html_lower
            in_gtm = bool(gtm_lower and sig in gtm_lower)
            in_net = sig in pw_net_lower
            if in_html or in_gtm or in_net:
                found_tech.append(tech_name)
                where = 'page HTML' if in_html else ('Playwright network' if in_net else 'GTM container')
                src_code = 'live_html' if in_html else ('pw_network' if in_net else 'gtm_container')
                snip = extract_code_snippet(
                    html_without_pw_comments if in_html else (pw_net_combined if in_net else gtm_js),
                    sig
                )
                evidence_items.append(f'{tech_name}: "{sig}" in {where} ("{snip}")')
                summary_items.append(SHORT_SUMMARY_LABELS.get(tech_name, tech_name))
                evidence_json_map[tech_name] = {
                    'source': src_code,
                    'signature': sig,
                }
                break

    for cms_name, signatures in CMS_HTML_ONLY_SIGNATURES.items():
        for sig in signatures:
            if sig in html_lower:
                detected_cms_list.append(cms_name)
                found_tech.append(cms_name)
                snip = extract_code_snippet(html_without_pw_comments, sig)
                evidence_items.append(f'{cms_name} (CMS): "{sig}" in page HTML ("{snip}")')
                summary_items.append(cms_name)
                evidence_json_map[cms_name] = {
                    'source': 'live_html',
                    'signature': sig,
                }
                break

    if 'WooCommerce' in detected_cms_list and 'WordPress' not in detected_cms_list:
        detected_cms_list.append('WordPress')
        if 'WordPress' not in found_tech:
            found_tech.append('WordPress')

    has_esp_retention = any(
        esp_sig in html_lower or esp_sig in gtm_lower or esp_sig in pw_net_lower
        for esp_sig in ESP_RETENTION_SIGNATURES
    )

    has_cookie_banner = (
        has_consent_mode_v2_signals
        or any(marker in html_lower or marker in gtm_lower for marker in COOKIE_CONSENT_MARKERS)
    )
    if has_cookie_banner and not (gcd_match or gcs_match):
        evidence_items.append(f'Cookie Consent / CMP Banner detected @ {page_url}')

    return {
        'has_meta_pixel': 'Meta Pixel' in found_tech,
        'has_tiktok_pixel': 'TikTok Pixel' in found_tech,
        'has_google_ads': 'Google Ads Conversion' in found_tech,
        'has_linkedin_pixel': 'LinkedIn Insight Tag' in found_tech,
        'has_pinterest_tag': 'Pinterest Tag' in found_tech,
        'has_hubspot': 'HubSpot' in found_tech,
        'has_klaviyo': 'Klaviyo' in found_tech,
        'has_esp_retention': has_esp_retention,
        'has_ga4': 'Google Analytics (GA4)' in found_tech,
        'has_gtm': 'Google Tag Manager' in found_tech,
        'has_sgtm': has_sgtm,
        'has_consent_mode_v2_signals': has_consent_mode_v2_signals,
        'duplicate_ga4_ids': duplicate_ga4_ids,
        'all_ga4_ids': '; '.join(capped_ga4_list) if capped_ga4_list else None,
        'all_ga4_ids_count': total_ga4_count if total_ga4_count > 0 else None,
        'ga4_detection_confidence': ga4_confidence,
        'detected_cms_list': detected_cms_list,
        'detected_cms': '; '.join(detected_cms_list) if detected_cms_list else None,
        'has_cookie_banner': has_cookie_banner,
        'detected_technologies_list': found_tech,
        'technology_evidence': ' | '.join(evidence_items) if evidence_items else None,
        'technology_evidence_summary': ', '.join(summary_items) if summary_items else None,
        'technology_evidence_json': json.dumps(evidence_json_map, ensure_ascii=False) if evidence_json_map else None,
        'tech_scan_completeness': scan_completeness
    }
