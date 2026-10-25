import json
import re
from .config import (
    AD_AND_ANALYTICS_SIGNATURES,
    CMS_HTML_ONLY_SIGNATURES,
    COOKIE_CONSENT_MARKERS,
    GA4_SCRIPT_SRC_REGEX,
    GA4_STRICT_10CHAR_REGEX,
    GA4_WIRE_REGEX,
    GOOGLE_ADS_REGEX,
    GTAG_CONFIG_GA4_REGEX,
    GTM_JSON_GA4_REGEX,
    SGTM_CUSTOM_LOADER_REGEX,
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


def build_summary_from_cached_record(rec: dict) -> str | None:
    parts = []
    raw_tech = rec.get('detected_technologies') or ''
    tech_list = [x.strip() for x in raw_tech.split(';') if x.strip()]
    ga4_ids_str = rec.get('all_ga4_ids') or ''
    first_ga4 = ga4_ids_str.split(';')[0].strip() if ga4_ids_str else ''

    for t in tech_list:
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
        entry: dict = {'source': source_label}
        if t == 'Google Analytics (GA4)' and ga4_ids:
            entry['ids'] = ga4_ids
        evidence_map[t] = entry
    return json.dumps(evidence_map, ensure_ascii=False)


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
    elif 'googletagmanager.com/gtm.js' in pw_net_lower:
        found_tech.append('Google Tag Manager')
        evidence_items.append(f'Google Tag Manager: network request gtm.js @ {page_url}')
        summary_items.append('GTM (net)')
        evidence_json_map['Google Tag Manager'] = {
            'source': 'pw_network',
            'ids': [],
        }

    # P3 #19: Server-Side GTM (sGTM) detection
    sgtm_match = SGTM_CUSTOM_LOADER_REGEX.search(combined_source)
    has_sgtm = bool(sgtm_match)
    if has_sgtm and sgtm_match:
        found_tech.append('Server-Side GTM (sGTM)')
        sgtm_snip = sgtm_match.group(0)[:70]
        evidence_items.append(f'Server-Side GTM (sGTM): custom endpoint "{sgtm_snip}" @ {page_url}')
        summary_items.append('sGTM')
        evidence_json_map['Server-Side GTM (sGTM)'] = {
            'source': 'live_html',
            'endpoint': sgtm_snip,
        }

    high_conf_ga4 = set(GA4_STRICT_10CHAR_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GTAG_CONFIG_GA4_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GA4_SCRIPT_SRC_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GA4_WIRE_REGEX.findall(combined_source))

    gtm_macro_ga4 = {m.upper() for m in GTM_JSON_GA4_REGEX.findall(gtm_js)} if gtm_js else set()
    all_ga4_set = sorted(high_conf_ga4 | gtm_macro_ga4)

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
        if high_conf_ga4 or len(all_ga4_set) >= 2:
            ga4_confidence = 'High'
        else:
            ga4_confidence = 'Medium (GTM Single Macro)'
        ga4_src_label = 'live_html' if any(gid in html for gid in all_ga4_set) else (
            'pw_network' if any(gid.lower() in pw_net_lower for gid in all_ga4_set) else 'gtm_container'
        )
        src_note = 'page HTML' if ga4_src_label == 'live_html' else (
            'Playwright network' if ga4_src_label == 'pw_network' else 'GTM container'
        )
        snip = extract_code_snippet(combined_source, all_ga4_set[0])
        evidence_items.append(
            f"Google Analytics (GA4) [{ga4_confidence}]: id={';'.join(all_ga4_set)} in {src_note} (\"{snip}\")"
        )
        summary_items.append(f'GA4 ({all_ga4_set[0]})')
        evidence_json_map['Google Analytics (GA4)'] = {
            'source': ga4_src_label,
            'confidence': ga4_confidence,
            'ids': all_ga4_set,
        }
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
            any(a in html for a in aw_ids) or 'googleadservices.com' in html_lower
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

    has_cookie_banner = any(
        marker in html_lower or marker in gtm_lower
        for marker in COOKIE_CONSENT_MARKERS
    )
    if has_cookie_banner:
        evidence_items.append(f'Cookie Consent / CMP Banner detected @ {page_url}')

    return {
        'has_meta_pixel': 'Meta Pixel' in found_tech,
        'has_tiktok_pixel': 'TikTok Pixel' in found_tech,
        'has_google_ads': 'Google Ads Conversion' in found_tech,
        'has_linkedin_pixel': 'LinkedIn Insight Tag' in found_tech,
        'has_pinterest_tag': 'Pinterest Tag' in found_tech,
        'has_hubspot': 'HubSpot' in found_tech,
        'has_klaviyo': 'Klaviyo' in found_tech,
        'has_ga4': 'Google Analytics (GA4)' in found_tech,
        'has_gtm': 'Google Tag Manager' in found_tech,
        'has_sgtm': has_sgtm,
        'all_ga4_ids': '; '.join(all_ga4_set) if all_ga4_set else None,
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
