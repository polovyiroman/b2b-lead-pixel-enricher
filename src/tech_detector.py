from collections import Counter
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
    clean_url_port,
)


def extract_verified_html_ga4_ids(html: str) -> list[str]:
    pos_map: dict[str, int] = {}
    for rx in (GTAG_CONFIG_GA4_REGEX, GA4_SCRIPT_SRC_REGEX, GA4_WIRE_REGEX):
        for m in rx.finditer(html):
            gid = m.group(1).upper()
            pos = m.start()
            if gid not in pos_map or pos < pos_map[gid]:
                pos_map[gid] = pos
    return sorted(pos_map.keys(), key=lambda g: pos_map[g])


def extract_gtm_ga4_ids(gtm_js: str) -> tuple[list[str], bool, str]:
    if not gtm_js:
        return [], False, 'None'

    tier_b1_set = set()
    for rx in (GTAG_CONFIG_GA4_REGEX, GA4_SCRIPT_SRC_REGEX, GA4_WIRE_REGEX):
        for m in rx.finditer(gtm_js):
            tier_b1_set.add(m.group(1).upper())
    if tier_b1_set:
        ordered_b1 = sorted(tier_b1_set)
        return ordered_b1[:5], len(ordered_b1) >= 2, 'High (GTM Active Config)'

    tier_b2_set = {m.group(1).upper() for m in GTM_JSON_GA4_REGEX.finditer(gtm_js)}
    if tier_b2_set:
        ordered_b2 = sorted(tier_b2_set)
        if len(ordered_b2) >= 2:
            return ordered_b2[:5], True, 'Medium-High (GTM Multi-Property JSON)'
        return ordered_b2[:1], False, 'Medium-High (GTM JSON Property)'

    strict_matches = [m.group(0).upper() for m in GA4_STRICT_10CHAR_REGEX.finditer(gtm_js)]
    counts = Counter(strict_matches)
    freq_candidates = sorted(gid for gid, c in counts.items() if c >= 2)
    if freq_candidates:
        return freq_candidates[:1], False, 'Medium (GTM Macro Heuristic)'

    if len(counts) == 1:
        return list(counts.keys()), False, 'Medium (GTM Single Macro)'

    return [], False, 'None'


def detect_tech_with_evidence(
    html: str,
    gtm_js: str,
    gtm_ids: list[str],
    page_url: str,
    scan_completeness: str = 'full'
) -> dict:
    clean_gtm = gtm_js.replace('\\/', '/')
    html_lower = html.lower().replace('\\/', '/')
    gtm_lower = clean_gtm.lower()
    clean_page_url = clean_url_port(page_url) or page_url
    is_partial = (scan_completeness != 'full')

    detected = []
    evidence_items = []
    summary_items = []

    has_cookie_banner = any(cm in html_lower or cm in gtm_lower for cm in COOKIE_CONSENT_MARKERS)

    has_gtm = bool(gtm_ids) or 'googletagmanager.com/gtm.js' in html_lower
    if has_gtm:
        detected.append('Google Tag Manager')
        ev_str = f"GTM ({', '.join(gtm_ids)})" if gtm_ids else 'GTM (gtm.js)'
        evidence_items.append(f'{ev_str} [Direct HTML] on {clean_page_url}')
        summary_items.append(ev_str)

    ga4_in_html = extract_verified_html_ga4_ids(html)
    ga4_in_gtm, is_multi_ga4, gtm_ga4_conf = extract_gtm_ga4_ids(clean_gtm)

    has_ga4 = (
        bool(ga4_in_html or ga4_in_gtm)
        or 'google-analytics.com/g/collect' in html_lower
        or 'google-analytics.com/g/collect' in gtm_lower
        or 'googletagmanager.com/gtag/js' in html_lower
        or 'googletagmanager.com/gtag/js' in gtm_lower
    )
    ga4_confidence = None
    if has_ga4:
        detected.append('Google Analytics (GA4)')
        if ga4_in_html:
            ga4_confidence = 'High (Direct HTML Config)'
            evidence_items.append(f'GA4 ({ga4_in_html[0]} in Direct HTML)')
            summary_items.append(f'GA4 ({ga4_in_html[0]})')
        elif ga4_in_gtm:
            ga4_confidence = gtm_ga4_conf
            if is_multi_ga4 and len(ga4_in_gtm) >= 2:
                preview_ids = ', '.join(ga4_in_gtm[:3])
                if len(ga4_in_gtm) > 3:
                    preview_ids += f', ... (+{len(ga4_in_gtm) - 3} more)'
                evidence_items.append(
                    f'GA4 (multi-property GTM container: {len(ga4_in_gtm)} measurement IDs — {preview_ids})'
                )
                summary_items.append(
                    f'GA4 ({len(ga4_in_gtm)} IDs: {ga4_in_gtm[0]}, +{len(ga4_in_gtm) - 1} more)'
                )
            else:
                evidence_items.append(f'GA4 ({ga4_in_gtm[0]} in GTM Container)')
                summary_items.append(f'GA4 ({ga4_in_gtm[0]})')
        else:
            ga4_confidence = 'Low (Script Endpoint Only — ID Dynamic)'
            evidence_items.append('GA4 (gtag.js endpoint detected; measurement_id not exposed in static HTML)')
            summary_items.append('GA4 (dynamic ID)')

    aw_in_html = sorted({m.upper() for m in GOOGLE_ADS_REGEX.findall(html)})
    aw_in_gtm = sorted({m.upper() for m in GOOGLE_ADS_REGEX.findall(clean_gtm)})
    has_google_ads = (
        bool(aw_in_html or aw_in_gtm)
        or 'googleadservices.com/pagead/conversion' in html_lower
        or 'googleadservices.com/pagead/conversion' in gtm_lower
    )
    if has_google_ads:
        detected.append('Google Ads Conversion')
        if aw_in_html:
            evidence_items.append(f'Google Ads ({aw_in_html[0]} in Direct HTML)')
            summary_items.append(f'Google Ads ({aw_in_html[0]})')
        elif aw_in_gtm:
            evidence_items.append(f'Google Ads ({aw_in_gtm[0]} in GTM Container)')
            summary_items.append(f'Google Ads ({aw_in_gtm[0]})')
        else:
            evidence_items.append('Google Ads (pagead/conversion script)')
            summary_items.append('Google Ads')

    for name, markers in AD_AND_ANALYTICS_SIGNATURES.items():
        matched_in_html = next((m for m in markers if m in html_lower), None)
        matched_in_gtm = next((m for m in markers if m in gtm_lower), None)
        if matched_in_html or matched_in_gtm:
            detected.append(name)
            summary_items.append(name)
            if matched_in_html:
                evidence_items.append(f"{name} ('{matched_in_html}' in Direct HTML)")
            else:
                evidence_items.append(f"{name} ('{matched_in_gtm}' in GTM Container)")

    detected_cms = []
    for cms_name, cms_markers in CMS_HTML_ONLY_SIGNATURES.items():
        matched_cms = next((m for m in cms_markers if m in html_lower), None)
        if matched_cms:
            detected.append(cms_name)
            detected_cms.append(cms_name)
            summary_items.append(cms_name)
            evidence_items.append(f"{cms_name} ('{matched_cms}' in Direct HTML)")

    has_any_tracking = has_gtm or has_ga4 or has_google_ads or any(
        t in detected for t in AD_AND_ANALYTICS_SIGNATURES
    )

    if not evidence_items:
        if has_cookie_banner:
            ev_summary = 'No static tags visible (Consent Mode / Cookie banner detected; tags likely fire post-consent)'
            short_summary = 'Consent-Gated (No static tags)'
        else:
            ev_summary = 'No tracking markers detected in static HTML'
            short_summary = 'None'
    else:
        if not has_any_tracking and has_cookie_banner:
            evidence_items.append(
                'Consent-gated tracking likely (Cookie Consent / Privacy API detected; pixels fire post-consent)'
            )
            summary_items.append('Consent-Gated Banner')
        ev_summary = ' | '.join(evidence_items)
        short_summary = ', '.join(summary_items)

    all_ga4_list = ga4_in_html[:3] if ga4_in_html else ga4_in_gtm[:5]

    def flag_or_none(val: bool) -> bool | None:
        if val:
            return True
        return None if is_partial else False

    return {
        'has_meta_pixel': flag_or_none('Meta Pixel' in detected),
        'has_tiktok_pixel': flag_or_none('TikTok Pixel' in detected),
        'has_google_ads': flag_or_none(has_google_ads),
        'has_linkedin_pixel': flag_or_none('LinkedIn Insight Tag' in detected),
        'has_pinterest_tag': flag_or_none('Pinterest Tag' in detected),
        'has_hubspot': flag_or_none('HubSpot' in detected),
        'has_klaviyo': flag_or_none('Klaviyo' in detected),
        'has_ga4': flag_or_none(has_ga4),
        'has_gtm': flag_or_none(has_gtm),
        'all_ga4_ids': '; '.join(all_ga4_list) if all_ga4_list else None,
        'ga4_detection_confidence': ga4_confidence,
        'detected_cms_list': detected_cms,
        'detected_cms': '; '.join(detected_cms) if detected_cms else None,
        'has_cookie_banner': has_cookie_banner,
        'detected_technologies_list': detected,
        'technology_evidence': ev_summary,
        'technology_evidence_summary': short_summary,
        'tech_scan_completeness': scan_completeness
    }


def build_summary_from_cached_record(record: dict) -> str:
    existing = record.get('technology_evidence_summary')
    if existing and ';' not in existing:
        return existing
    raw_tech = record.get('detected_technologies') or ''
    if not raw_tech:
        return 'None'
    short_parts = []
    for item in [x.strip() for x in raw_tech.split(';') if x.strip()]:
        if item == 'Google Tag Manager':
            short_parts.append('GTM')
        elif item == 'Google Analytics (GA4)':
            ga4_raw = record.get('all_ga4_ids') or ''
            ga4_clean = [g.strip() for g in ga4_raw.split(';') if g.strip()]
            if len(ga4_clean) >= 2:
                short_parts.append(f'GA4 ({len(ga4_clean)} IDs: {ga4_clean[0]}, +{len(ga4_clean) - 1} more)')
            elif ga4_clean:
                short_parts.append(f'GA4 ({ga4_clean[0]})')
            else:
                short_parts.append('GA4')
        elif item == 'Google Ads Conversion':
            short_parts.append('Google Ads')
        else:
            short_parts.append(item)
    return ', '.join(short_parts) if short_parts else 'None'
