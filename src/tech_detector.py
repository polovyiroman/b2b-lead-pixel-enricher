from collections import Counter
import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from .config import (
    AD_AND_ANALYTICS_SIGNATURES,
    CMS_HTML_ONLY_SIGNATURES,
    CONSENT_MODE_V2_GCD_REGEX,
    CONSENT_MODE_V2_GCS_REGEX,
    COOKIE_CONSENT_MARKERS,
    CSP_STRICT_SIGNATURES,
    EAA_ACCESSIBILITY_WIDGETS,
    ENTERPRISE_PIM_ERP_CMS_SIGNATURES,
    GA4_SCRIPT_SRC_REGEX,
    GA4_STRICT_10CHAR_REGEX,
    GA4_WIRE_REGEX,
    GOOGLE_ADS_REGEX,
    GTAG_CONFIG_GA4_REGEX,
    GTM_JSON_GA4_REGEX,
    LOGISTICS_AND_RETURNS_SIGNATURES,
    MAX_DISPLAY_GA4_IDS,
    SAFE_DEMO_SCHEDULER_PATTERNS,
    SGTM_CUSTOM_LOADER_REGEX,
    SGTM_FIRST_PARTY_COLLECT_REGEX,
    is_valid_gtm_id,
)

HTTP_HEADERS_COMMENT_RE = re.compile(r'<!--\s*http_headers_json:\s*(\{.*?\})\s*-->', re.DOTALL)
PW_NET_REQ_COMMENT_RE = re.compile(r'<!--\s*pw_net_req:\s*(https?://[^\s>]+)\s*-->', re.IGNORECASE)

SHOPIFY_SHOP_DOMAIN_RE = re.compile(
    r'(?:Shopify\.shop\s*=\s*["\']|["\']shop["\']\s*:\s*["\'])([a-z0-9-]+\.myshopify\.com)["\']',
    re.IGNORECASE,
)

HREFLANG_LINK_RE = re.compile(
    r'<link[^>]+rel=["\']alternate["\'][^>]+hreflang=["\']([a-zA-Z]{2}(?:-[a-zA-Z]{2})?)["\']|'
    r'<link[^>]+hreflang=["\']([a-zA-Z]{2}(?:-[a-zA-Z]{2})?)["\'][^>]+rel=["\']alternate["\']',
    re.IGNORECASE,
)

ATS_HTML_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ('Greenhouse', re.compile(r'boards(?:-api)?\.greenhouse\.io/(?:v1/boards/)?([a-z0-9_-]+)', re.I)),
    ('Lever', re.compile(r'jobs\.lever\.co/([a-z0-9_-]+)', re.I)),
    ('Workable', re.compile(r'apply\.workable\.com/(?:api/v3/accounts/)?([a-z0-9_-]+)', re.I)),
    ('SmartRecruiters', re.compile(r'jobs\.smartrecruiters\.com/([a-z0-9_-]+)', re.I)),
    ('Personio', re.compile(r'([a-z0-9-]+)\.jobs\.personio\.(?:de|com)', re.I)),
    ('Teamtailor', re.compile(r'([a-z0-9-]+)\.teamtailor\.com', re.I)),
    ('Ashby', re.compile(r'jobs\.ashbyhq\.com/([a-z0-9_-]+)', re.I)),
)

MARKETING_DATA_JOB_RE = re.compile(
    r'\b(?:marketing|growth|performance|ppc|seo|crm|retention|e-?commerce|ecommerce|'
    r'digital|analytics|analyst|data|cro|conversion|paid\s+social|paid\s+search|'
    r'brand|content|маркетинг|аналітик|трафік|конверс)\b',
    re.IGNORECASE,
)

AGENCY_CREDIT_RE = re.compile(
    r'(?:розробка\s+(?:та\s+підтримка\s+)?сайту|створення\s+сайту|дизайн\s+та\s+розробка|'
    r'seo[\s\-]просування|просування\s+сайту|created\s+by|developed\s+by|designed\s+by|'
    r'website\s+by|site\s+by|built\s+by|digital\s+partner|realisierung|webdesign\s+by|'
    r'conception\s+et\s+réalisation|realizacja)\s*[:\-–—]?\s*'
    r'(?:<a[^>]*>)?([A-ZА-ЯІЇЄҐ0-9][A-Za-zА-Яа-яІЇЄҐіїєґ0-9\s.&\-]{2,42})(?:</a>)?',
    re.IGNORECASE,
)

AGENCY_CREDIT_NOISE = {
    'shopify', 'wordpress', 'webflow', 'wix', 'tilda', 'squarespace', 'magento',
    'woocommerce', 'shopware', 'prestashop', 'opencart', 'bitrix', 'horoshop',
    'cloudflare', 'vercel', 'netlify', 'aws', 'google', 'all rights reserved',
    'всі права захищено', 'все права защищены', 'cookie', 'privacy', 'terms',
}

COOKIE_TECH_SIGNATURES: Dict[str, str] = {
    'fpid': 'Server-Side GTM (sGTM)',
    '_ga': 'Google Analytics (GA4)',
    '_gcl_au': 'Google Ads Conversion',
    '_fbp': 'Meta Pixel',
    '_fbc': 'Meta Pixel',
    '_ttp': 'TikTok Pixel',
    'li_fat_id': 'LinkedIn Insight Tag',
    '_pin_unauth': 'Pinterest Tag',
    '_clck': 'Microsoft Clarity',
    '_clsk': 'Microsoft Clarity',
    '_hjsessionuser': 'Hotjar',
    'hubspotutk': 'HubSpot',
    '__kla_id': 'Klaviyo',
}

RUNTIME_NET_SIGNATURES: Dict[str, tuple[str, ...]] = {
    'Google Tag Manager': ('googletagmanager.com/gtm.js', '/gtm.js?id=gtm-'),
    'Google Analytics (GA4)': ('google-analytics.com/g/collect', 'analytics.google.com/g/collect', 'googletagmanager.com/gtag/js?id=g-', '/g/collect?'),
    'Google Ads Conversion': ('googleadservices.com', 'doubleclick.net/pagead', 'googletagmanager.com/gtag/js?id=aw-'),
    'Meta Pixel': ('connect.facebook.net', 'facebook.com/tr'),
    'TikTok Pixel': ('analytics.tiktok.com',),
    'LinkedIn Insight Tag': ('snap.licdn.com', 'px.ads.linkedin.com'),
    'Pinterest Tag': ('s.pinimg.com/ct/', 'ct.pinterest.com'),
    'Microsoft Clarity': ('clarity.ms/tag/', 'clarity.ms/collect'),
    'Hotjar': ('static.hotjar.com', 'script.hotjar.com'),
    'HubSpot': ('js.hs-scripts.com', 'js.hs-analytics.net'),
    'Klaviyo': ('static.klaviyo.com', 'a.klaviyo.com'),
    'Shopify': ('cdn.shopify.com',),
}

PAYMENT_GATEWAY_NAMES: Set[str] = {
    'Stripe', 'Adyen', 'Klarna', 'Billie', 'Mondu', 'Hokodo', 'Two',
    'Mollie', 'Braintree', 'Checkout.com', 'PayPal', 'Apple Pay', 'Google Pay',
}

PAYMENT_HTML_SIGNATURES: Dict[str, tuple[str, ...]] = {
    'Stripe': ('js.stripe.com', 'checkout.stripe.com'),
    'Adyen': ('checkoutshopper-live.adyen.com', 'adyen.com/hpp'),
    'Klarna': ('x.klarnacdn.net', 'js.klarna.com', 'klarna-payments'),
    'Mollie': ('js.mollie.com', 'checkout.mollie.com'),
    'Braintree': ('js.braintreegateway.com', 'braintree-api.com'),
    'Checkout.com': ('cdn.checkout.com',),
    'PayPal': ('paypal.com/sdk/js', 'paypalobjects.com/api/checkout'),
}


def cap_ga4_ids_and_confidence(
    raw_ids_str: str | None,
    max_display: int = 5,
    base_confidence: str | None = None,
) -> tuple[str | None, int | None, str | None]:
    if not raw_ids_str:
        return None, None, base_confidence
    seen: list[str] = []
    for item in str(raw_ids_str).split(';'):
        clean_id = item.strip().upper()
        if clean_id and clean_id not in seen:
            seen.append(clean_id)
    if not seen:
        return None, None, base_confidence
    total_count = len(seen)
    displayed = seen[:max(1, int(max_display))]
    conf = base_confidence or f'Verified ({total_count} GA4 property ID{"s" if total_count > 1 else ""})'
    return '; '.join(displayed), total_count, conf


def extract_embedded_headers_and_ssr_signals_v23_1(html: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        'csp_techs': {},
        'csp_gateways': set(),
        'cookie_techs': {},
        'has_enterprise_cdn': False,
        'ssr_cms': None,
    }
    if not html:
        return out

    m = HTTP_HEADERS_COMMENT_RE.search(html)
    if not m:
        return out

    try:
        hdrs = json.loads(m.group(1))
    except Exception:
        return out
    if not isinstance(hdrs, dict):
        return out

    csp_combined = ' '.join(
        str(hdrs.get(k) or '')
        for k in ('content-security-policy', 'content-security-policy-report-only')
    ).lower()

    if csp_combined:
        for domain_sig, tech_name in CSP_STRICT_SIGNATURES.items():
            if domain_sig in csp_combined:
                if tech_name in PAYMENT_GATEWAY_NAMES:
                    out['csp_gateways'].add(tech_name)
                else:
                    out['csp_techs'][tech_name] = f'CSP Header allowlist: {domain_sig}'

    cookie_names = [str(c).lower() for c in (hdrs.get('cookie_names') or [])]
    for c_name in cookie_names:
        if c_name in COOKIE_TECH_SIGNATURES:
            t_name = COOKIE_TECH_SIGNATURES[c_name]
            out['cookie_techs'][t_name] = f'HTTP Set-Cookie runtime cookie: {c_name}'
        elif c_name.startswith('_ga_'):
            out['cookie_techs']['Google Analytics (GA4)'] = f'HTTP Set-Cookie runtime cookie: {c_name}'

    if hdrs.get('x-shopid') or hdrs.get('x-shopify-stage'):
        out['ssr_cms'] = 'Shopify'
    elif hdrs.get('x-magento-tags'):
        out['ssr_cms'] = 'Magento'
    elif hdrs.get('sw-context-token'):
        out['ssr_cms'] = 'Shopware'

    if hdrs.get('x-akamai-transformed') or hdrs.get('cf-polished') or hdrs.get('cf-ew-via'):
        out['has_enterprise_cdn'] = True

    return out


def decode_apple_pay_merchant_association_safe(raw_text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {'has_apple_pay': False, 'psp_gateways': []}
    if not raw_text or len(raw_text) < 40:
        return out
    low = raw_text.lower()
    if '<html' in low[:400] or '<!doctype' in low[:400]:
        return out

    psp_markers = {
        'merchant.com.stripe': 'Stripe',
        'merchant.com.adyen': 'Adyen',
        'merchant.com.braintree': 'Braintree',
        'merchant.com.checkout': 'Checkout.com',
        'merchant.com.mollie': 'Mollie',
        'merchant.com.worldpay': 'Worldpay',
        'merchant.com.klarna': 'Klarna',
    }
    found_psps: list[str] = []
    for sig, psp_name in psp_markers.items():
        if sig in low:
            found_psps.append(psp_name)
    if found_psps:
        out['has_apple_pay'] = True
        out['psp_gateways'] = sorted(set(found_psps))
    return out


def extract_shopify_pim_and_logistics_signals(html: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        'myshopify_canonical_domain': None,
        'demo_scheduler_tool': None,
        'has_automated_returns_portal': False,
        'logistics_carriers': [],
        'accessibility_widget': None,
        'enterprise_pim_and_cms': [],
    }
    if not html:
        return out

    m_shop = SHOPIFY_SHOP_DOMAIN_RE.search(html)
    if m_shop:
        out['myshopify_canonical_domain'] = m_shop.group(1).lower()

    low = html.lower()
    for tool_name, patterns in SAFE_DEMO_SCHEDULER_PATTERNS.items():
        if any(p in low for p in patterns):
            out['demo_scheduler_tool'] = tool_name
            break

    carriers: Set[str] = set()
    for sig, (label, kind) in LOGISTICS_AND_RETURNS_SIGNATURES.items():
        if sig in low:
            if kind == 'returns_portal':
                out['has_automated_returns_portal'] = True
            else:
                carriers.add(label)
    out['logistics_carriers'] = sorted(carriers)

    for w_sig, w_name in EAA_ACCESSIBILITY_WIDGETS.items():
        if w_sig in low:
            out['accessibility_widget'] = w_name
            break

    pim_found: Set[str] = set()
    for tech_name, sigs in ENTERPRISE_PIM_ERP_CMS_SIGNATURES.items():
        if any(s in low for s in sigs):
            pim_found.add(tech_name)
    out['enterprise_pim_and_cms'] = sorted(pim_found)
    return out


def extract_account_scale_signals(
    html: str,
    ga4_ids_count: int | None = None,
    advertiser_sister_domains: list[str] | None = None,
) -> Dict[str, Any]:
    """
    v24.1 Account Scale Intelligence:
    Визначає географічний масштаб бізнесу (estimated_markets_count, detected_market_locales)
    на основі <link rel="alternate" hreflang="...">, мульти-властивостей GA4 та сестринських доменів.
    """
    locales: Set[str] = set()
    if html:
        for g1, g2 in HREFLANG_LINK_RE.findall(html[:120000]):
            loc = (g1 or g2 or '').strip()
            if loc and loc.lower() != 'x-default':
                locales.add(loc)

    country_codes: Set[str] = set()
    for loc in locales:
        parts = loc.split('-')
        code = parts[-1].upper() if len(parts) == 2 else parts[0].upper()
        if len(code) == 2:
            country_codes.add(code)

    ga4_cnt = int(ga4_ids_count or 0)
    sister_cnt = len(advertiser_sister_domains or [])
    ga4_market_est = max(1, ga4_cnt // 2) if ga4_cnt >= 4 else 1

    est_markets = max(1, len(country_codes), ga4_market_est, sister_cnt)
    return {
        'estimated_markets_count': est_markets,
        'detected_market_locales': sorted(locales)[:20],
    }


def detect_agency_credits_from_html_and_gtm(
    html: str,
    gtm_js: str = '',
    brand_root: str = '',
) -> Optional[str]:
    """
    v24.1.1 Competitive Agency Intelligence:
    Виявляє веб-студію, розробника або performance-агенцію у футері сайту чи GTM-контейнері.
    Використовує лише точні маркери агенцій (без загального підрядка 'dept', який збігається з department).
    """
    b_low = (brand_root or '').lower().strip()
    if html:
        tail = html[-35000:] if len(html) > 35000 else html
        for m in AGENCY_CREDIT_RE.finditer(tail):
            cand = ' '.join(m.group(1).split()).strip(' .,:;-–—|/\\"\'')
            cand_low = cand.lower()
            if len(cand) < 3 or len(cand) > 40:
                continue
            if any(noise in cand_low for noise in AGENCY_CREDIT_NOISE):
                continue
            if b_low and len(b_low) >= 3 and b_low in cand_low:
                continue
            if any(ch.isdigit() for ch in cand) and len(cand) < 5:
                continue
            return cand

    if gtm_js:
        gtm_low = gtm_js.lower()
        known_gtm_agencies = (
            ('netpeak', 'Netpeak Agency'),
            ('promodo', 'Promodo Agency'),
            ('inweb', 'Inweb Agency'),
            ('deptagency', 'DEPT Agency'),
            ('by dept', 'DEPT Agency'),
            ('powered by dept', 'DEPT Agency'),
            ('created by dept', 'DEPT Agency'),
            ('dept agency', 'DEPT Agency'),
            ('publicis', 'Publicis Media'),
            ('groupm', 'GroupM'),
            ('dentsu', 'Dentsu'),
            ('jellyfish', 'Jellyfish'),
        )
        for sig, label in known_gtm_agencies:
            if sig in gtm_low and (not b_low or sig != b_low):
                return label

    return None


def detect_ats_from_html_or_dns(html: str, dns_ats_provider: str | None = None) -> tuple[str | None, str | None]:
    """
    Повертає (ats_provider, company_slug) з DNS CNAME або посилань на кар'єрній сторінці.
    """
    if html:
        for provider, rx in ATS_HTML_PATTERNS:
            m = rx.search(html)
            if m:
                slug = m.group(1).strip().lower()
                if slug and slug not in ('embed', 'api', 'v1', 'v3', 'jobs', 'careers', 'www'):
                    return provider, slug
    if dns_ats_provider:
        return dns_ats_provider, None
    return None, None


def _extract_ga4_ids_from_text(text: str, is_gtm: bool = False) -> Set[str]:
    found: Set[str] = set()
    if not text:
        return found
    for rx in (GTAG_CONFIG_GA4_REGEX, GA4_SCRIPT_SRC_REGEX, GA4_WIRE_REGEX):
        for m in rx.findall(text):
            found.add(m.upper())
    if is_gtm:
        for m in GTM_JSON_GA4_REGEX.findall(text):
            found.add(m.upper())
    for m in GA4_STRICT_10CHAR_REGEX.findall(text):
        up = m.upper()
        if not up.startswith(('G-TEST', 'G-XXXX', 'G-0000')):
            found.add(up)
    return found


def detect_tech_with_evidence(
    html: str,
    gtm_js: str,
    gtm_ids: list[str],
    page_url: str,
    scan_completeness: str = 'full',
) -> dict:
    """
    v24.1.1 Enterprise MarTech & Account Intelligence:
    Розділяє джерела сигналів на 3 рівні підтвердження:
      - `runtime_verified` (мережевий запит Playwright `pw_net_req` або першосторонні кукі `FPID`/`_ga`/`_fbp`);
      - `configured_in_code` (HTML-код сторінки або внутрішній код розпакованого `gtm.js`);
      - `allowlisted_in_csp` (лише список дозволених доменів у заголовку `Content-Security-Policy`).
    """
    html_str = html or ''
    gtm_str = gtm_js or ''
    html_clean_body = PW_NET_REQ_COMMENT_RE.sub('', HTTP_HEADERS_COMMENT_RE.sub('', html_str))
    html_low = html_clean_body.lower()
    gtm_low = gtm_str.lower()

    evidence_map: Dict[str, Dict[str, str]] = {}
    tier_rank = {
        'allowlisted_in_csp': 1,
        'configured_in_code': 2,
        'runtime_verified': 3,
    }

    def _record_tech(tech_name: str, tier: str, source: str, evidence_detail: str) -> None:
        existing = evidence_map.get(tech_name)
        if not existing or tier_rank[tier] > tier_rank.get(existing.get('verification_tier', ''), 0):
            evidence_map[tech_name] = {
                'verification_tier': tier,
                'source': source,
                'evidence': evidence_detail[:220],
            }

    hdr_info = extract_embedded_headers_and_ssr_signals_v23_1(html_str)
    for tech_name, csp_ev in hdr_info['csp_techs'].items():
        _record_tech(tech_name, 'allowlisted_in_csp', 'http_headers_csp', csp_ev)
    for tech_name, ck_ev in hdr_info['cookie_techs'].items():
        _record_tech(tech_name, 'runtime_verified', 'runtime_cookie', ck_ev)

    net_urls = PW_NET_REQ_COMMENT_RE.findall(html_str)
    runtime_ga4_hit_counts: Counter = Counter()
    consent_mode_signals: Set[str] = set()
    sgtm_hosts: Set[str] = set()

    for n_url in net_urls:
        n_low = n_url.lower()
        for tech_name, markers in RUNTIME_NET_SIGNATURES.items():
            if any(mk in n_low for mk in markers):
                _record_tech(tech_name, 'runtime_verified', 'runtime_network', f'Playwright network hit: {n_url[:140]}')

        if '/g/collect' in n_low:
            try:
                qs = parse_qs(urlparse(n_url).query)
                for tid in qs.get('tid', []):
                    if tid.upper().startswith('G-'):
                        runtime_ga4_hit_counts[tid.upper()] += 1
            except Exception:
                pass
            m_sgtm = SGTM_FIRST_PARTY_COLLECT_REGEX.search(n_url)
            if m_sgtm:
                sgtm_hosts.add(m_sgtm.group(1).lower())
                _record_tech('Server-Side GTM (sGTM)', 'runtime_verified', 'runtime_network', f'1st-party sGTM collect endpoint: {m_sgtm.group(1)}')

        for gcs_m in CONSENT_MODE_V2_GCS_REGEX.findall(n_url):
            consent_mode_signals.add(f'gcs={gcs_m}')
        for gcd_m in CONSENT_MODE_V2_GCD_REGEX.findall(n_url):
            consent_mode_signals.add(f'gcd={gcd_m}')

    valid_gtms = sorted({g.upper() for g in (gtm_ids or []) if is_valid_gtm_id(g)})
    if valid_gtms:
        _record_tech('Google Tag Manager', 'configured_in_code', 'html', f'Container IDs: {", ".join(valid_gtms[:4])}')

    html_ga4_ids = _extract_ga4_ids_from_text(html_clean_body, is_gtm=False)
    gtm_ga4_ids = _extract_ga4_ids_from_text(gtm_str, is_gtm=True)
    net_ga4_ids = set(runtime_ga4_hit_counts.keys())

    if net_ga4_ids:
        _record_tech('Google Analytics (GA4)', 'runtime_verified', 'runtime_network', f'Active /g/collect hits for {", ".join(sorted(net_ga4_ids)[:3])}')
    elif html_ga4_ids or gtm_ga4_ids:
        src_lbl = 'gtm_container' if (gtm_ga4_ids and not html_ga4_ids) else 'html'
        all_sample = sorted(html_ga4_ids | gtm_ga4_ids)[:3]
        _record_tech('Google Analytics (GA4)', 'configured_in_code', src_lbl, f'Measurement IDs: {", ".join(all_sample)}')

    gads_html = set(GOOGLE_ADS_REGEX.findall(html_clean_body))
    gads_gtm = set(GOOGLE_ADS_REGEX.findall(gtm_str))
    if gads_html or gads_gtm:
        aw_sample = sorted(gads_html | gads_gtm)[:3]
        _record_tech(
            'Google Ads Conversion',
            'configured_in_code',
            'gtm_container' if (gads_gtm and not gads_html) else 'html',
            f'Conversion IDs: {", ".join(aw_sample)}',
        )

    for m_loader in SGTM_CUSTOM_LOADER_REGEX.findall(html_clean_body):
        _record_tech('Server-Side GTM (sGTM)', 'configured_in_code', 'html', f'Custom sGTM loader: {m_loader[:100]}')
    for m_coll in SGTM_FIRST_PARTY_COLLECT_REGEX.findall(html_clean_body + '\n' + gtm_str):
        sgtm_hosts.add(m_coll.lower())
        _record_tech('Server-Side GTM (sGTM)', 'configured_in_code', 'html', f'First-party sGTM endpoint: {m_coll}')

    for gcs_m in CONSENT_MODE_V2_GCS_REGEX.findall(html_clean_body + '\n' + gtm_str):
        consent_mode_signals.add(f'gcs={gcs_m}')
    for gcd_m in CONSENT_MODE_V2_GCD_REGEX.findall(html_clean_body + '\n' + gtm_str):
        consent_mode_signals.add(f'gcd={gcd_m}')

    for tech_name, sigs in AD_AND_ANALYTICS_SIGNATURES.items():
        matched_html = next((s for s in sigs if s in html_low), None)
        if matched_html:
            _record_tech(tech_name, 'configured_in_code', 'html', f'HTML signature: {matched_html}')
            continue
        if gtm_low:
            matched_gtm = next((s for s in sigs if s in gtm_low), None)
            if matched_gtm:
                _record_tech(tech_name, 'configured_in_code', 'gtm_container', f'GTM container signature: {matched_gtm}')

    detected_cms_list: list[str] = []
    if hdr_info.get('ssr_cms'):
        detected_cms_list.append(hdr_info['ssr_cms'])
        _record_tech(hdr_info['ssr_cms'], 'configured_in_code', 'http_headers_ssr', f'SSR header: {hdr_info["ssr_cms"]}')

    for cms_name, sigs in CMS_HTML_ONLY_SIGNATURES.items():
        matched_cms = next((s for s in sigs if s in html_low), None)
        if matched_cms:
            if cms_name not in detected_cms_list:
                detected_cms_list.append(cms_name)
            _record_tech(cms_name, 'configured_in_code', 'html', f'CMS signature: {matched_cms}')

    if 'Shopify' in detected_cms_list and 'WordPress' in detected_cms_list:
        detected_cms_list = [c for c in detected_cms_list if c != 'WordPress']
        evidence_map.pop('WordPress', None)
    if 'WooCommerce' in detected_cms_list and 'WordPress' not in detected_cms_list:
        detected_cms_list.append('WordPress')

    payment_gateways: Set[str] = set(hdr_info['csp_gateways'])
    for psp_name, sigs in PAYMENT_HTML_SIGNATURES.items():
        if any(s in html_low or s in gtm_low for s in sigs):
            payment_gateways.add(psp_name)

    has_cookie_banner = any(m in html_low for m in COOKIE_CONSENT_MARKERS)

    dup_ga4_ids = sorted(html_ga4_ids & gtm_ga4_ids)
    dup_runtime_confirmed = any(runtime_ga4_hit_counts.get(gid, 0) >= 2 for gid in dup_ga4_ids)
    if not dup_ga4_ids:
        runtime_multi = sorted(gid for gid, cnt in runtime_ga4_hit_counts.items() if cnt >= 2)
        if runtime_multi:
            dup_ga4_ids = runtime_multi
            dup_runtime_confirmed = True

    all_detected_techs = sorted(evidence_map.keys())
    effective_completeness = scan_completeness
    if all_detected_techs and all(
        info.get('verification_tier') == 'allowlisted_in_csp' for info in evidence_map.values()
    ):
        effective_completeness = 'partial_csp_headers'

    all_ga4_combined = sorted(html_ga4_ids | gtm_ga4_ids | net_ga4_ids)
    raw_ga4_joined = '; '.join(all_ga4_combined) if all_ga4_combined else None

    ga4_tier = (evidence_map.get('Google Analytics (GA4)') or {}).get('verification_tier')
    if ga4_tier == 'runtime_verified':
        base_ga4_conf = f'High (Runtime Verified — {len(all_ga4_combined)} GA4 ID{"s" if len(all_ga4_combined) != 1 else ""})'
    elif ga4_tier == 'configured_in_code':
        base_ga4_conf = f'Verified in Code ({len(all_ga4_combined)} GA4 ID{"s" if len(all_ga4_combined) != 1 else ""})'
    elif ga4_tier == 'allowlisted_in_csp':
        base_ga4_conf = 'Low (CSP Header Allowlist Only — Tag Firing Unverified)'
    else:
        base_ga4_conf = None

    all_ga4_str, all_ga4_count, ga4_conf = cap_ga4_ids_and_confidence(
        raw_ga4_joined,
        max_display=MAX_DISPLAY_GA4_IDS,
        base_confidence=base_ga4_conf,
    )

    tech_verification_tiers = {
        t: info['verification_tier'] for t, info in evidence_map.items()
    }

    evidence_lines = [
        f"{t} [{info['verification_tier']}]: {info['evidence']}"
        for t, info in sorted(evidence_map.items())
    ]
    summary_parts = [
        f"{t} ({info['verification_tier']})"
        for t, info in sorted(evidence_map.items())[:8]
    ]

    return {
        'has_meta_pixel': 'Meta Pixel' in evidence_map,
        'has_tiktok_pixel': 'TikTok Pixel' in evidence_map,
        'has_google_ads': 'Google Ads Conversion' in evidence_map,
        'has_linkedin_pixel': 'LinkedIn Insight Tag' in evidence_map,
        'has_pinterest_tag': 'Pinterest Tag' in evidence_map,
        'has_hubspot': 'HubSpot' in evidence_map,
        'has_klaviyo': 'Klaviyo' in evidence_map,
        'has_ga4': 'Google Analytics (GA4)' in evidence_map,
        'has_gtm': 'Google Tag Manager' in evidence_map,
        'has_sgtm': 'Server-Side GTM (sGTM)' in evidence_map,
        'has_esp_retention': bool({'Klaviyo', 'HubSpot', 'Braze'} & set(evidence_map.keys())),
        'has_enterprise_cdn': bool(hdr_info.get('has_enterprise_cdn')),
        'gtm_ids': valid_gtms,
        'all_ga4_ids': all_ga4_str,
        'all_ga4_ids_count': all_ga4_count,
        'ga4_detection_confidence': ga4_conf,
        'duplicate_ga4_ids': dup_ga4_ids,
        'duplicate_ga4_runtime_confirmed': dup_runtime_confirmed,
        'has_cookie_banner': has_cookie_banner,
        'has_consent_mode_v2_signals': bool(consent_mode_signals),
        'consent_mode_v2_signals': sorted(consent_mode_signals),
        'detected_cms_list': detected_cms_list,
        'detected_cms': '; '.join(detected_cms_list) if detected_cms_list else None,
        'payment_gateways': sorted(payment_gateways),
        'detected_technologies_list': all_detected_techs,
        'tech_verification_tiers': tech_verification_tiers,
        'technology_evidence_summary': ', '.join(summary_parts) if summary_parts else 'No tracking technologies detected',
        'technology_evidence': ' | '.join(evidence_lines) if evidence_lines else 'No tracking signatures matched',
        'technology_evidence_json': json.dumps(evidence_map, ensure_ascii=False) if evidence_map else None,
        'tech_scan_completeness': effective_completeness,
    }


def detect_broken_attribution_red_flags(
    tech_info: dict,
    company_category: str = '',
    is_eu_gdpr: bool = False,
    pw_used: bool = False,
) -> list[str]:
    if company_category == 'Non-Profit / Education / Institution':
        return []

    red_flags: list[str] = []
    dup_ids = tech_info.get('duplicate_ga4_ids') or []
    dup_rt = bool(tech_info.get('duplicate_ga4_runtime_confirmed'))
    if dup_ids:
        status_lbl = 'duplicate_runtime_hits_confirmed' if dup_rt else 'duplicate_configuration_suspected'
        red_flags.append(
            f"Duplicate GA4 Tagging [{status_lbl}] ({dup_ids[0]} present in both HTML and GTM)"
        )

    scan_comp = str(tech_info.get('tech_scan_completeness') or 'full')
    tiers = tech_info.get('tech_verification_tiers') or {}
    gads_tier = tiers.get('Google Ads Conversion', '')

    if (
        is_eu_gdpr
        and tech_info.get('has_google_ads')
        and gads_tier != 'allowlisted_in_csp'
        and not tech_info.get('has_consent_mode_v2_signals')
        and scan_comp == 'full'
        and (pw_used or tech_info.get('has_cookie_banner'))
    ):
        red_flags.append(
            'EU Consent Mode v2 Gap (Google Ads active in EEA/UK without observable gcs/gcd consent signals)'
        )

    return red_flags


def build_summary_from_cached_record(rec: dict) -> str:
    tech_str = str(rec.get('detected_technologies') or '')
    techs = [x.strip() for x in tech_str.split(';') if x.strip()]
    if not techs:
        return 'No tracking technologies in cached snapshot'
    ga4_str = rec.get('all_ga4_ids')
    ga4_note = f' [GA4: {ga4_str}]' if ga4_str else ''
    return f"{', '.join(techs[:6])}{ga4_note} (Cached Snapshot)"


def build_evidence_json_from_cached_record(rec: dict, source_label: str = 'cache') -> str | None:
    tech_str = str(rec.get('detected_technologies') or '')
    techs = [x.strip() for x in tech_str.split(';') if x.strip()]
    if not techs:
        return None
    ev_map = {
        t: {
            'verification_tier': 'configured_in_code',
            'source': source_label,
            'evidence': f'Recovered from {source_label}',
        }
        for t in techs
    }
    return json.dumps(ev_map, ensure_ascii=False)


async def fetch_google_ads_transparency_intel_v23_1(
    http_client: Any,
    domain: str,
    etld_func: Callable[[str], tuple[str, str]],
    infra_denylist: tuple[str, ...] = (),
) -> Dict[str, Any]:
    """
    Виправлено (v24.1): При таймауті або HTTP-помилці RPC повертає `ads_active_last_30d: None`
    (а не хибне `False`), а при активній рекламі розпізнає конкретні формати оголошень.
    """
    out: Dict[str, Any] = {
        'ads_rpc_status': 'not_checked',
        'ads_active_last_30d': None,
        'active_ad_formats': [],
        'verified_advertiser_legal_name': None,
        'advertiser_sister_domains': [],
    }
    reg_dom, _ = etld_func(domain)
    target = reg_dom or domain.lower().strip()
    if not target:
        return out

    rpc_url = 'https://adstransparency.google.com/anji/_/rpc/SearchService/SearchSuggestions?authuser='
    payload = {'1': target, '2': 5, '3': 5}
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://adstransparency.google.com',
        'Referer': 'https://adstransparency.google.com/',
    }
    try:
        resp = await http_client.post(
            rpc_url,
            data={'f.req': json.dumps(payload)},
            headers=headers,
            timeout=2.4,
        )
        if resp.status_code == 200 and resp.text:
            body = resp.text.lstrip(")]}'\n ")
            data = json.loads(body)
            suggestions = data.get('1') or []
            if isinstance(suggestions, list) and suggestions:
                out['ads_rpc_status'] = 'verified_active_advertiser'
                out['ads_active_last_30d'] = True
                raw_low = body.lower()
                formats_found: list[str] = []
                if 'shopping' in raw_low or 'merchant' in raw_low:
                    formats_found.append('Shopping')
                if 'video' in raw_low or 'youtube' in raw_low:
                    formats_found.append('Video')
                if 'display' in raw_low or 'image' in raw_low:
                    formats_found.append('Display')
                if not formats_found or 'search' in raw_low or 'text' in raw_low:
                    formats_found.insert(0, 'Search')
                out['active_ad_formats'] = list(dict.fromkeys(formats_found))

                first_item = suggestions[0]
                if isinstance(first_item, dict):
                    adv_obj = first_item.get('1') or {}
                    if isinstance(adv_obj, dict):
                        legal_n = adv_obj.get('1')
                        if legal_n and isinstance(legal_n, str):
                            out['verified_advertiser_legal_name'] = legal_n.strip()
            else:
                out['ads_rpc_status'] = 'checked_no_active_ads'
                out['ads_active_last_30d'] = False
        else:
            out['ads_rpc_status'] = f'rpc_http_{resp.status_code}'
            out['ads_active_last_30d'] = None
    except Exception:
        out['ads_rpc_status'] = 'rpc_timeout_or_blocked'
        out['ads_active_last_30d'] = None
    return out


async def fetch_public_ats_hiring_intel(
    http_client: Any,
    ats_provider: str | None,
    brand_slug: str,
) -> Dict[str, Any]:
    """
    v24.1 Multi-Platform ATS Hiring Parser:
    Підтримує Greenhouse, Lever, Workable, SmartRecruiters та Personio.
    Якщо ATS не виявлено або не підтримується — повертає `open_positions_total: None` (не 0).
    """
    out: Dict[str, Any] = {
        'ats_provider': ats_provider,
        'open_positions_total': None,
        'hiring_departments': [],
        'hiring_marketing_or_data_roles': None,
    }
    if not brand_slug or not ats_provider:
        return out

    titles: List[str] = []
    depts: Set[str] = set()

    try:
        if ats_provider == 'Greenhouse':
            resp = await http_client.get(
                f'https://boards-api.greenhouse.io/v1/boards/{brand_slug}/jobs',
                timeout=2.2,
            )
            if resp.status_code == 200:
                jobs = resp.json().get('jobs') or []
                out['open_positions_total'] = len(jobs)
                for j in jobs[:80]:
                    if j.get('title'):
                        titles.append(str(j['title']))
                    for d in (j.get('departments') or []):
                        if isinstance(d, dict) and d.get('name'):
                            depts.add(str(d['name']).strip())

        elif ats_provider == 'Lever':
            resp = await http_client.get(
                f'https://api.lever.co/v0/postings/{brand_slug}?mode=json',
                timeout=2.2,
            )
            if resp.status_code == 200:
                jobs = resp.json() if isinstance(resp.json(), list) else []
                out['open_positions_total'] = len(jobs)
                for j in jobs[:80]:
                    if j.get('text'):
                        titles.append(str(j['text']))
                    cats = j.get('categories') or {}
                    if isinstance(cats, dict) and cats.get('department'):
                        depts.add(str(cats['department']).strip())

        elif ats_provider == 'Workable':
            resp = await http_client.post(
                f'https://apply.workable.com/api/v3/accounts/{brand_slug}/jobs',
                json={'query': '', 'location': [], 'department': [], 'worktype': []},
                timeout=2.2,
            )
            if resp.status_code == 200:
                data = resp.json()
                jobs = data.get('results') or []
                out['open_positions_total'] = int(data.get('total') or len(jobs))
                for j in jobs[:80]:
                    if j.get('title'):
                        titles.append(str(j['title']))
                    if j.get('department'):
                        depts.add(str(j['department']).strip())

        elif ats_provider == 'SmartRecruiters':
            resp = await http_client.get(
                f'https://api.smartrecruiters.com/v1/companies/{brand_slug}/postings',
                timeout=2.2,
            )
            if resp.status_code == 200:
                data = resp.json()
                jobs = data.get('content') or []
                out['open_positions_total'] = int(data.get('totalFound') or len(jobs))
                for j in jobs[:80]:
                    if j.get('name'):
                        titles.append(str(j['name']))
                    dept_obj = j.get('department') or {}
                    if isinstance(dept_obj, dict) and dept_obj.get('label'):
                        depts.add(str(dept_obj['label']).strip())

        elif ats_provider == 'Personio':
            resp = await http_client.get(
                f'https://{brand_slug}.jobs.personio.de/xml',
                timeout=2.2,
            )
            if resp.status_code == 200 and '<position>' in resp.text:
                xml_txt = resp.text
                pos_titles = re.findall(r'<name>\s*<!\[CDATA\[(.*?)\]\]>\s*</name>|<name>(.*?)</name>', xml_txt)
                pos_depts = re.findall(r'<department>\s*<!\[CDATA\[(.*?)\]\]>\s*</department>|<department>(.*?)</department>', xml_txt)
                cleaned_t = [a or b for a, b in pos_titles if (a or b)]
                out['open_positions_total'] = len(cleaned_t)
                titles.extend(cleaned_t[:80])
                for a, b in pos_depts:
                    val = (a or b).strip()
                    if val:
                        depts.add(val)
    except Exception:
        pass

    if out['open_positions_total'] is not None:
        out['hiring_departments'] = sorted(depts)[:8]
        combined_text = ' '.join(titles + list(depts))
        out['hiring_marketing_or_data_roles'] = bool(MARKETING_DATA_JOB_RE.search(combined_text))

    return out
