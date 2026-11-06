from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any, Callable, Dict, List, Set

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
_NET_COLLECT_TID_REGEX = re.compile(r'/g/collect\?[^"\'\s<>]*?(?:^|[?&])tid=(G-[A-Z0-9]{6,12})\b', re.I)

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

HTTP_HEADERS_COMMENT_RE = re.compile(r"<!--\s*http_headers_json:\s*(\{.*?\})\s*-->", re.DOTALL)
NEXT_DATA_SCRIPT_RE = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL
)
SHOPIFY_SHOP_HANDLE_RE = re.compile(r'Shopify\.shop\s*=\s*["\']([a-zA-Z0-9_-]+\.myshopify\.com)["\']')
SHOPIFY_COUNTRY_RE = re.compile(r'Shopify\.country\s*=\s*["\']([A-Z]{2})["\']')
SHOPIFY_CURRENCY_RE = re.compile(r'Shopify\.currency\s*=\s*\{\s*["\']active["\']\s*:\s*["\']([A-Z]{3})["\']')

SALES_LED_CTA_RE = re.compile(
    r"\b(book\s+a\s+demo|request\s+a\s+demo|schedule\s+a\s+demo|talk\s+to\s+sales|"
    r"request\s+a\s+quote|contact\s+sales|demo\s+buchen|termin\s+vereinbaren)\b",
    re.IGNORECASE
)
PLG_TRIAL_CTA_RE = re.compile(
    r"\b(start\s+free\s+trial|try\s+for\s+free|get\s+started\s+free|sign\s+up\s+free|kostenlos\s+testen)\b",
    re.IGNORECASE
)

STRICT_URL_HOST_RE = re.compile(r"https?://(?:www\.)?([a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})+)", re.IGNORECASE)
SOCIAL_AND_PLATFORM_DENYLIST = {
    "facebook.com", "instagram.com", "tiktok.com", "linkedin.com", "youtube.com",
    "youtu.be", "twitter.com", "x.com", "pinterest.com", "shopify.com", "apple.com",
    "play.google.com", "apps.apple.com", "trustpilot.com", "wikipedia.org",
    "google.com", "googlesyndication.com", "doubleclick.net", "gstatic.com"
}

CANONICAL_INTERNAL_TOOLS_MAP: Dict[str, str] = {
    "sap": "SAP", "salesforce": "Salesforce", "hubspot": "HubSpot",
    "klaviyo": "Klaviyo", "snowflake": "Snowflake", "bigquery": "BigQuery",
    "databricks": "Databricks", "looker": "Looker", "tableau": "Tableau",
    "powerbi": "Power BI", "power bi": "Power BI", "netsuite": "Oracle NetSuite",
    "workday": "Workday", "jira": "Jira", "confluence": "Confluence",
    "kubernetes": "Kubernetes", "terraform": "Terraform", "aws": "AWS",
    "azure": "Azure", "gcp": "GCP", "shopify plus": "Shopify Plus",
    "shopware": "Shopware", "magento": "Magento", "braze": "Braze",
    "segment": "Segment", "amplitude": "Amplitude", "mixpanel": "Mixpanel", "okta": "Okta",
}
INTERNAL_TECH_PATTERNS = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in CANONICAL_INTERNAL_TOOLS_MAP.keys()) + r")\b",
    re.IGNORECASE
)


# ==============================================================================
# v23.1 Complete: 5 функцій розширеної детекції технологій (Фаза 3)
# ==============================================================================

def extract_embedded_headers_and_ssr_signals_v23_1(html_text: str) -> Dict[str, Any]:
    detected_tech: Set[str] = set()
    payment_gateways: Set[str] = set()
    has_sgtm_cookie = False
    has_enterprise_cdn = False

    if not html_text:
        return {
            "detected_tech": [],
            "payment_gateways": [],
            "has_sgtm_fpid_cookie": False,
            "has_enterprise_cdn": False,
        }

    hdr_match = HTTP_HEADERS_COMMENT_RE.search(html_text)
    if hdr_match:
        try:
            hdrs = json.loads(hdr_match.group(1))
        except Exception:
            hdrs = {}

        csp_and_rep = " ".join(
            str(hdrs.get(k, "")) for k in (
                "content-security-policy", "content-security-policy-report-only",
                "reporting-endpoints", "report-to", "nel"
            )
        ).lower()

        for sig, name in CSP_STRICT_SIGNATURES.items():
            if sig in csp_and_rep:
                detected_tech.add(name)
                if name in ("Stripe", "Adyen", "Klarna", "Billie", "Mondu", "Hokodo", "Two", "Mollie", "Braintree", "Checkout.com"):
                    payment_gateways.add(name)

        cookie_names_low = {str(c).lower() for c in (hdrs.get("cookie_names") or [])}
        if cookie_names_low & {"fpid", "fplc", "fpau"}:
            detected_tech.add("Server-Side GTM (sGTM)")
            has_sgtm_cookie = True
        if cookie_names_low & {"_fbp", "_fbc"}:
            detected_tech.add("Meta Pixel")
        if "_ttp" in cookie_names_low:
            detected_tech.add("TikTok Pixel")
        if "hubspotutk" in cookie_names_low:
            detected_tech.add("HubSpot")
        if "_kla_id" in cookie_names_low:
            detected_tech.add("Klaviyo")

        if any(k in hdrs for k in ("cf-polished", "cf-ew-via", "x-akamai-transformed")):
            has_enterprise_cdn = True
        if hdrs.get("x-shopid") or "shopify" in str(hdrs.get("server-timing", "")).lower():
            detected_tech.add("Shopify")
        if "x-magento-tags" in hdrs:
            detected_tech.add("Magento")
        if "sw-context-token" in hdrs:
            detected_tech.add("Shopware")

    if "__NEXT_DATA__" in html_text:
        detected_tech.add("Next.js")
        nd_match = NEXT_DATA_SCRIPT_RE.search(html_text)
        if nd_match:
            nd_low = nd_match.group(1).lower()
            if '"algoliaappid"' in nd_low or "algolianet.com" in nd_low:
                detected_tech.add("Algolia")
            if "pk_live_" in nd_low or '"stripepublishablekey"' in nd_low:
                detected_tech.add("Stripe")
                payment_gateways.add("Stripe")
            if '"adyenclientkey"' in nd_low or "adyen.com" in nd_low or "checkoutshopper-" in nd_low:
                detected_tech.add("Adyen")
                payment_gateways.add("Adyen")
            if "sentry.io" in nd_low or '"sentrydsn"' in nd_low:
                detected_tech.add("Sentry")

    return {
        "detected_tech": sorted(detected_tech),
        "payment_gateways": sorted(payment_gateways),
        "has_sgtm_fpid_cookie": has_sgtm_cookie,
        "has_enterprise_cdn": has_enterprise_cdn,
    }


def decode_apple_pay_merchant_association_safe(raw_body: str) -> Dict[str, Any]:
    if not raw_body or len(raw_body) < 64:
        return {"has_apple_pay": False, "psp_gateways": []}
    head_low = raw_body[:500].lstrip().lower()
    if any(tag in head_low for tag in ("<!doctype", "<html", "<head", "<body", "<script")):
        return {"has_apple_pay": False, "psp_gateways": []}

    clean = raw_body.strip()
    decoded_ascii = clean.lower()
    if all(c in "0123456789abcdefABCDEF\n\r\t " for c in clean[:128]):
        try:
            decoded_ascii = bytes.fromhex("".join(clean.split())).decode("latin1", errors="ignore").lower()
        except Exception:
            pass

    if "merchant.com." not in decoded_ascii and '"pspid"' not in decoded_ascii:
        return {"has_apple_pay": False, "psp_gateways": []}

    strict_oid_markers = {
        "merchant.com.stripe": "Stripe",
        "merchant.com.adyen": "Adyen",
        "merchant.com.shopify": "Shopify Payments",
        "merchant.com.mollie": "Mollie",
        "merchant.com.braintree": "Braintree",
        "merchant.com.checkout": "Checkout.com",
        "merchant.com.worldpay": "Worldpay",
        "merchant.com.klarna": "Klarna",
    }
    found = sorted({name for marker, name in strict_oid_markers.items() if marker in decoded_ascii})
    return {"has_apple_pay": True, "psp_gateways": found}


def extract_shopify_pim_and_logistics_signals(html_text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "myshopify_canonical_domain": None,
        "shopify_inline_country": None,
        "shopify_inline_currency": None,
        "enterprise_pim_and_cms": [],
        "logistics_carriers": [],
        "returns_and_3pl_stack": [],
        "has_automated_returns_portal": False,
        "demo_scheduler_tool": None,
        "gtm_sales_motion": "CORPORATE_OR_SERVICE",
        "accessibility_widget": None,
    }
    if not html_text:
        return out
    low = html_text.lower()

    if "shopify." in low:
        m_shop = SHOPIFY_SHOP_HANDLE_RE.search(html_text)
        if m_shop:
            out["myshopify_canonical_domain"] = m_shop.group(1).lower()
        m_country = SHOPIFY_COUNTRY_RE.search(html_text)
        if m_country:
            out["shopify_inline_country"] = m_country.group(1).upper()
        m_curr = SHOPIFY_CURRENCY_RE.search(html_text)
        if m_curr:
            out["shopify_inline_currency"] = m_curr.group(1).upper()

    pim_set: Set[str] = set()
    for name, markers in ENTERPRISE_PIM_ERP_CMS_SIGNATURES.items():
        if any(m in low for m in markers):
            pim_set.add(name)
    out["enterprise_pim_and_cms"] = sorted(pim_set)

    carriers: Set[str] = set()
    orchestrators: Set[str] = set()
    for marker, (l_name, kind) in LOGISTICS_AND_RETURNS_SIGNATURES.items():
        if marker in low:
            if kind == "carrier":
                carriers.add(l_name)
            else:
                orchestrators.add(l_name)
                if kind == "returns_portal":
                    out["has_automated_returns_portal"] = True
    out["logistics_carriers"] = sorted(carriers)
    out["returns_and_3pl_stack"] = sorted(orchestrators)

    for tool_name, patterns in SAFE_DEMO_SCHEDULER_PATTERNS.items():
        if any(p in low for p in patterns):
            out["demo_scheduler_tool"] = tool_name
            break

    for marker, w_name in EAA_ACCESSIBILITY_WIDGETS.items():
        if marker in low:
            out["accessibility_widget"] = w_name
            break

    has_demo = bool(out["demo_scheduler_tool"] or SALES_LED_CTA_RE.search(html_text))
    has_trial = bool(PLG_TRIAL_CTA_RE.search(html_text))
    if has_demo and has_trial:
        out["gtm_sales_motion"] = "B2B_HYBRID_PLG_AND_SALES"
    elif has_demo:
        out["gtm_sales_motion"] = "B2B_ENTERPRISE_SALES_LED"
    elif has_trial:
        out["gtm_sales_motion"] = "B2B_PLG_SELF_SERVE"
    elif "/cart" in low or "add-to-cart" in low or out["myshopify_canonical_domain"]:
        out["gtm_sales_motion"] = "COMMERCE_TRANSACTIONAL"

    return out


async def fetch_google_ads_transparency_intel_v23_1(
    http_session: Any,
    domain: str,
    etld_func: Callable[[str], tuple[str, str]],
    infra_denylist: tuple[str, ...]
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ads_rpc_status": "not_checked",
        "has_verified_advertiser_profile": False,
        "ads_active_last_30d": None,
        "advertiser_id": None,
        "verified_advertiser_legal_name": None,
        "advertiser_country": None,
        "active_ad_formats": [],
        "last_ad_seen_date": None,
        "advertiser_sister_domains": [],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://adstransparency.google.com",
        "Referer": "https://adstransparency.google.com/",
    }
    sugg_url = "https://adstransparency.google.com/anji/_/rpc/SearchService/SearchSuggestions?authuser="
    try:
        resp1 = await http_session.post(
            sugg_url,
            data={"f.req": json.dumps({"1": domain, "2": 5, "3": 5})},
            headers=headers,
            timeout=2.8
        )
        if resp1.status_code == 429:
            result["ads_rpc_status"] = "rate_limited"
            return result
        if resp1.status_code != 200:
            result["ads_rpc_status"] = f"http_{resp1.status_code}"
            return result
        data1 = json.loads(resp1.text.lstrip(")]}'\n "))
        result["ads_rpc_status"] = "ok"
    except Exception:
        result["ads_rpc_status"] = "network_error"
        return result

    for item in (data1.get("1") or []):
        adv_block = item.get("1") if isinstance(item, dict) else None
        if isinstance(adv_block, dict) and str(adv_block.get("2", "")).startswith("AR"):
            result["has_verified_advertiser_profile"] = True
            result["verified_advertiser_legal_name"] = adv_block.get("1")
            result["advertiser_id"] = adv_block.get("2")
            result["advertiser_country"] = adv_block.get("3")
            break

    if not result["advertiser_id"]:
        result["ads_active_last_30d"] = False
        return result

    now_utc = datetime.now(timezone.utc)
    start_int = int((now_utc - timedelta(days=30)).strftime("%Y%m%d"))
    end_int = int(now_utc.strftime("%Y%m%d"))
    creatives_url = "https://adstransparency.google.com/anji/_/rpc/SearchService/SearchCreatives?authuser="
    creatives_req = {
        "2": 10,
        "3": {"12": {"1": "", "2": True}, "13": {"1": [result["advertiser_id"]]}, "6": start_int, "7": end_int},
        "7": {"1": 1, "2": 0, "3": 2580}
    }
    try:
        resp2 = await http_session.post(
            creatives_url,
            data={"f.req": json.dumps(creatives_req)},
            headers=headers,
            timeout=2.8
        )
        if resp2.status_code == 200:
            raw_text2 = resp2.text.lstrip(")]}'\n ")
            data2 = json.loads(raw_text2)
            creatives_list = data2.get("1") or []
            result["ads_active_last_30d"] = bool(creatives_list)
            if creatives_list:
                format_map = {1: "TEXT", 2: "IMAGE", 3: "VIDEO"}
                formats_found = set()
                latest_ts = 0
                for cr in creatives_list:
                    if not isinstance(cr, dict):
                        continue
                    fmt_code = cr.get("4")
                    if fmt_code in format_map:
                        formats_found.add(format_map[fmt_code])
                    last_shown = cr.get("7") or cr.get("6")
                    if isinstance(last_shown, dict):
                        ts_sec = int(last_shown.get("1", 0))
                        if ts_sec > latest_ts:
                            latest_ts = ts_sec
                result["active_ad_formats"] = sorted(formats_found)
                if latest_ts > 0:
                    result["last_ad_seen_date"] = datetime.fromtimestamp(latest_ts, tz=timezone.utc).strftime("%Y-%m-%d")

                norm_text = raw_text2.replace("\\/", "/").replace("\\u002f", "/")
                curr_reg, _ = etld_func(domain)
                sisters: Set[str] = set()
                for host_m in STRICT_URL_HOST_RE.findall(norm_text):
                    reg_d, _ = etld_func(host_m.lower())
                    if not reg_d or reg_d == curr_reg or reg_d in SOCIAL_AND_PLATFORM_DENYLIST:
                        continue
                    if any(reg_d.endswith(inf) for inf in infra_denylist):
                        continue
                    if not reg_d.endswith((".js", ".css", ".png", ".jpg", ".svg", ".webp", ".json")):
                        sisters.add(reg_d)
                result["advertiser_sister_domains"] = sorted(sisters)[:10]
    except Exception:
        pass
    return result


async def fetch_public_ats_hiring_intel(
    http_session: Any,
    ats_provider: str,
    company_token: str
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "open_positions_total": 0,
        "hiring_departments": [],
        "detected_internal_tools_from_jobs": [],
        "is_expanding_rapidly": False,
    }
    if ats_provider == "Greenhouse":
        dept_url = f"https://boards-api.greenhouse.io/v1/boards/{company_token}/departments"
        try:
            resp = await http_session.get(dept_url, timeout=2.5)
            if resp.status_code != 200:
                return out
            departments_raw = resp.json().get("departments") or []
            active_depts: List[str] = []
            priority_ids: List[int] = []
            seen_ids = set()
            for dept in departments_raw:
                if not isinstance(dept, dict):
                    continue
                jobs = dept.get("jobs") or []
                if jobs:
                    d_name = (dept.get("name") or "").strip()
                    if d_name and d_name.lower() != "no department":
                        active_depts.append(d_name)
                    for j in jobs:
                        jid = j.get("id")
                        title = (j.get("title") or "").lower()
                        if jid and jid not in seen_ids:
                            seen_ids.add(jid)
                            if len(priority_ids) < 3 and any(
                                k in title for k in ("engineer", "developer", "data", "marketing", "crm", "growth", "revops")
                            ):
                                priority_ids.append(jid)
            out["open_positions_total"] = len(seen_ids)
            out["hiring_departments"] = sorted(dict.fromkeys(active_depts))[:10]
            out["is_expanding_rapidly"] = len(seen_ids) >= 10

            tools_found: Set[str] = set()
            for jid in priority_ids:
                try:
                    j_resp = await http_session.get(
                        f"https://boards-api.greenhouse.io/v1/boards/{company_token}/jobs/{jid}",
                        timeout=2.0
                    )
                    if j_resp.status_code == 200:
                        content = j_resp.json().get("content") or ""
                        for m in INTERNAL_TECH_PATTERNS.findall(content):
                            canon = CANONICAL_INTERNAL_TOOLS_MAP.get(m.lower())
                            if canon:
                                tools_found.add(canon)
                except Exception:
                    continue
            out["detected_internal_tools_from_jobs"] = sorted(tools_found)
        except Exception:
            pass
    return out


# ==============================================================================
# Core Technology & Evidence Detector
# ==============================================================================

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
    if 'sgtm_fpid_cookie_verified' in ev_str:
        return True
    if 'doubleclick.net' in ev_str.lower() and not SGTM_CUSTOM_LOADER_REGEX.search(ev_str):
        return False
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
        conf = f'High ({total_count} GA4 IDs configured in multi-region GTM lookup table; verify active runtime property)'
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
    dup_runtime_confirmed = bool(tech_info.get('duplicate_ga4_runtime_confirmed'))
    has_esp = bool(
        tech_info.get('has_klaviyo')
        or tech_info.get('has_hubspot')
        or tech_info.get('has_esp_retention')
    )

    paid_count = sum(1 for x in (has_meta, has_gads, has_tiktok) if x)

    if dup_ga4_ids:
        dup_str = ', '.join(dup_ga4_ids[:2])
        if dup_runtime_confirmed:
            flags.append(
                f'Duplicate GA4 Tagging [duplicate_runtime_hits_confirmed] ({dup_str} present in both HTML and GTM with multiple network hits observed)'
            )
        else:
            flags.append(
                f'Duplicate GA4 Tagging [duplicate_configuration_suspected] ({dup_str} present in both page HTML and GTM container — verify runtime firing triggers)'
            )

    if (
        is_eu_gdpr
        and has_gads
        and not has_cm_v2
        and tech_info.get('tech_scan_completeness') == 'full'
        and (pw_used or has_consent_banner)
    ):
        flags.append(
            'EU Consent Mode v2 Gap (Google Ads tag configured in EEA jurisdiction without observable gcs/gcd consent signals)'
        )

    if paid_count >= 2 and not has_sgtm:
        flags.append(
            'Client-Side Tracking Architecture (Multi-pixel ad tags configured without observable first-party sGTM collector — validate ITP/CAPI signal recovery)'
        )

    if company_category == 'E-commerce / Retail Brand' and paid_count >= 1 and not has_esp:
        flags.append(
            'E-commerce Retention Stack Hypothesis (Ad pixels configured without observable client-side ESP/Klaviyo/CRM retention script)'
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

    header_ssr_signals = extract_embedded_headers_and_ssr_signals_v23_1(html)
    html_without_comments = HTTP_HEADERS_COMMENT_RE.sub('', _PW_NET_REQ_REGEX.sub('', html))
    html_lower = html_without_comments.lower()
    gtm_lower = gtm_js.lower() if gtm_js else ''
    combined_source = f'{html_without_comments}\n{ pw_net_combined }\n{gtm_js}' if gtm_js else f'{html_without_comments}\n{pw_net_combined}'

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
    has_sgtm_cookie = bool(header_ssr_signals.get('has_sgtm_fpid_cookie'))
    has_sgtm = bool(sgtm_match or has_sgtm_cookie)

    if has_sgtm:
        found_tech.append('Server-Side GTM (sGTM)')
        if sgtm_match:
            sgtm_snip = sgtm_match.group(0)[:85]
            sgtm_src = 'pw_network' if (sgtm_collect_match and sgtm_snip.lower() in pw_net_lower) else 'live_html'
            evidence_items.append(f'Server-Side GTM (sGTM): custom endpoint "{sgtm_snip}" @ {page_url}')
            evidence_json_map['Server-Side GTM (sGTM)'] = {
                'source': sgtm_src,
                'endpoint': sgtm_snip,
            }
        else:
            evidence_items.append(f'Server-Side GTM (sGTM): sgtm_fpid_cookie_verified @ {page_url}')
            evidence_json_map['Server-Side GTM (sGTM)'] = {
                'source': 'http_cookie_header',
                'cookie': 'FPID',
            }
        summary_items.append('sGTM')

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

    html_direct_ga4 = {m.upper() for m in GTAG_CONFIG_GA4_REGEX.findall(html_without_comments)}
    html_direct_ga4.update(m.upper() for m in GA4_SCRIPT_SRC_REGEX.findall(html_without_comments))

    high_conf_ga4 = set(GA4_STRICT_10CHAR_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GTAG_CONFIG_GA4_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GA4_SCRIPT_SRC_REGEX.findall(combined_source))
    high_conf_ga4.update(m.upper() for m in GA4_WIRE_REGEX.findall(combined_source))

    gtm_macro_ga4 = {m.upper() for m in GTM_JSON_GA4_REGEX.findall(gtm_js)} if gtm_js else set()
    duplicate_ga4_ids = sorted(html_direct_ga4 & gtm_macro_ga4)

    net_tid_counts = Counter(m.upper() for m in _NET_COLLECT_TID_REGEX.findall(pw_net_combined))
    duplicate_ga4_runtime_confirmed = any(net_tid_counts.get(gid, 0) >= 2 for gid in duplicate_ga4_ids)

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
            ga4_confidence = (
                f'High ({total_ga4_count} GA4 IDs configured in multi-region GTM lookup table; verify active runtime property)'
            )
        elif high_conf_ga4 or total_ga4_count >= 2:
            ga4_confidence = 'High'
        else:
            ga4_confidence = 'Medium (GTM Single Macro)'
        ga4_src_label = 'live_html' if any(gid in html_without_comments for gid in all_ga4_set) else (
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
            ga4_ev_entry['duplicate_status'] = (
                'duplicate_runtime_hits_confirmed' if duplicate_ga4_runtime_confirmed else 'duplicate_configuration_suspected'
            )
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
            any(a in html_without_comments for a in aw_ids) or 'googleadservices.com' in html_lower
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
                    html_without_comments if in_html else (pw_net_combined if in_net else gtm_js),
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
                snip = extract_code_snippet(html_without_comments, sig)
                evidence_items.append(f'{cms_name} (CMS): "{sig}" in page HTML ("{snip}")')
                summary_items.append(cms_name)
                evidence_json_map[cms_name] = {
                    'source': 'live_html',
                    'signature': sig,
                }
                break

    # Додаємо технології, знайдені через безпечні HTTP-заголовки / CSP / cookie_names (v23.1)
    for hdr_tech in header_ssr_signals.get('detected_tech') or []:
        if hdr_tech in ('Shopify', 'Magento', 'Shopware') and hdr_tech not in detected_cms_list:
            detected_cms_list.append(hdr_tech)
        if hdr_tech not in found_tech:
            found_tech.append(hdr_tech)
            short_lbl = SHORT_SUMMARY_LABELS.get(hdr_tech, hdr_tech)
            if short_lbl not in summary_items:
                summary_items.append(short_lbl)
            evidence_items.append(f'{hdr_tech}: verified via HTTP CSP/Cookie/SSR header @ {page_url}')
            evidence_json_map.setdefault(hdr_tech, {'source': 'http_headers_or_ssr'})

    if 'WooCommerce' in detected_cms_list and 'WordPress' not in detected_cms_list:
        detected_cms_list.append('WordPress')
        if 'WordPress' not in found_tech:
            found_tech.append('WordPress')

    has_esp_retention = (
        'Klaviyo' in found_tech
        or 'HubSpot' in found_tech
        or any(
            esp_sig in html_lower or esp_sig in gtm_lower or esp_sig in pw_net_lower
            for esp_sig in ESP_RETENTION_SIGNATURES
        )
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
        'has_enterprise_cdn': bool(header_ssr_signals.get('has_enterprise_cdn')),
        'payment_gateways': header_ssr_signals.get('payment_gateways') or [],
        'has_consent_mode_v2_signals': has_consent_mode_v2_signals,
        'duplicate_ga4_ids': duplicate_ga4_ids,
        'duplicate_ga4_runtime_confirmed': duplicate_ga4_runtime_confirmed,
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
