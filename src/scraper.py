import asyncio
from datetime import datetime, timezone
import ipaddress
import json
import re
import socket
import ssl
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse
from apify import Actor
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from curl_cffi.requests import AsyncSession

from .config import (
    CHECKOUT_REDIRECT_HOSTS,
    CMP_ACCEPT_SELECTORS,
    CONTACT_ANCHOR_TEXT_KEYWORDS,
    EMAIL_REGEX,
    GTM_ID_REGEX,
    INFRA_SAN_DENYLIST,
    KNOWN_DOMAIN_REDIRECT_ALIASES,
    MAX_HTML_BYTES,
    MULTI_PART_TLDS as CONFIG_MULTI_PART_TLDS,
    PRIMARY_CONTACT_KEYWORDS,
    SCHEMA_PHONE_REGEX,
    SECONDARY_CONTACT_KEYWORDS,
    SOFT_404_TITLE_REGEX,
    TRUSTED_CA_ISSUER_MARKERS,
    clean_url_port,
    is_valid_gtm_id,
)
from .contacts import (
    clean_and_validate_social_url,
    decode_cf_email,
    extract_valid_phones,
    pick_best_social_candidate,
)

try:
    from patchright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
    _USING_PATCHRIGHT = True
except ImportError:
    try:
        from playwright.async_api import async_playwright
        _PLAYWRIGHT_AVAILABLE = True
        _USING_PATCHRIGHT = False
    except ImportError:
        _PLAYWRIGHT_AVAILABLE = False
        _USING_PATCHRIGHT = False

_SHARED_PW = None
_SHARED_BROWSER = None
_NATIVE_CLEAN_UA: str | None = None
_BROWSER_LOCK = asyncio.Lock()
_PW_SEMAPHORE = asyncio.Semaphore(3)
_ESCALATION_PROXY_CFG = None

STRIPPABLE_SUBDOMAIN_PREFIXES = {
    'www', 'en', 'de', 'uk', 'ua', 'ru', 'fr', 'es', 'it', 'nl',
    'pl', 'pt', 'se', 'sv', 'no', 'dk', 'da', 'fi', 'cz', 'cs',
    'ro', 'hu', 'at', 'ch', 'be', 'us', 'gb', 'eu', 'int', 'global', 'm'
}

MULTI_PART_TLD_SUFFIXES = tuple(f'.{t}' for t in CONFIG_MULTI_PART_TLDS)

CF_EMAIL_ATTR_RE = re.compile(r'data-cfemail=["\']([0-9a-fA-F]{10,128})["\']')
CF_EMAIL_HREF_RE = re.compile(r'/cdn-cgi/l/email-protection#([0-9a-fA-F]{10,128})')
HONEYPOT_STYLE_RE = re.compile(
    r"(?:font-size\s*:\s*0(?:px|em|rem|pt|%|\b)|opacity\s*:\s*0(?:\.0+)?\b|"
    r"left\s*:\s*-\d{3,}px|text-indent\s*:\s*-\d{3,}px)",
    re.IGNORECASE
)


def _extract_etld_local(host_or_url: str) -> tuple[str, str]:
    if not host_or_url:
        return "", ""
    raw = host_or_url.strip().lower()
    hostname = (urlparse(raw).hostname or "") if "://" in raw else raw.split("/")[0].split(":")[0]
    hostname = hostname.strip(".")
    while hostname.startswith("*.") or hostname.startswith("*. "):
        hostname = hostname[2:].strip()
    parts = [p for p in hostname.split(".") if p]
    if len(parts) < 2:
        return hostname, hostname
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in CONFIG_MULTI_PART_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}", parts[-3]
    return last_two, parts[-2]


async def _check_host_ssrf_local(hostname: str, timeout: float = 1.2) -> tuple[bool, str]:
    if not hostname:
        return False, "empty_host"
    clean = hostname.strip().lower().rstrip(".")
    if clean in ("localhost", "0.0.0.0", "broadcasthost") or clean.endswith(
        (".local", ".internal", ".arpa", ".lan", ".localhost", ".home", ".corp", ".intranet")
    ):
        return False, "ssrf_blocked"
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
            return False, "ssrf_blocked"
        return True, "ok"
    except ValueError:
        pass
    try:
        loop = asyncio.get_running_loop()
        addr_info = await asyncio.wait_for(loop.getaddrinfo(clean, None), timeout=timeout)
        if not addr_info:
            return False, "dns_error"
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
                return False, "ssrf_blocked"
        return True, "ok"
    except (socket.gaierror, asyncio.TimeoutError):
        return False, "dns_error"
    except Exception:
        return False, "dns_error"


# ==============================================================================
# v23.1 Complete: 7 функцій безбраузерного витягу даних (Фаза 1)
# ==============================================================================

def append_safe_headers_comment_v23_1(html_text: str, resp_headers: Any) -> str:
    """
    Вшиває інфраструктурні заголовки та ВИКЛЮЧНО імена кукі (cookie_names без значень)
    у коментар <!-- http_headers_json: {...} --> в кінці HTML.
    """
    if not html_text or not resp_headers:
        return html_text
    safe_keys = {
        "content-security-policy", "content-security-policy-report-only",
        "server-timing", "x-shopid", "x-shopify-stage", "x-magento-tags",
        "sw-context-token", "alt-svc", "cf-polished", "cf-ew-via",
        "x-akamai-transformed", "reporting-endpoints", "report-to", "nel",
    }
    extracted: Dict[str, Any] = {}
    cookie_names: Set[str] = set()

    items = resp_headers.multi_items() if hasattr(resp_headers, "multi_items") else resp_headers.items()
    for k, v in items:
        k_low = str(k).lower()
        if k_low in safe_keys:
            extracted[k_low] = str(v)[:3500]
        elif k_low == "set-cookie":
            first_pair = str(v).split(";", 1)[0].strip()
            if "=" in first_pair:
                c_name = first_pair.split("=", 1)[0].strip()
                if c_name and len(c_name) <= 64:
                    cookie_names.add(c_name)

    if cookie_names:
        extracted["cookie_names"] = sorted(cookie_names)
    if not extracted:
        return html_text

    safe_json = json.dumps(extracted, ensure_ascii=False).replace("-->", "--\\u003e")
    return f"{html_text}\n<!-- http_headers_json: {safe_json} -->"


def evaluate_x509_der_trust_and_org(cert: x509.Certificate) -> Dict[str, Any]:
    now_utc = datetime.now(timezone.utc)
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    is_not_expired = nb <= now_utc <= na
    is_not_self_signed = cert.issuer != cert.subject

    issuer_attrs = (
        cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        + cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    )
    issuer_str = " ".join(str(a.value) for a in issuer_attrs).lower()
    is_known_ca = any(ca in issuer_str for ca in TRUSTED_CA_ISSUER_MARKERS)
    is_trusted = bool(is_not_expired and is_not_self_signed and is_known_ca)

    org_name = None
    if is_trusted:
        subj_orgs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if subj_orgs:
            val = str(subj_orgs[0].value).strip()
            if val and "cloudflare" not in val.lower() and "persona not validated" not in val.lower():
                org_name = val

    return {
        "tls_trust_status": "trusted_ca_active" if is_trusted else "untrusted_or_expired_observed",
        "issuer_ca": issuer_str[:120] if issuer_str else None,
        "verified_organization_name": org_name,
    }


async def extract_tls_x509_der_intel(domain: str, timeout: float = 2.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "organization_name": None,
        "tls_trust_status": "unreachable",
        "jurisdiction_country": None,
        "corporate_sans": [],
        "prioritized_bypass_hosts": [],
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        der_bytes = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        if not der_bytes:
            return result

        cert = x509.load_der_x509_certificate(der_bytes)
        trust_info = evaluate_x509_der_trust_and_org(cert)
        result["organization_name"] = trust_info["verified_organization_name"]
        result["tls_trust_status"] = trust_info["tls_trust_status"]

        jur_attrs = cert.subject.get_attributes_for_oid(NameOID.JURISDICTION_COUNTRY_NAME)
        if jur_attrs and trust_info["tls_trust_status"] == "trusted_ca_active":
            result["jurisdiction_country"] = str(jur_attrs[0].value).strip()

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            raw_dns: List[str] = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            raw_dns = []

        _, target_brand = _extract_etld_local(domain)
        clean_sans: Set[str] = set()
        bypass_candidates: List[str] = []

        for entry in raw_dns:
            ch = entry.lower().strip().removeprefix("*.")
            reg_dom, san_brand = _extract_etld_local(ch)
            if not reg_dom or any(reg_dom.endswith(infra) for infra in INFRA_SAN_DENYLIST):
                continue
            clean_sans.add(reg_dom)
            if san_brand == target_brand and ch not in (domain, f"www.{domain}"):
                if any(k in ch for k in ("corporate.", "group.", "about.", "ir.", "b2b.")):
                    bypass_candidates.insert(0, ch)
                else:
                    bypass_candidates.append(reg_dom)

        result["corporate_sans"] = sorted(clean_sans)[:15]
        result["prioritized_bypass_hosts"] = list(dict.fromkeys(bypass_candidates))[:5]
    except Exception:
        pass
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    return result


def decode_cloudflare_cfemail_hex(hex_str: str) -> str:
    try:
        clean_hex = hex_str.strip()
        if len(clean_hex) < 10 or len(clean_hex) % 2 != 0:
            return ""
        key = int(clean_hex[:2], 16)
        decoded = "".join(chr(int(clean_hex[i : i + 2], 16) ^ key) for i in range(2, len(clean_hex), 2))
        return decoded if "@" in decoded and "." in decoded else ""
    except Exception:
        return ""


def deobfuscate_cfemails_in_html(html_text: str) -> str:
    if not html_text or ("data-cfemail" not in html_text and "email-protection#" not in html_text):
        return html_text

    def _replace_attr(m: re.Match) -> str:
        email = decode_cloudflare_cfemail_hex(m.group(1))
        return f'data-cfemail="{m.group(1)}" data-decoded-email="{email}"' if email else m.group(0)

    def _replace_href(m: re.Match) -> str:
        email = decode_cloudflare_cfemail_hex(m.group(1))
        return f"mailto:{email}" if email else m.group(0)

    out = CF_EMAIL_ATTR_RE.sub(_replace_attr, html_text)
    return CF_EMAIL_HREF_RE.sub(_replace_href, out)


def prune_honeypot_leaf_nodes_in_soup(soup: Any) -> Set[str]:
    poisoned_emails: Set[str] = set()
    if not soup:
        return poisoned_emails
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    for tag in soup.find_all(["span", "a", "div", "p", "small"]):
        if tag.find(["div", "section", "nav", "ul", "table", "form"]):
            continue
        style_str = str(tag.get("style") or "")
        cls_list = " ".join(tag.get("class") or []).lower()
        if HONEYPOT_STYLE_RE.search(style_str) or "honeypot" in cls_list or " trap" in f" {cls_list}":
            raw_content = f"{tag.get_text(' ', strip=True)} {tag.get('href', '')}"
            for bad_email in email_re.findall(raw_content):
                poisoned_emails.add(bad_email.lower())
            tag.decompose()
    return poisoned_emails


async def fetch_waf_bypass_or_wayback_legal(
    http_client: Any,
    domain: str,
    bypass_hosts: List[str]
) -> Tuple[str, str]:
    """
    Повертає (recovered_html, recovery_source).
    Спочатку перевіряє корпоративні SAN-хости з тим самим brand_root (після Anti-SSRF перевірки),
    а за їх відсутності забирає юридичний роут із Wayback Machine CDX API з модифікатором id_.
    """
    _, target_brand = _extract_etld_local(domain)
    for host in (bypass_hosts or [])[:3]:
        _, host_brand = _extract_etld_local(host)
        if host_brand != target_brand:
            continue
        is_ok, _ = await _check_host_ssrf_local(host, timeout=1.2)
        if not is_ok:
            continue
        for path in ("/impressum", "/imprint", "/en/imprint", "/contact", ""):
            try:
                resp = await http_client.get(f"https://{host}{path}", timeout=2.5)
                if resp.status_code == 200 and len(resp.text) > 800:
                    return resp.text, f"lateral_san:{host}{path}"
            except Exception:
                continue

    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
        f"&collapse=urlkey&filter=statuscode:200"
        f"&filter=original:.*(impressum|imprint|legal|kontakt|contact|about).*&limit=3"
    )
    try:
        cdx_resp = await http_client.get(cdx_url, timeout=2.5)
        if cdx_resp.status_code == 200:
            rows = cdx_resp.json()
            if isinstance(rows, list) and len(rows) >= 2:
                headers_row = rows[0]
                data_row = rows[-1]
                row_dict = dict(zip(headers_row, data_row))
                ts = row_dict.get("timestamp")
                orig = row_dict.get("original")
                if ts and orig:
                    snap_resp = await http_client.get(f"https://web.archive.org/web/{ts}id_/{orig}", timeout=2.8)
                    if snap_resp.status_code == 200 and len(snap_resp.text) > 500:
                        return snap_resp.text, "wayback_cdx_legal"
    except Exception:
        pass
    return "", "none"


async def fetch_store_and_well_known_bundle(
    http_client: Any,
    domain: str,
    html_text: str = ""
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "products_list": [],
        "ecom_currency": None,
        "ecom_avg_price": None,
        "ecom_out_of_stock_ratio": 0.0,
        "sitemap_estimated_skus": 0,
        "apple_pay_raw": "",
        "android_package_name": None,
        "security_txt_contact": None,
    }
    is_shopify = "shopify" in (html_text or "").lower()
    tasks: Dict[str, Any] = {
        "apple_pay": http_client.get(f"https://{domain}/.well-known/apple-developer-merchantid-domain-association", timeout=2.0),
        "assetlinks": http_client.get(f"https://{domain}/.well-known/assetlinks.json", timeout=2.0),
        "security_txt": http_client.get(f"https://{domain}/.well-known/security.txt", timeout=2.0),
        "sitemap": http_client.get(f"https://{domain}/sitemap.xml", timeout=2.2),
    }
    if is_shopify:
        tasks["products_json"] = http_client.get(f"https://{domain}/products.json?limit=250", timeout=2.5)
        tasks["cart_js"] = http_client.get(f"https://{domain}/cart.js", timeout=1.8)

    keys = list(tasks.keys())
    res_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
    res_map = dict(zip(keys, res_list))

    p_resp = res_map.get("products_json")
    if p_resp and not isinstance(p_resp, Exception) and getattr(p_resp, "status_code", 0) == 200:
        try:
            prods = p_resp.json().get("products") or []
            out["products_list"] = prods
            prices = []
            unavail = 0
            total_v = 0
            for pr in prods:
                for v in (pr.get("variants") or []):
                    total_v += 1
                    if not v.get("available", True):
                        unavail += 1
                    try:
                        val = float(v.get("price") or 0)
                        if val > 0:
                            prices.append(val)
                    except (ValueError, TypeError):
                        pass
            if prices:
                out["ecom_avg_price"] = round(sum(prices) / len(prices), 2)
            if total_v > 0:
                out["ecom_out_of_stock_ratio"] = round(unavail / total_v, 2)
        except Exception:
            pass

    c_resp = res_map.get("cart_js")
    if c_resp and not isinstance(c_resp, Exception) and getattr(c_resp, "status_code", 0) == 200:
        try:
            out["ecom_currency"] = c_resp.json().get("currency")
        except Exception:
            pass

    ap_resp = res_map.get("apple_pay")
    if ap_resp and not isinstance(ap_resp, Exception) and getattr(ap_resp, "status_code", 0) == 200:
        out["apple_pay_raw"] = ap_resp.text[:16384]

    al_resp = res_map.get("assetlinks")
    if al_resp and not isinstance(al_resp, Exception) and getattr(al_resp, "status_code", 0) == 200:
        try:
            al_data = al_resp.json()
            if isinstance(al_data, list) and al_data:
                pkg = (al_data[0].get("target") or {}).get("package_name")
                if pkg:
                    out["android_package_name"] = str(pkg)
        except Exception:
            pass

    sec_resp = res_map.get("security_txt")
    if sec_resp and not isinstance(sec_resp, Exception) and getattr(sec_resp, "status_code", 0) == 200:
        ctype = str(sec_resp.headers.get("content-type", "")).lower()
        txt_body = sec_resp.text[:2000]
        if "text/plain" in ctype and "contact:" in txt_body.lower():
            m_sec = re.search(r"Contact:\s*(?:mailto:)?([^\s\r\n]+)", txt_body, re.IGNORECASE)
            if m_sec:
                out["security_txt_contact"] = m_sec.group(1).strip()

    sm_resp = res_map.get("sitemap")
    if sm_resp and not isinstance(sm_resp, Exception) and getattr(sm_resp, "status_code", 0) == 200:
        sm_text = sm_resp.text[:65536]
        prod_shards = len(re.findall(r"sitemap[-_]?products", sm_text, re.IGNORECASE))
        url_tags = len(re.findall(r"<loc>", sm_text, re.IGNORECASE))
        out["sitemap_estimated_skus"] = prod_shards * 2500 if prod_shards > 0 else url_tags

    return out


# ==============================================================================
# Core Scraper & Playwright Engine
# ==============================================================================

def is_playwright_available() -> bool:
    return _PLAYWRIGHT_AVAILABLE


def has_residential_escalation_proxy() -> bool:
    return _ESCALATION_PROXY_CFG is not None


def configure_pw(escalation_proxy=None, max_concurrent: int = 3) -> None:
    global _ESCALATION_PROXY_CFG, _PW_SEMAPHORE
    _ESCALATION_PROXY_CFG = escalation_proxy
    _PW_SEMAPHORE = asyncio.Semaphore(max(1, int(max_concurrent or 3)))


async def close_shared_playwright_browser() -> None:
    global _SHARED_PW, _SHARED_BROWSER, _NATIVE_CLEAN_UA
    async with _BROWSER_LOCK:
        if _SHARED_BROWSER is not None:
            try:
                await _SHARED_BROWSER.close()
            except Exception:
                pass
            _SHARED_BROWSER = None
        if _SHARED_PW is not None:
            try:
                await _SHARED_PW.stop()
            except Exception:
                pass
            _SHARED_PW = None
        _NATIVE_CLEAN_UA = None


def strip_language_or_www_subdomains(host: str) -> str:
    h = (host or '').strip().lower().strip('.')
    if not h:
        return h
    min_parts = 3 if h.endswith(MULTI_PART_TLD_SUFFIXES) else 2
    parts = h.split('.')
    while len(parts) > min_parts and parts[0] in STRIPPABLE_SUBDOMAIN_PREFIXES:
        parts.pop(0)
    return '.'.join(parts)


def _is_safe_domain(netloc: str) -> bool:
    if not netloc:
        return False
    host = netloc.split(':')[0].strip().lower().strip('[]')
    if not host or '.' not in host or ' ' in host:
        return False
    if host in ('localhost', 'broadcasthost', '0.0.0.0') or host.endswith(
        ('.local', '.internal', '.lan', '.localhost', '.home', '.corp', '.intranet', '.arpa')
    ):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    tld = host.rsplit('.', 1)[-1]
    if not tld.isalpha() or len(tld) < 2:
        return False
    return bool(re.fullmatch(r'[a-z0-9.-]+', host))


def prepare_domains(raw_domains: list[str]) -> list[tuple[str, str, list[str]]]:
    grouped: dict[str, list[str]] = {}
    root_urls: dict[str, str] = {}

    for item in raw_domains:
        if not item or not isinstance(item, str):
            continue
        raw = item.strip().lower()
        if not raw:
            continue
        if '://' not in raw:
            parsed = urlparse(f'https://{raw}')
        else:
            parsed = urlparse(raw)
            if parsed.scheme not in ('http', 'https'):
                continue

        host = parsed.netloc or parsed.path.split('/')[0]
        host = host.split('@')[-1]
        host = re.sub(r':\d+$', '', host).strip('.')
        host = strip_language_or_www_subdomains(host)

        if not _is_safe_domain(host):
            continue

        canonical = KNOWN_DOMAIN_REDIRECT_ALIASES.get(host, host)
        if canonical not in grouped:
            grouped[canonical] = []
            root_urls[canonical] = f'https://{canonical}/'
        if host not in grouped[canonical]:
            grouped[canonical].append(host)
        if canonical not in grouped[canonical]:
            grouped[canonical].append(canonical)

    return [(dom, root_urls[dom], aliases) for dom, aliases in grouped.items()]


def get_clean_canonical_domain(final_url: str, fallback_domain: str) -> str:
    fb_clean = strip_language_or_www_subdomains(fallback_domain)
    try:
        parsed = urlparse(final_url)
        host = re.sub(r':\d+$', '', parsed.netloc.lower()).strip('.')
        if not host or CHECKOUT_REDIRECT_HOSTS.match(host):
            return KNOWN_DOMAIN_REDIRECT_ALIASES.get(fb_clean, fb_clean)
        host = strip_language_or_www_subdomains(host)
        if not host:
            return KNOWN_DOMAIN_REDIRECT_ALIASES.get(fb_clean, fb_clean)
        return KNOWN_DOMAIN_REDIRECT_ALIASES.get(host, host)
    except Exception:
        return KNOWN_DOMAIN_REDIRECT_ALIASES.get(fb_clean, fb_clean)


def classify_failure_status(status: int, err_msg: str) -> str:
    err_low = (err_msg or '').lower()
    if status in (401, 403, 429, 503) or 'cloudflare' in err_low or 'captcha' in err_low or 'waf:' in err_low:
        return 'blocked'
    if 'timeout' in err_low or 'timed out' in err_low:
        return 'timeout'
    if 'ssl' in err_low or 'certificate' in err_low:
        return 'ssl_error'
    if 'resolve' in err_low or 'name or service not known' in err_low or 'dns' in err_low or 'getaddrinfo' in err_low:
        return 'dns_error'
    if status >= 500:
        return f'http_{status}'
    return 'unreachable'


def is_dynamic_hopeless_waf(err_msg: str) -> bool:
    err_low = (err_msg or '').lower()
    hard_waf_markers = ('waf:akamai', 'waf:datadome', 'waf:perimeterx', 'waf:imperva')
    if any(m in err_low for m in hard_waf_markers) and _ESCALATION_PROXY_CFG is None:
        return True
    if ('waf:cf_challenge' in err_low) and _ESCALATION_PROXY_CFG is None:
        return True
    return False


def is_soft_404_page(html: str, page_title: str) -> bool:
    if not html:
        return True
    if page_title and SOFT_404_TITLE_REGEX.search(page_title):
        return True
    if len(html) < 1800 and ('404' in html[:800] or 'not found' in html[:800].lower()):
        return True
    return False


def _detect_waf_vendor_from_response(resp) -> str:
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in (resp.headers or {}).items()}
        server = headers.get('server', '')
        if 'akamaighost' in server or 'akamai' in server or 'x-akamai-transformed' in headers:
            return 'waf:akamai'
        if 'datadome' in server or 'x-datadome' in headers or 'x-dd-b' in headers:
            return 'waf:datadome'
        if 'cf-mitigated' in headers or ('cloudflare' in server and resp.status_code in (403, 503)):
            return 'waf:cf_challenge'
        if 'x-iinfo' in headers or 'incapsula' in server:
            return 'waf:imperva'
    except Exception:
        pass
    return ''


async def fetch_html_safely(
    client: AsyncSession,
    url: str,
    proxy_config=None,
    timeout: float = 12.0,
    retries: int = 2
) -> tuple[int, str, str, str]:
    """
    Системний інваріант #1 та #2 (v23.1 Complete):
    Незмінно повертає 4-елементний кортеж (status, html, final_url, err_msg)
    та вшиває безпечні HTTP-заголовки і cookie_names у коментар <!-- http_headers_json: {...} -->.
    """
    last_status = 0
    last_err = ''
    final_url = url

    for attempt in range(retries + 1):
        proxy_url = None
        if proxy_config is not None and attempt > 0:
            try:
                proxy_url = await proxy_config.new_url()
            except Exception:
                proxy_url = None
        try:
            kwargs = {'timeout': timeout, 'allow_redirects': True}
            if proxy_url:
                kwargs['proxy'] = proxy_url
            resp = await client.get(url, **kwargs)
            last_status = resp.status_code
            final_url = str(resp.url) or url
            if 200 <= last_status < 400:
                text = resp.text[:MAX_HTML_BYTES] if resp.text else ''
                text = append_safe_headers_comment_v23_1(text, getattr(resp, 'headers', None))
                return last_status, text, final_url, ''
            waf_tag = _detect_waf_vendor_from_response(resp)
            last_err = f'HTTP {last_status} ({waf_tag})' if waf_tag else f'HTTP {last_status}'
        except Exception as e:
            last_err = str(e)
        if attempt < retries:
            await asyncio.sleep(0.6 * (attempt + 1))

    return last_status, '', final_url, last_err


async def fetch_gtm_scripts(client: AsyncSession, html: str) -> tuple[list[str], str]:
    gtm_ids = sorted({
        m.upper() for m in GTM_ID_REGEX.findall(html)
        if is_valid_gtm_id(m)
    })
    if not gtm_ids:
        return [], ''

    async def _fetch_one(gid: str) -> str:
        gtm_url = f'https://www.googletagmanager.com/gtm.js?id={gid}'
        for use_direct in (False, True):
            try:
                kwargs: dict = {'timeout': 6.0}
                if use_direct:
                    kwargs['proxy'] = None
                resp = await client.get(gtm_url, **kwargs)
                if resp.status_code == 200 and resp.text:
                    return resp.text[:450_000]
            except Exception:
                continue
        return ''

    scripts = await asyncio.gather(*(_fetch_one(gid) for gid in gtm_ids[:2]))
    return gtm_ids, '\n'.join(s for s in scripts if s)


async def load_robots_rules(client: AsyncSession, base_root: str) -> tuple[list[str], float]:
    disallowed: list[str] = []
    crawl_delay = 0.05
    try:
        resp = await client.get(f'{base_root}/robots.txt', timeout=4.0)
        if resp.status_code == 200 and resp.text:
            active_ua = False
            for line in resp.text.splitlines()[:200]:
                line = line.split('#', 1)[0].strip()
                if not line or ':' not in line:
                    continue
                k, v = [x.strip() for x in line.split(':', 1)]
                k_low = k.lower()
                if k_low == 'user-agent':
                    active_ua = (v == '*' or 'bot' in v.lower())
                elif active_ua and k_low == 'disallow' and v.startswith('/'):
                    if v != '/':
                        disallowed.append(v)
                elif active_ua and k_low == 'crawl-delay':
                    try:
                        crawl_delay = min(0.5, max(0.05, float(v)))
                    except ValueError:
                        pass
    except Exception:
        pass
    return disallowed, crawl_delay


def is_allowed_by_robots(url: str, disallowed_paths: list[str]) -> bool:
    if not disallowed_paths:
        return True
    path = urlparse(url).path or '/'
    return not any(path.startswith(d) for d in disallowed_paths)


async def discover_links_from_sitemap(client: AsyncSession, base_root: str) -> list[str]:
    found: list[str] = []
    for sm_path in ('/sitemap.xml', '/sitemap_index.xml', '/page-sitemap.xml'):
        try:
            resp = await client.get(f'{base_root}{sm_path}', timeout=5.0)
            if resp.status_code == 200 and resp.text:
                locs = re.findall(r'<loc>\s*(https?://[^<\s]+)\s*</loc>', resp.text, re.I)
                for loc in locs[:400]:
                    p_low = urlparse(loc).path.lower()
                    if any(k in p_low for k in PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS):
                        if loc not in found:
                            found.append(loc)
                if found:
                    break
        except Exception:
            continue
    return found[:8]


def extract_semantic_contact_links_from_html(
    html: str,
    base_url: str,
    canonical_domain: str
) -> list[str]:
    soup = BeautifulSoup(html, 'lxml')
    links: list[str] = []
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            continue
        full_u = clean_url_port(urljoin(base_url, href))
        if not full_u:
            continue
        parsed = urlparse(full_u)
        if parsed.scheme not in ('http', 'https'):
            continue
        host = strip_language_or_www_subdomains(parsed.netloc.lower())
        if host != canonical_domain and not host.endswith(f'.{canonical_domain}'):
            continue
        path_low = parsed.path.lower()
        anchor_low = a_tag.get_text(' ', strip=True).lower()
        if (
            any(k in path_low for k in PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS)
            or any(ak in anchor_low for ak in CONTACT_ANCHOR_TEXT_KEYWORDS)
        ):
            if full_u not in links:
                links.append(full_u)
    return links[:10]


def parse_html_sync(
    html: str,
    page_url: str,
    default_region: str = 'US'
) -> tuple[str, str, str, dict[str, str], list[tuple[str, int, str]], dict[str, tuple[str, str]], list[str]]:
    html_deobf = deobfuscate_cfemails_in_html(html)
    soup = BeautifulSoup(html_deobf, 'lxml')
    poisoned_honeypot_emails = prune_honeypot_leaf_nodes_in_soup(soup)

    page_title = ''
    if soup.title and soup.title.string:
        page_title = ' '.join(soup.title.string.split())[:220]
    if not page_title:
        og_t = soup.find('meta', attrs={'property': 'og:title'}) or soup.find('meta', attrs={'name': 'twitter:title'})
        if og_t and og_t.get('content'):
            page_title = ' '.join(str(og_t['content']).split())[:220]

    meta_desc = ''
    desc_tag = (
        soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)})
        or soup.find('meta', attrs={'property': 'og:description'})
    )
    if desc_tag and desc_tag.get('content'):
        meta_desc = ' '.join(str(desc_tag['content']).split())[:350]

    email_sources: dict[str, str] = {}
    for m in EMAIL_REGEX.findall(html_deobf):
        if m.lower() not in poisoned_honeypot_emails:
            email_sources.setdefault(m, page_url)

    for cf_el in soup.find_all(attrs={'data-cfemail': True}):
        decoded = decode_cf_email(str(cf_el.get('data-cfemail', '')))
        if decoded and '@' in decoded and decoded.lower() not in poisoned_honeypot_emails:
            email_sources.setdefault(decoded, page_url)

    raw_tel_candidates: list[tuple[str, str]] = []
    for sm in SCHEMA_PHONE_REGEX.findall(html_deobf):
        raw_tel_candidates.append((sm, 'schema_telephone'))

    parsed_base = urlparse(page_url)
    base_host = strip_language_or_www_subdomains(re.sub(r':\d+$', '', parsed_base.netloc.lower()))
    brand_root = base_host.split('.')[0] if base_host else ''

    social_candidates: dict[str, list[tuple[str, str]]] = {
        'linkedin': [], 'instagram': [], 'facebook': [],
        'telegram': [], 'tiktok': [], 'youtube': [], 'twitter': []
    }
    contact_links: list[str] = []

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        if not href:
            continue
        href_low = href.lower()
        if href_low.startswith('mailto:'):
            addr = href[7:].split('?')[0].strip()
            if addr and '@' in addr and addr.lower() not in poisoned_honeypot_emails:
                email_sources.setdefault(addr, page_url)
            continue
        if href_low.startswith('tel:'):
            raw_tel = href[4:].split('?')[0].strip()
            parent_ctx = a_tag.parent.get_text(' ', strip=True)[:120] if a_tag.parent else ''
            raw_tel_candidates.append((raw_tel, parent_ctx))
            continue

        full_url = clean_url_port(urljoin(page_url, href))
        if not full_url:
            continue
        p_u = urlparse(full_url)
        if p_u.scheme not in ('http', 'https'):
            continue

        u_host = p_u.netloc.lower()
        for plat, dom_markers in (
            ('linkedin', ('linkedin.com',)),
            ('instagram', ('instagram.com',)),
            ('facebook', ('facebook.com', 'fb.com')),
            ('telegram', ('t.me', 'telegram.me')),
            ('tiktok', ('tiktok.com',)),
            ('youtube', ('youtube.com',)),
            ('twitter', ('twitter.com', 'x.com')),
        ):
            if any(dm in u_host for dm in dom_markers):
                clean_soc = clean_and_validate_social_url(plat, full_url)
                if clean_soc:
                    social_candidates[plat].append((clean_soc, page_url))
                break
        else:
            clean_u_host = strip_language_or_www_subdomains(re.sub(r':\d+$', '', u_host))
            if clean_u_host == base_host or clean_u_host.endswith(f'.{base_host}'):
                path_low = p_u.path.lower()
                anchor_txt = a_tag.get_text(' ', strip=True).lower()
                if (
                    any(k in path_low for k in PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS)
                    or any(ak in anchor_txt for ak in CONTACT_ANCHOR_TEXT_KEYWORDS)
                ):
                    if full_url not in contact_links and full_url != page_url:
                        contact_links.append(full_url)

    for script_or_style in soup(['script', 'style', 'noscript', 'svg', 'path']):
        script_or_style.decompose()

    main_text = ' '.join(soup.get_text(' . ', strip=True).split())
    valid_phones = extract_valid_phones(main_text, raw_tel_candidates, default_region)
    phones_with_source = [(p, sc, page_url) for p, sc in valid_phones]

    socials_with_source: dict[str, tuple[str, str]] = {}
    for plat, cands in social_candidates.items():
        best_u, best_src = pick_best_social_candidate(cands, brand_root)
        if best_u and best_src:
            socials_with_source[plat] = (best_u, best_src)

    return (
        page_title,
        meta_desc,
        main_text,
        email_sources,
        phones_with_source,
        socials_with_source,
        contact_links[:10]
    )


def pw_locale_for_region(region: str | None) -> str:
    reg = (region or 'US').upper()
    return {
        'UA': 'uk-UA',
        'DE': 'de-DE',
        'AT': 'de-AT',
        'CH': 'de-CH',
        'FR': 'fr-FR',
        'ES': 'es-ES',
        'IT': 'it-IT',
        'NL': 'nl-NL',
        'PL': 'pl-PL',
        'GB': 'en-GB',
        'UK': 'en-GB',
    }.get(reg, 'en-US')


async def _get_or_launch_browser():
    global _SHARED_PW, _SHARED_BROWSER, _NATIVE_CLEAN_UA
    async with _BROWSER_LOCK:
        if _SHARED_BROWSER is not None and _SHARED_BROWSER.is_connected():
            return _SHARED_BROWSER
        if _SHARED_PW is None:
            _SHARED_PW = await async_playwright().start()
        _SHARED_BROWSER = await _SHARED_PW.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
            ]
        )
        try:
            tmp_page = await _SHARED_BROWSER.new_page()
            raw_ua = await tmp_page.evaluate('() => navigator.userAgent')
            await tmp_page.close()
            if raw_ua and isinstance(raw_ua, str):
                _NATIVE_CLEAN_UA = raw_ua.replace('HeadlessChrome/', 'Chrome/')
        except Exception:
            _NATIVE_CLEAN_UA = None
        return _SHARED_BROWSER


async def _try_accept_cookie_banner(page) -> bool:
    for sel in CMP_ACCEPT_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.is_visible(timeout=150):
                await loc.click(timeout=500)
                await page.wait_for_timeout(1200)
                return True
        except Exception:
            continue
    try:
        await page.wait_for_timeout(600)
    except Exception:
        pass
    return False


async def fetch_html_playwright_fallback(
    url: str,
    proxy_url: str | None = None,
    locale: str = 'en-US',
    accept_consent: bool = True,
    max_attempts: int = 2,
    start_residential: bool = False,
) -> tuple[str, str, str, bool, int]:
    """
    v23.1 Complete:
    При запуску з резидентським проксі (start_residential=True) обмежує кількість спроб до 1
    після отримання launched_empty_shell або жорсткого WAF-блокування.
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return '', url, 'disabled', False, 0

    attempts_made = 0
    last_status = 'launched_failed'
    effective_max_attempts = 1 if start_residential else max_attempts

    async with _PW_SEMAPHORE:
        for attempt_idx in range(1, effective_max_attempts + 1):
            attempts_made += 1
            use_res = start_residential or (attempt_idx > 1 and _ESCALATION_PROXY_CFG is not None)
            active_proxy = proxy_url
            if use_res and _ESCALATION_PROXY_CFG is not None:
                try:
                    active_proxy = await _ESCALATION_PROXY_CFG.new_url()
                except Exception:
                    active_proxy = proxy_url

            context = None
            try:
                browser = await _get_or_launch_browser()
                ctx_kwargs: dict = {
                    'locale': locale,
                    'viewport': {'width': 1366, 'height': 768},
                }
                if _NATIVE_CLEAN_UA:
                    ctx_kwargs['user_agent'] = _NATIVE_CLEAN_UA
                if active_proxy:
                    parsed_p = urlparse(active_proxy)
                    ctx_kwargs['proxy'] = {
                        'server': f'{parsed_p.scheme}://{parsed_p.hostname}:{parsed_p.port}',
                        'username': parsed_p.username or '',
                        'password': parsed_p.password or '',
                    }

                context = await browser.new_context(**ctx_kwargs)
                page = await context.new_page()

                captured_tracker_urls: list[str] = []

                def _on_request(req):
                    try:
                        r_url = req.url
                        r_low = r_url.lower()
                        is_first_party_sgtm_or_ga4 = (
                            '/g/collect' in r_low
                            or '/gtm.js?id=gtm-' in r_low
                        )
                        is_known_vendor_tracker = any(
                            tk in r_low for tk in (
                                'googletagmanager.com', 'google-analytics.com', 'analytics.google.com',
                                'doubleclick.net', 'googleadservices.com', 'connect.facebook.net',
                                'facebook.com/tr', 'analytics.tiktok.com', 'snap.licdn.com',
                                'clarity.ms', 'hotjar.com', 'hs-scripts.com', 'klaviyo.com', 'cdn.shopify.com'
                            )
                        )
                        if is_first_party_sgtm_or_ga4 or is_known_vendor_tracker:
                            if len(captured_tracker_urls) < 60:
                                captured_tracker_urls.append(r_url[:360])
                    except Exception:
                        pass

                page.on('request', _on_request)

                await page.route(
                    re.compile(r'\.(?:png|jpe?g|gif|webp|avif|mp4|webm|woff2?|ttf|otf)(?:\?|$)', re.I),
                    lambda route: asyncio.create_task(route.abort())
                )

                nav_incomplete = False
                try:
                    resp = await page.goto(url, wait_until='domcontentloaded', timeout=18000)
                    if resp and resp.status in (403, 429, 503):
                        last_status = f'launched_blocked_{resp.status}'
                        if attempt_idx < effective_max_attempts:
                            continue
                except Exception as nav_err:
                    nav_incomplete = True
                    if 'timeout' in str(nav_err).lower():
                        last_status = 'launched_timeout'
                    else:
                        last_status = 'launched_error'

                if accept_consent:
                    await _try_accept_cookie_banner(page)
                else:
                    try:
                        await page.wait_for_timeout(600)
                    except Exception:
                        pass

                content = await page.content()
                final_u = page.url or url

                if captured_tracker_urls:
                    net_comments = '\n'.join(f'<!-- pw_net_req: {u} -->' for u in captured_tracker_urls)
                    content = f'{content}\n{net_comments}'

                if content and len(content) >= 2500:
                    low_c = content[:4000].lower()
                    if any(w in low_c for w in ('just a moment...', 'attention required! | cloudflare', 'cf-browser-verification')):
                        last_status = 'launched_blocked_cloudflare'
                        if attempt_idx < effective_max_attempts:
                            continue
                    return content[:MAX_HTML_BYTES], final_u, 'rendered', nav_incomplete, attempts_made

                last_status = 'launched_empty_shell'
                if start_residential:
                    break
            except Exception as e:
                last_status = 'launched_timeout' if 'timeout' in str(e).lower() else 'launched_error'
            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass

    return '', url, last_status, True, attempts_made
