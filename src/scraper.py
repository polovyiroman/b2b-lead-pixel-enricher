import asyncio
import ipaddress
import json
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

try:
    from cryptography import x509 as crypto_x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    crypto_x509 = None
    ExtensionOID = None
    NameOID = None
    _CRYPTOGRAPHY_AVAILABLE = False

try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    async_playwright = None
    _PLAYWRIGHT_AVAILABLE = False

from .config import (
    CHECKOUT_REDIRECT_HOSTS,
    CMP_ACCEPT_SELECTORS,
    CONTACT_ANCHOR_TEXT_KEYWORDS,
    EMAIL_REGEX,
    GTM_ID_REGEX,
    INFRA_SAN_DENYLIST,
    KNOWN_DOMAIN_REDIRECT_ALIASES,
    MAX_HTML_BYTES,
    MULTI_PART_TLDS,
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
    clean_escaped_email_prefix,
    decode_cf_email,
    extract_valid_phones,
    pick_best_social_candidate,
)

_PW_LOCK = asyncio.Lock()
_PW_RUNTIME: Any = None
_PW_BROWSER: Any = None
_PW_SEMAPHORE = asyncio.Semaphore(2)
_ESCALATION_PROXY_CFG: Any = None

CF_HREF_RE = re.compile(r'/cdn-cgi/l/email-protection#([a-fA-F0-9]{4,})', re.IGNORECASE)
CF_DATA_RE = re.compile(r'data-cfemail=["\']([a-fA-F0-9]{4,})["\']', re.IGNORECASE)

HONEYPOT_STYLE_RE = re.compile(
    r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b|'
    r'font-size\s*:\s*0(?:px|pt|em|rem|%)?\b|height\s*:\s*0(?:px)?\s*;?\s*width\s*:\s*0(?:px)?|'
    r'left\s*:\s*-\d{4,}px|top\s*:\s*-\d{4,}px)',
    re.IGNORECASE,
)

WAF_CHALLENGE_TITLE_MARKERS = (
    'just a moment',
    'attention required',
    'checking your browser',
    'verify you are human',
    'access denied',
    'please wait while your request is being verified',
    'трохи зачекайте',
    'подождите немного',
    'ddos-guard',
    'human verification',
    'pardon our interruption',
    'bot protection',
    'are you a robot',
    'security check',
    'enable javascript and cookies to continue',
)

WAF_CHALLENGE_HTML_MARKERS = (
    'cf-browser-verification',
    'cdn-cgi/challenge-platform',
    '_cf_chl_opt',
    'geo.captcha-delivery.com',
    'datadome.co',
    'px-captcha',
    'perimeterx',
    'akamai-bm-telemetry',
    'incapsula_resource',
    '_incapsula_resource',
)

SOCIAL_HOST_MAP: Dict[str, Tuple[str, ...]] = {
    'linkedin': ('linkedin.com',),
    'instagram': ('instagram.com',),
    'facebook': ('facebook.com', 'fb.com'),
    'telegram': ('t.me', 'telegram.me'),
    'tiktok': ('tiktok.com',),
    'youtube': ('youtube.com', 'youtu.be'),
}

SAFE_HEADER_KEYS = (
    'content-security-policy',
    'content-security-policy-report-only',
    'x-shopid',
    'x-shopify-stage',
    'x-magento-tags',
    'sw-context-token',
    'x-akamai-transformed',
    'cf-polished',
    'cf-ew-via',
    'server',
    'x-powered-by',
)

PW_TRACKED_NET_KEYWORDS = (
    'googletagmanager.com',
    'google-analytics.com',
    'analytics.google.com',
    '/g/collect',
    '/collect?',
    '/gtm.js',
    '/gtag/js',
    'googleadservices.com',
    'doubleclick.net/pagead',
    'connect.facebook.net',
    'facebook.com/tr',
    'analytics.tiktok.com',
    'snap.licdn.com',
    'px.ads.linkedin.com',
    's.pinimg.com/ct/',
    'ct.pinterest.com',
    'clarity.ms/',
    'hotjar.com',
    'hs-scripts.com',
    'hs-analytics.net',
    'klaviyo.com',
    'cdn.shopify.com',
    'stape.io',
    'stape.net',
)

PW_FIRST_PARTY_SGTM_SUBS: Set[str] = {
    'sgtm', 'gtm', 'sst', 'metrics', 'analytics', 'tag', 'tags',
    'track', 'tracking', 'collect', 'data', 'stats', 'measure',
    'measurement', 'events', 'server-side', 'ss', 'stape', 'telemetry',
}

REGION_TO_PW_LOCALE: Dict[str, str] = {
    'UA': 'uk-UA',
    'DE': 'de-DE',
    'AT': 'de-AT',
    'CH': 'de-CH',
    'PL': 'pl-PL',
    'FR': 'fr-FR',
    'ES': 'es-ES',
    'IT': 'it-IT',
    'NL': 'nl-NL',
    'BE': 'nl-BE',
    'GB': 'en-GB',
    'UK': 'en-GB',
    'CZ': 'cs-CZ',
    'SE': 'sv-SE',
    'NO': 'nb-NO',
    'DK': 'da-DK',
    'FI': 'fi-FI',
    'PT': 'pt-PT',
    'US': 'en-US',
}

SITEMAP_LOC_RE = re.compile(r'<loc>\s*(https?://[^<\s]+)\s*</loc>', re.IGNORECASE)
JSONLD_PRICE_RE = re.compile(r'"price"\s*:\s*"?(\d+(?:\.\d{1,2})?)"?', re.IGNORECASE)
JSONLD_CURRENCY_RE = re.compile(r'"priceCurrency"\s*:\s*"([A-Z]{3})"', re.IGNORECASE)


def _extract_etld_local(host_or_url: str) -> tuple[str, str]:
    if not host_or_url:
        return '', ''
    raw = host_or_url.strip().lower()
    hostname = (urlparse(raw).hostname or '') if '://' in raw else raw.split('/')[0].split(':')[0]
    hostname = hostname.strip('.')
    while hostname.startswith('*.'):
        hostname = hostname[2:].strip()
    parts = [p for p in hostname.split('.') if p]
    if len(parts) < 2:
        return hostname, hostname
    last_two = f'{parts[-2]}.{parts[-1]}'
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return f'{parts[-3]}.{last_two}', parts[-3]
    return last_two, parts[-2]


def _is_safe_domain(host_or_netloc: str) -> bool:
    if not host_or_netloc:
        return False
    host = host_or_netloc.strip().lower().split(':')[0].rstrip('.')
    if not host or '.' not in host:
        return False
    if host in ('localhost', '0.0.0.0', 'broadcasthost') or host.endswith(
        ('.local', '.internal', '.arpa', '.lan', '.localhost', '.home', '.corp', '.intranet')
    ):
        return False
    try:
        ip_obj = ipaddress.ip_address(host)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return True


def prepare_domains(raw_domains: list[str] | Any) -> list[tuple[str, str, list[str]]]:
    if not isinstance(raw_domains, list):
        return []
    grouped: Dict[str, List[str]] = {}
    order: List[str] = []

    for item in raw_domains:
        if not isinstance(item, str):
            continue
        raw = item.strip()
        if not raw:
            continue
        if '://' not in raw:
            raw_url = f'https://{raw}'
        else:
            raw_url = raw
        parsed = urlparse(raw_url)
        host = (parsed.hostname or '').lower().strip().rstrip('.')
        if host.startswith('www.'):
            host = host[4:]
        if not host or '.' not in host or not _is_safe_domain(host):
            continue

        canonical = KNOWN_DOMAIN_REDIRECT_ALIASES.get(host, host)
        if canonical not in grouped:
            grouped[canonical] = []
            order.append(canonical)
        if host not in grouped[canonical]:
            grouped[canonical].append(host)
        if canonical not in grouped[canonical]:
            grouped[canonical].append(canonical)

    out: list[tuple[str, str, list[str]]] = []
    for canonical in order:
        out.append((canonical, f'https://{canonical}/', grouped[canonical]))
    return out


def is_checkout_redirect_url(url: str | None) -> bool:
    if not url:
        return False
    host = (urlparse(url).hostname or '').lower().strip()
    if not host:
        return False
    if CHECKOUT_REDIRECT_HOSTS.match(host):
        return True
    if host.endswith('.myshopify.com') or host in ('checkout.shopify.com', 'pay.shopify.com'):
        return True
    return False


def get_clean_canonical_domain(final_url: str | None, fallback_domain: str) -> str:
    fb = (fallback_domain or '').lower().strip().removeprefix('www.').rstrip('.')
    if not final_url or is_checkout_redirect_url(final_url):
        return fb
    host = (urlparse(final_url).hostname or '').lower().strip().removeprefix('www.').rstrip('.')
    if not host or '.' not in host or not _is_safe_domain(host):
        return fb
    if host.endswith(('cloudflare.com', 'cloudfront.net', 'amazonaws.com', 'shopify.com')):
        return fb
    return KNOWN_DOMAIN_REDIRECT_ALIASES.get(host, host)


def is_soft_404_page(html: str, page_title: str = '') -> bool:
    if page_title and SOFT_404_TITLE_REGEX.match(page_title.strip()):
        return True
    if html and len(html) < 4000:
        low = html.lower()
        if any(m in low for m in ('<title>404', 'error 404', 'page not found', 'сторінку не знайдено')):
            return True
    return False


def is_waf_challenge_page(html: str, page_title: str = '') -> bool:
    title_low = (page_title or '').strip().lower()
    if title_low and any(m in title_low for m in WAF_CHALLENGE_TITLE_MARKERS):
        return True
    if not html:
        return False
    head_low = html[:25000].lower()
    m_title = re.search(r'<title[^>]*>(.*?)</title>', head_low, re.DOTALL)
    if m_title:
        inner_t = ' '.join(m_title.group(1).split())
        if any(m in inner_t for m in WAF_CHALLENGE_TITLE_MARKERS):
            return True
    if len(html) < 45000 and any(mk in head_low for mk in WAF_CHALLENGE_HTML_MARKERS):
        return True
    return False


def is_dynamic_hopeless_waf(err_msg: str | None) -> bool:
    low = (err_msg or '').lower()
    return any(tok in low for tok in ('datadome', 'perimeterx', 'akamai_bot_manager', 'waf_hard_block'))


def classify_failure_status(status: int, err_msg: str | None = '') -> str:
    if status in (401, 403, 406, 429, 451, 503):
        return 'blocked'
    if 400 <= status < 600:
        return f'http_{status}'
    low = (err_msg or '').lower()
    if any(k in low for k in ('could not resolve', 'nxdomain', 'name or service not known', 'nodename nor servname', 'dns')):
        return 'dns_error'
    if any(k in low for k in ('ssl', 'certificate', 'tls', 'handshake')):
        return 'ssl_error'
    if any(k in low for k in ('timed out', 'timeout')):
        return 'timeout'
    return 'unreachable'


def deobfuscate_cfemails_in_html(html: str) -> str:
    if not html or ('email-protection' not in html and 'data-cfemail' not in html):
        return html or ''

    def _repl_href(m: re.Match) -> str:
        dec = decode_cf_email(m.group(1))
        return f'mailto:{dec}' if (dec and '@' in dec) else m.group(0)

    out = CF_HREF_RE.sub(_repl_href, html)

    def _repl_data(m: re.Match) -> str:
        dec = decode_cf_email(m.group(1))
        return f'data-cfemail="{m.group(1)}" data-decoded-email="{dec}"' if (dec and '@' in dec) else m.group(0)

    return CF_DATA_RE.sub(_repl_data, out)


def prune_honeypot_leaf_nodes_in_soup(soup: BeautifulSoup) -> Set[str]:
    poisoned: Set[str] = set()
    if soup is None:
        return poisoned

    to_remove = []
    for el in soup.find_all(['a', 'span', 'div', 'p', 'li', 'input']):
        style_val = str(el.get('style') or '')
        cls_val = ' '.join(el.get('class') or []).lower() if isinstance(el.get('class'), list) else str(el.get('class') or '').lower()
        is_hidden = (
            el.has_attr('hidden')
            or bool(HONEYPOT_STYLE_RE.search(style_val))
            or any(hc in cls_val.split() for hc in ('honeypot', 'hp-field', 'sr-only-trap', 'd-none-trap'))
        )
        if not is_hidden:
            continue
        if el.find_all(['section', 'article', 'main', 'footer', 'header', 'nav']):
            continue

        txt = el.get_text(' ', strip=True)
        href = str(el.get('href') or '')
        for raw_em in EMAIL_REGEX.findall(f'{txt} {href}'):
            clean_em = clean_escaped_email_prefix(raw_em)
            if clean_em:
                poisoned.add(clean_em)
        to_remove.append(el)

    for el in to_remove:
        try:
            el.decompose()
        except Exception:
            pass

    return poisoned


def append_safe_headers_comment_v23_1(html: str, headers: Any) -> str:
    if headers is None:
        return html or ''
    extracted: Dict[str, Any] = {}
    cookie_names: Set[str] = set()

    try:
        items_iter = headers.multi_items() if hasattr(headers, 'multi_items') else headers.items()
    except Exception:
        items_iter = []

    for k, v in items_iter:
        k_low = str(k).lower().strip()
        v_str = str(v).strip()
        if k_low == 'set-cookie':
            c_name = v_str.split('=', 1)[0].strip()
            if c_name and len(c_name) <= 48:
                cookie_names.add(c_name)
        elif k_low in SAFE_HEADER_KEYS:
            if k_low in extracted:
                extracted[k_low] = f"{extracted[k_low]} ; {v_str[:1500]}"
            else:
                extracted[k_low] = v_str[:3000]

    if cookie_names:
        extracted['cookie_names'] = sorted(cookie_names)[:30]

    if not extracted:
        return html or ''

    try:
        hdr_json = json.dumps(extracted, ensure_ascii=False)
        return f"{html or ''}\n<!-- http_headers_json: {hdr_json} -->"
    except Exception:
        return html or ''


async def fetch_html_safely(
    client: AsyncSession,
    url: str,
    proxy_config: Any = None,
    timeout: float = 12.0,
    retries: int = 2,
) -> tuple[int, str, str, str]:
    last_status = 0
    last_html = ''
    last_final_url = url
    last_err = ''

    req_headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,de;q=0.8,uk;q=0.7',
        'Upgrade-Insecure-Requests': '1',
    }

    for attempt in range(max(1, retries + 1)):
        proxy_url = None
        if proxy_config is not None and attempt > 0:
            try:
                proxy_url = await proxy_config.new_url()
            except Exception:
                proxy_url = None

        req_kwargs: Dict[str, Any] = {
            'headers': req_headers,
            'timeout': timeout,
            'allow_redirects': True,
        }
        if proxy_url:
            req_kwargs['proxies'] = {'http': proxy_url, 'https': proxy_url}

        try:
            resp = await client.get(url, **req_kwargs)
            st = int(getattr(resp, 'status_code', 0) or 0)
            fin_u = str(getattr(resp, 'url', '') or url)
            raw_text = str(getattr(resp, 'text', '') or '')
            if len(raw_text) > MAX_HTML_BYTES:
                raw_text = raw_text[:MAX_HTML_BYTES]

            hdrs = getattr(resp, 'headers', None)
            if 200 <= st < 400:
                if is_waf_challenge_page(raw_text):
                    last_status = 403
                    last_html = append_safe_headers_comment_v23_1(raw_text, hdrs)
                    last_final_url = fin_u
                    last_err = 'waf_challenge_page'
                    continue
                body = deobfuscate_cfemails_in_html(raw_text)
                body = append_safe_headers_comment_v23_1(body, hdrs)
                return st, body, fin_u, ''

            last_status = st
            last_html = append_safe_headers_comment_v23_1(raw_text, hdrs)
            last_final_url = fin_u
            last_err = f'HTTP {st}'
            if st in (404, 410):
                break
        except Exception as exc:
            last_status = 0
            last_err = str(exc) or 'request_exception'
            low_err = last_err.lower()
            if any(k in low_err for k in ('could not resolve', 'nxdomain', 'name or service not known')):
                break

        if attempt < retries:
            await asyncio.sleep(0.35 * (attempt + 1))

    return last_status, last_html, last_final_url, last_err


def extract_semantic_contact_links_from_html(html: str, base_url: str) -> list[str]:
    if not html or not base_url:
        return []
    soup = BeautifulSoup(html, 'lxml')
    base_host = (urlparse(base_url).hostname or '').lower().removeprefix('www.')
    links: List[str] = []
    seen: Set[str] = set()

    extra_leadership_keywords = (
        'team', 'leadership', 'management', 'founders', 'career', 'careers', 'jobs', 'karriere', 'vorstand'
    )
    all_path_keywords = PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS + extra_leadership_keywords

    for a in soup.find_all('a', href=True):
        href = str(a.get('href') or '').strip()
        if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
            continue
        abs_url = urljoin(base_url, href).split('#')[0]
        parsed = urlparse(abs_url)
        if parsed.scheme not in ('http', 'https'):
            continue
        link_host = (parsed.hostname or '').lower().removeprefix('www.')
        if link_host != base_host:
            continue
        path_low = parsed.path.lower()
        if any(path_low.endswith(ext) for ext in ('.pdf', '.jpg', '.png', '.svg', '.zip', '.xml')):
            continue
        anchor_low = a.get_text(' ', strip=True).lower()
        if any(k in path_low for k in all_path_keywords) or any(k in anchor_low for k in CONTACT_ANCHOR_TEXT_KEYWORDS):
            norm_u = clean_url_port(abs_url) or abs_url
            if norm_u not in seen:
                seen.add(norm_u)
                links.append(norm_u)
    return links[:15]


def parse_html_sync(
    html: str,
    page_url: str,
    default_region: str = 'US',
) -> tuple[str, str, str, dict[str, str], list[tuple[str, int, str]], dict[str, tuple[str, str]], list[str]]:
    if not html:
        return '', '', '', {}, [], {}, []

    clean_html = deobfuscate_cfemails_in_html(html)
    soup = BeautifulSoup(clean_html, 'lxml')
    poisoned_emails = prune_honeypot_leaf_nodes_in_soup(soup)

    page_title = ''
    if soup.title and soup.title.string:
        page_title = ' '.join(soup.title.string.split())[:220]

    meta_desc = ''
    meta_tag = soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)}) or soup.find(
        'meta', attrs={'property': re.compile(r'^og:description$', re.I)}
    )
    if meta_tag and meta_tag.get('content'):
        meta_desc = ' '.join(str(meta_tag['content']).split())[:350]

    email_sources: Dict[str, str] = {}
    raw_tel_links: List[Tuple[str, str]] = []
    social_candidates: Dict[str, List[Tuple[str, str]]] = {k: [] for k in SOCIAL_HOST_MAP}

    base_host = (urlparse(page_url).hostname or '').lower().removeprefix('www.')
    brand_root = base_host.split('.')[0] if base_host else ''

    extra_leadership_keywords = (
        'team', 'leadership', 'management', 'founders', 'career', 'careers', 'jobs', 'karriere', 'vorstand'
    )
    all_path_keywords = PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS + extra_leadership_keywords
    contact_links: List[str] = []
    seen_links: Set[str] = set()

    for a in soup.find_all('a', href=True):
        href = str(a.get('href') or '').strip()
        if not href:
            continue
        href_low = href.lower()
        anchor_text = a.get_text(' ', strip=True)

        if href_low.startswith('mailto:'):
            raw_m = href[7:].split('?')[0].strip()
            clean_m = clean_escaped_email_prefix(raw_m)
            if clean_m and '@' in clean_m and clean_m not in poisoned_emails:
                email_sources.setdefault(clean_m, page_url)
            continue

        if href_low.startswith('tel:'):
            raw_t = href[4:].split('?')[0].strip()
            if raw_t:
                parent_txt = a.parent.get_text(' ', strip=True)[:120] if a.parent else anchor_text
                raw_tel_links.append((raw_t, f'{anchor_text} {parent_txt}'))
            continue

        if href_low.startswith(('#', 'javascript:')):
            continue

        abs_url = urljoin(page_url, href).split('#')[0]
        parsed = urlparse(abs_url)
        if parsed.scheme not in ('http', 'https'):
            continue
        link_host = (parsed.hostname or '').lower().removeprefix('www.')

        matched_social = False
        for plat, hosts in SOCIAL_HOST_MAP.items():
            if any(link_host == h or link_host.endswith(f'.{h}') for h in hosts):
                clean_soc = clean_and_validate_social_url(plat, abs_url)
                if clean_soc:
                    social_candidates[plat].append((clean_soc, page_url))
                matched_social = True
                break
        if matched_social:
            continue

        if link_host == base_host:
            path_low = parsed.path.lower()
            if not any(path_low.endswith(ext) for ext in ('.pdf', '.jpg', '.png', '.svg', '.zip', '.xml')):
                if any(k in path_low for k in all_path_keywords) or any(
                    k in anchor_text.lower() for k in CONTACT_ANCHOR_TEXT_KEYWORDS
                ):
                    norm_u = clean_url_port(abs_url) or abs_url
                    if norm_u not in seen_links:
                        seen_links.add(norm_u)
                        contact_links.append(norm_u)

    for el_cf in soup.find_all(attrs={'data-decoded-email': True}):
        dec_em = clean_escaped_email_prefix(str(el_cf.get('data-decoded-email') or ''))
        if dec_em and '@' in dec_em and dec_em not in poisoned_emails:
            email_sources.setdefault(dec_em, page_url)

    for s_tag in soup(['script', 'style', 'noscript', 'svg']):
        if s_tag.name == 'script' and 'ld+json' in str(s_tag.get('type') or '').lower():
            ld_str = s_tag.string or ''
            for ph_m in SCHEMA_PHONE_REGEX.findall(ld_str):
                raw_tel_links.append((ph_m, 'schema.org corporate telephone'))
            for em_m in EMAIL_REGEX.findall(ld_str):
                c_em = clean_escaped_email_prefix(em_m)
                if c_em and c_em not in poisoned_emails:
                    email_sources.setdefault(c_em, page_url)
        s_tag.decompose()

    main_text = ' '.join(soup.get_text(' ', strip=True).split())

    for em_m in EMAIL_REGEX.findall(main_text):
        c_em = clean_escaped_email_prefix(em_m)
        if c_em and c_em not in poisoned_emails:
            email_sources.setdefault(c_em, page_url)

    valid_phones = extract_valid_phones(main_text, raw_tel_links, default_region)
    phones_with_source = [(p, sc, page_url) for p, sc in valid_phones]

    socials_with_source: Dict[str, Tuple[str, str]] = {}
    for plat, cands in social_candidates.items():
        best_u, best_s = pick_best_social_candidate(cands, brand_root)
        if best_u and best_s:
            socials_with_source[plat] = (best_u, best_s)

    return (
        page_title,
        meta_desc,
        main_text,
        email_sources,
        phones_with_source,
        socials_with_source,
        contact_links[:15],
    )


async def fetch_gtm_scripts(client: AsyncSession, html: str) -> tuple[list[str], str]:
    if not html:
        return [], ''
    gtm_ids = sorted({m.upper() for m in GTM_ID_REGEX.findall(html) if is_valid_gtm_id(m)})
    if not gtm_ids:
        return [], ''

    chunks: List[str] = []

    async def _fetch_one(gid: str) -> str:
        try:
            resp = await client.get(f'https://www.googletagmanager.com/gtm.js?id={gid}', timeout=4.5)
            if resp.status_code == 200 and resp.text:
                return resp.text[:450_000]
        except Exception:
            pass
        return ''

    fetched = await asyncio.gather(*(_fetch_one(g) for g in gtm_ids[:3]), return_exceptions=True)
    for item in fetched:
        if isinstance(item, str) and item:
            chunks.append(item)

    return gtm_ids, '\n'.join(chunks)


async def load_robots_rules(client: AsyncSession, base_root: str) -> tuple[list[str], float]:
    disallowed: List[str] = []
    crawl_delay = 0.25
    try:
        resp = await client.get(f'{base_root.rstrip("/")}/robots.txt', timeout=3.0)
        if resp.status_code == 200 and resp.text:
            active_star = False
            for line in resp.text.splitlines()[:200]:
                clean_l = line.split('#', 1)[0].strip()
                if not clean_l or ':' not in clean_l:
                    continue
                k, v = [x.strip() for x in clean_l.split(':', 1)]
                k_low = k.lower()
                if k_low == 'user-agent':
                    active_star = (v == '*')
                elif active_star and k_low == 'disallow' and v:
                    disallowed.append(v)
                elif active_star and k_low == 'crawl-delay':
                    try:
                        crawl_delay = min(1.5, max(0.1, float(v)))
                    except Exception:
                        pass
    except Exception:
        pass
    return disallowed, crawl_delay


def is_allowed_by_robots(url: str, disallowed_paths: list[str]) -> bool:
    if not disallowed_paths:
        return True
    path = urlparse(url).path or '/'
    for rule in disallowed_paths:
        if rule == '/':
            return False
        if rule and path.startswith(rule):
            return False
    return True


async def discover_links_from_sitemap(client: AsyncSession, base_root: str) -> list[str]:
    found: List[str] = []
    keywords = PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS + ('team', 'leadership', 'careers')
    try:
        resp = await client.get(f'{base_root.rstrip("/")}/sitemap.xml', timeout=3.5)
        if resp.status_code == 200 and resp.text:
            for loc in SITEMAP_LOC_RE.findall(resp.text[:350_000]):
                p_low = urlparse(loc).path.lower()
                if any(k in p_low for k in keywords):
                    if loc not in found:
                        found.append(loc)
                    if len(found) >= 8:
                        break
    except Exception:
        pass
    return found


async def fetch_store_and_well_known_bundle(
    client: AsyncSession,
    canonical_domain: str,
    html: str = '',
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        'apple_pay_raw': None,
        'sitemap_estimated_skus': None,
        'ecom_avg_price': None,
        'ecom_currency': None,
    }
    base = f'https://{canonical_domain}'

    async def _get_apple_pay() -> Optional[str]:
        try:
            r = await client.get(f'{base}/.well-known/apple-developer-merchantid-domain-association', timeout=2.0)
            if r.status_code == 200 and r.text and len(r.text) >= 40:
                return r.text[:20_000]
        except Exception:
            pass
        return None

    async def _get_shopify_products() -> tuple[Optional[float], Optional[str]]:
        if 'shopify' not in (html or '').lower():
            return None, None
        try:
            r = await client.get(f'{base}/products.json?limit=30', timeout=2.2)
            if r.status_code == 200:
                prods = (r.json() or {}).get('products') or []
                prices: List[float] = []
                for p in prods[:30]:
                    variants = p.get('variants') or []
                    if variants and isinstance(variants[0], dict):
                        try:
                            val = float(variants[0].get('price') or 0)
                            if val > 0:
                                prices.append(val)
                        except Exception:
                            pass
                if prices:
                    return round(sum(prices) / len(prices), 2), None
        except Exception:
            pass
        return None, None

    async def _estimate_sitemap_skus() -> Optional[int]:
        try:
            r = await client.get(f'{base}/sitemap.xml', timeout=2.2)
            if r.status_code == 200 and r.text:
                locs = SITEMAP_LOC_RE.findall(r.text[:350_000])
                if not locs:
                    return None
                product_sitemaps = [u for u in locs if 'product' in u.lower() and u.lower().endswith('.xml')]
                if product_sitemaps:
                    sub_r = await client.get(product_sitemaps[0], timeout=2.0)
                    if sub_r.status_code == 200 and sub_r.text:
                        sub_locs = SITEMAP_LOC_RE.findall(sub_r.text[:500_000])
                        if sub_locs:
                            return len(sub_locs) * max(1, len(product_sitemaps))
                product_urls = [
                    u for u in locs
                    if any(tok in u.lower() for tok in ('/product', '/p/', '/item/', '/dp/', '/shop/'))
                ]
                if product_urls:
                    return len(product_urls)
        except Exception:
            pass
        return None

    ap_raw, (avg_p, curr), sku_est = await asyncio.gather(
        _get_apple_pay(), _get_shopify_products(), _estimate_sitemap_skus(), return_exceptions=False
    )

    out['apple_pay_raw'] = ap_raw
    out['sitemap_estimated_skus'] = sku_est if (sku_est and sku_est > 0) else None

    if avg_p is None and html:
        raw_prices = [float(p) for p in JSONLD_PRICE_RE.findall(html[:120_000]) if 1.0 <= float(p) <= 50000.0]
        if raw_prices:
            avg_p = round(sum(raw_prices[:20]) / len(raw_prices[:20]), 2)
    if curr is None and html:
        m_cur = JSONLD_CURRENCY_RE.search(html[:120_000])
        if m_cur:
            curr = m_cur.group(1).upper()

    out['ecom_avg_price'] = avg_p
    out['ecom_currency'] = curr
    return out


def _inspect_tls_cert_sync(domain: str, timeout: float = 1.8) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        'tls_trust_status': 'unchecked',
        'organization_name': None,
        'corporate_sans': [],
        'prioritized_bypass_hosts': [],
    }
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_bytes = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert() or {}
    except Exception:
        out['tls_trust_status'] = 'tls_handshake_failed'
        return out

    issuer_str = str(cert_dict.get('issuer') or '').lower()
    if any(ca in issuer_str for ca in TRUSTED_CA_ISSUER_MARKERS):
        out['tls_trust_status'] = 'valid_trusted_ca'
    else:
        out['tls_trust_status'] = 'valid_tls'

    sans_raw: Set[str] = set()
    org_name: Optional[str] = None

    if _CRYPTOGRAPHY_AVAILABLE and der_bytes and crypto_x509 is not None:
        try:
            cert = crypto_x509.load_der_x509_certificate(der_bytes)
            org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if org_attrs:
                org_name = str(org_attrs[0].value).strip()
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for dns_name in san_ext.value.get_values_for_type(crypto_x509.DNSName):
                    sans_raw.add(dns_name.lower().lstrip('*.'))
            except Exception:
                pass
        except Exception:
            pass
    else:
        for typ, val in cert_dict.get('subjectAltName') or ():
            if typ == 'DNS':
                sans_raw.add(str(val).lower().lstrip('*.'))
        for rdn in cert_dict.get('subject') or ():
            for k, v in rdn:
                if k == 'organizationName':
                    org_name = str(v).strip()

    curr_reg, _ = _extract_etld_local(domain)
    corp_sans: Set[str] = set()
    bypass_hosts: List[str] = []

    for h in sans_raw:
        if any(h.endswith(bad) for bad in INFRA_SAN_DENYLIST):
            continue
        reg_h, _ = _extract_etld_local(h)
        if reg_h and reg_h != curr_reg:
            corp_sans.add(reg_h)
        elif h.endswith(curr_reg) and any(
            h.startswith(pref) for pref in ('blog.', 'about.', 'corporate.', 'careers.', 'jobs.', 'press.', 'ir.')
        ):
            bypass_hosts.append(h)

    out['organization_name'] = org_name
    out['corporate_sans'] = sorted(corp_sans)[:12]
    out['prioritized_bypass_hosts'] = sorted(set(bypass_hosts))[:4]
    return out


async def extract_tls_x509_der_intel(domain: str, timeout: float = 1.8) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _inspect_tls_cert_sync, domain, timeout),
            timeout=timeout + 0.6,
        )
    except Exception:
        return {
            'tls_trust_status': 'tls_timeout',
            'organization_name': None,
            'corporate_sans': [],
            'prioritized_bypass_hosts': [],
        }


async def fetch_waf_bypass_or_wayback_legal(
    client: AsyncSession,
    canonical_domain: str,
    prioritized_bypass_hosts: list[str] | None = None,
) -> tuple[str, str]:
    for host in (prioritized_bypass_hosts or [])[:2]:
        try:
            st, body, _, _ = await fetch_html_safely(client, f'https://{host}/', timeout=3.0, retries=0)
            if 200 <= st < 400 and len(body) > 800 and not is_waf_challenge_page(body):
                return body, f'subdomain_bypass:{host}'
        except Exception:
            pass

    try:
        cdx_url = (
            f'https://web.archive.org/cdx/search/cdx?url={canonical_domain}/*'
            f'&output=json&fl=timestamp,original&filter=statuscode:200&limit=5&from=20250101'
        )
        r = await client.get(cdx_url, timeout=2.5)
        if r.status_code == 200:
            rows = r.json()
            if isinstance(rows, list) and len(rows) > 1:
                best_row = next(
                    (row for row in rows[1:] if any(k in str(row[1]).lower() for k in ('impressum', 'contact', 'about'))),
                    rows[1],
                )
                wb_url = f'https://web.archive.org/web/{best_row[0]}id_/{best_row[1]}'
                wb_resp = await client.get(wb_url, timeout=3.5)
                if wb_resp.status_code == 200 and len(wb_resp.text) > 800 and not is_waf_challenge_page(wb_resp.text):
                    return deobfuscate_cfemails_in_html(wb_resp.text[:MAX_HTML_BYTES]), 'wayback_snapshot'
    except Exception:
        pass

    return '', ''


# ==============================================================================
# Playwright Shared Browser Pool & v24.2 Resilient Proxy + sGTM Capture Engine
# ==============================================================================

def is_playwright_available() -> bool:
    return _PLAYWRIGHT_AVAILABLE


def configure_pw(escalation_proxy: Any = None, max_concurrent: int = 2) -> None:
    global _ESCALATION_PROXY_CFG, _PW_SEMAPHORE
    _ESCALATION_PROXY_CFG = escalation_proxy
    cap = max(1, min(8, int(max_concurrent or 2)))
    _PW_SEMAPHORE = asyncio.Semaphore(cap)


def pw_locale_for_region(region: str | None) -> str:
    return REGION_TO_PW_LOCALE.get((region or 'US').upper().strip(), 'en-US')


async def _ensure_shared_playwright_browser() -> Any:
    global _PW_RUNTIME, _PW_BROWSER
    async with _PW_LOCK:
        if _PW_BROWSER is not None:
            try:
                if _PW_BROWSER.is_connected():
                    return _PW_BROWSER
            except Exception:
                pass
        if not _PLAYWRIGHT_AVAILABLE or async_playwright is None:
            return None
        _PW_RUNTIME = await async_playwright().start()
        _PW_BROWSER = await _PW_RUNTIME.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                '--disable-gpu',
            ],
        )
        return _PW_BROWSER


async def close_shared_playwright_browser() -> None:
    global _PW_RUNTIME, _PW_BROWSER
    async with _PW_LOCK:
        if _PW_BROWSER is not None:
            try:
                await _PW_BROWSER.close()
            except Exception:
                pass
            _PW_BROWSER = None
        if _PW_RUNTIME is not None:
            try:
                await _PW_RUNTIME.stop()
            except Exception:
                pass
            _PW_RUNTIME = None


def _parse_playwright_proxy(proxy_url: str | None) -> Optional[Dict[str, str]]:
    if not proxy_url:
        return None
    try:
        p = urlparse(proxy_url)
        if not p.hostname or not p.port:
            return None
        cfg: Dict[str, str] = {'server': f'{p.scheme or "http"}://{p.hostname}:{p.port}'}
        if p.username:
            cfg['username'] = p.username
        if p.password:
            cfg['password'] = p.password
        return cfg
    except Exception:
        return None


def _build_pw_proxy_attempt_plan(
    start_residential: bool,
    res_proxy_url: Optional[str],
    std_proxy_url: Optional[str],
    max_attempts: int = 1,
) -> List[Tuple[str, Optional[str]]]:
    """
    Гарантує, що при `start_residential=True` Playwright НІКОЛИ не виходить мовчки
    з `playwright_attempts_count: 0`:
      1. Якщо RESIDENTIAL проксі не видався (`None`) — одразу робить спробу через стандартний пул проксі.
      2. Якщо спроба через RESIDENTIAL провалилась — автоматично виконує ще 1 резервну спробу
         через стандартний пул проксі (`std_proxy_url`).
    """
    plan: List[Tuple[str, Optional[str]]] = []
    if start_residential:
        if res_proxy_url:
            plan.append(('residential', res_proxy_url))
            if std_proxy_url and std_proxy_url != res_proxy_url:
                plan.append(('standard_pool_fallback', std_proxy_url))
            else:
                plan.append(('direct_fallback', None))
        else:
            plan.append(('standard_pool_fallback', std_proxy_url))
    else:
        plan.append(('standard_pool', std_proxy_url))
        if max_attempts >= 2 and res_proxy_url and res_proxy_url != std_proxy_url:
            plan.append(('residential_escalation', res_proxy_url))
    return plan


def _should_capture_pw_request(req_url: str, target_reg_dom: str) -> bool:
    r_low = (req_url or '').lower()
    if any(k in r_low for k in PW_TRACKED_NET_KEYWORDS):
        return True
    if target_reg_dom:
        req_host = (urlparse(req_url).hostname or '').lower().strip('.')
        if req_host.endswith(f'.{target_reg_dom}') and req_host != f'www.{target_reg_dom}':
            sub_label = req_host[:-(len(target_reg_dom) + 1)].split('.')[0]
            if sub_label in PW_FIRST_PARTY_SGTM_SUBS:
                return True
    return False


async def fetch_html_playwright_fallback(
    url: str,
    proxy_url: str | None = None,
    locale: str = 'en-US',
    max_attempts: int = 1,
    start_residential: bool = False,
) -> tuple[str, str, str, bool, int]:
    """
    Виконує рендеринг сторінки у Playwright із кліком по CMP-банеру згоди, перехопленням
    мережевих запитів трекінгу й першосторонніх sGTM-піддоменів (`pw_net_req`), а також
    резервним фолбеком проксі при `start_residential=True`.
    Повертає: (html, final_url, status_str, incomplete_flag, attempts_made).
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return '', url, 'disabled', True, 0

    target_reg_dom, _ = _extract_etld_local(url)

    res_proxy_url: Optional[str] = None
    if _ESCALATION_PROXY_CFG is not None and (start_residential or max_attempts >= 2):
        try:
            sess_id = f"res_{abs(hash(url)) % 100000}"
            res_proxy_url = await _ESCALATION_PROXY_CFG.new_url(session_id=sess_id)
        except Exception:
            res_proxy_url = None

    attempt_plan = _build_pw_proxy_attempt_plan(
        start_residential=start_residential,
        res_proxy_url=res_proxy_url,
        std_proxy_url=proxy_url,
        max_attempts=max_attempts,
    )

    attempts_made = 0
    last_status_str = 'launched_failed'
    last_html = ''
    last_final_url = url
    last_incomplete = True

    async with _PW_SEMAPHORE:
        browser = await _ensure_shared_playwright_browser()
        if browser is None:
            return '', url, 'browser_launch_failed', True, 0

        for tier_name, active_proxy_url in attempt_plan:
            attempts_made += 1
            context = None
            page = None
            captured_net_urls: List[str] = []
            resp_headers_obj: Any = None

            try:
                ctx_kwargs: Dict[str, Any] = {
                    'locale': locale,
                    'viewport': {'width': 1366, 'height': 768},
                    'ignore_https_errors': True,
                    'user_agent': (
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/129.0.0.0 Safari/537.36'
                    ),
                }
                pw_proxy = _parse_playwright_proxy(active_proxy_url)
                if pw_proxy:
                    ctx_kwargs['proxy'] = pw_proxy

                context = await browser.new_context(**ctx_kwargs)
                await context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
                page = await context.new_page()

                def _on_request(req: Any) -> None:
                    try:
                        r_url = str(req.url or '')
                        if len(captured_net_urls) < 70 and _should_capture_pw_request(r_url, target_reg_dom):
                            if r_url not in captured_net_urls:
                                captured_net_urls.append(r_url)
                    except Exception:
                        pass

                page.on('request', _on_request)

                async def _route_filter(route: Any) -> None:
                    try:
                        if route.request.resource_type in ('image', 'media', 'font'):
                            await route.abort()
                        else:
                            await route.continue_()
                    except Exception:
                        pass

                await page.route('**/*', _route_filter)

                nav_resp = await page.goto(url, wait_until='domcontentloaded', timeout=18_000)
                if nav_resp is not None:
                    resp_headers_obj = nav_resp.headers

                # Клік по банеру згоди на cookie для активації GA4/Consent Mode v2 та sGTM тегів
                for sel in CMP_ACCEPT_SELECTORS:
                    try:
                        loc = page.locator(sel).first
                        if await loc.is_visible(timeout=250):
                            await loc.click(timeout=800)
                            await page.wait_for_timeout(900)
                            break
                    except Exception:
                        continue

                try:
                    await page.wait_for_load_state('networkidle', timeout=4500)
                    incomplete_flag = False
                except Exception:
                    await page.wait_for_timeout(1200)
                    incomplete_flag = True

                raw_html = await page.content()
                fin_u = str(page.url or url)
                page_title = await page.title()

                if len(raw_html) > MAX_HTML_BYTES:
                    raw_html = raw_html[:MAX_HTML_BYTES]

                if is_waf_challenge_page(raw_html, page_title):
                    last_status_str = f'launched_blocked_waf ({tier_name})'
                    last_html = ''
                    last_final_url = fin_u
                    last_incomplete = True
                    continue

                if len(raw_html.strip()) < 1500:
                    last_status_str = 'launched_empty_shell'
                    last_html = raw_html
                    last_final_url = fin_u
                    last_incomplete = True
                    continue

                enriched_html = deobfuscate_cfemails_in_html(raw_html)
                if resp_headers_obj:
                    enriched_html = append_safe_headers_comment_v23_1(enriched_html, resp_headers_obj)
                if captured_net_urls:
                    net_comments = '\n'.join(f'<!-- pw_net_req: {u} -->' for u in captured_net_urls[:60])
                    enriched_html = f'{enriched_html}\n{net_comments}'

                return enriched_html, fin_u, 'rendered', incomplete_flag, attempts_made

            except Exception as exc:
                err_low = str(exc).lower()
                if 'timeout' in err_low:
                    last_status_str = f'launched_timeout ({tier_name})'
                elif any(k in err_low for k in ('err_proxy', 'err_tunnel', '407', 'connection refused')):
                    last_status_str = f'launched_proxy_rejected ({tier_name})'
                else:
                    last_status_str = f'launched_error ({tier_name})'
                last_incomplete = True
            finally:
                if page is not None:
                    try:
                        await page.close()
                    except Exception:
                        pass
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass

    return last_html, last_final_url, last_status_str, last_incomplete, attempts_made
