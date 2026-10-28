import asyncio
import ipaddress
import re
from urllib.parse import urljoin, urlparse
from apify import Actor
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

from .config import (
    CHECKOUT_REDIRECT_HOSTS,
    CONTACT_ANCHOR_TEXT_KEYWORDS,
    EMAIL_REGEX,
    GTM_ID_REGEX,
    KNOWN_DOMAIN_REDIRECT_ALIASES,
    MAX_HTML_BYTES,
    PRIMARY_CONTACT_KEYWORDS,
    SCHEMA_PHONE_REGEX,
    SECONDARY_CONTACT_KEYWORDS,
    SOFT_404_TITLE_REGEX,
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
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

_SHARED_PW = None
_SHARED_BROWSER = None
_BROWSER_LOCK = asyncio.Lock()
_PW_SEMAPHORE = asyncio.Semaphore(3)
_ESCALATION_PROXY_CFG = None


def is_playwright_available() -> bool:
    return _PLAYWRIGHT_AVAILABLE


def configure_pw(escalation_proxy=None, max_concurrent: int = 3) -> None:
    global _ESCALATION_PROXY_CFG, _PW_SEMAPHORE
    _ESCALATION_PROXY_CFG = escalation_proxy
    _PW_SEMAPHORE = asyncio.Semaphore(max(1, int(max_concurrent or 3)))


async def close_shared_playwright_browser() -> None:
    global _SHARED_PW, _SHARED_BROWSER
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


def _is_safe_domain(netloc: str) -> bool:
    """
    P1-C Fix (v20.15 SSRF Protection):
    Відхиляє IP-літерали (127.0.0.1, 10.x.x.x, 192.168.x.x, 169.254.169.254, IPv6),
    внутрішні TLD (.local, .internal, .lan, .localhost, .arpa) та невалідні символи хоста.
    """
    if not netloc:
        return False
    host = netloc.split(':')[0].strip().lower().strip('[]')
    if not host or '.' not in host or ' ' in host:
        return False
    if host in ('localhost', 'broadcasthost') or host.endswith(
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
        if host.startswith('www.'):
            host = host[4:]

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
    try:
        parsed = urlparse(final_url)
        host = re.sub(r':\d+$', '', parsed.netloc.lower())
        if host.startswith('www.'):
            host = host[4:]
        if not host or CHECKOUT_REDIRECT_HOSTS.match(host):
            return KNOWN_DOMAIN_REDIRECT_ALIASES.get(fallback_domain, fallback_domain)
        return KNOWN_DOMAIN_REDIRECT_ALIASES.get(host, host)
    except Exception:
        return KNOWN_DOMAIN_REDIRECT_ALIASES.get(fallback_domain, fallback_domain)


def classify_failure_status(status: int, err_msg: str) -> str:
    err_low = (err_msg or '').lower()
    if status in (401, 403, 429, 503) or 'cloudflare' in err_low or 'captcha' in err_low:
        return 'blocked'
    if 'timeout' in err_low or 'timed out' in err_low:
        return 'timeout'
    if 'ssl' in err_low or 'certificate' in err_low:
        return 'ssl_error'
    if 'resolve' in err_low or 'name or service not known' in err_low or 'dns' in err_low:
        return 'dns_error'
    if status >= 500:
        return f'http_{status}'
    return 'unreachable'


def is_soft_404_page(html: str, page_title: str) -> bool:
    if not html:
        return True
    if page_title and SOFT_404_TITLE_REGEX.search(page_title):
        return True
    if len(html) < 1800 and ('404' in html[:800] or 'not found' in html[:800].lower()):
        return True
    return False


async def fetch_html_safely(
    client: AsyncSession,
    url: str,
    proxy_config=None,
    timeout: float = 12.0,
    retries: int = 2
) -> tuple[int, str, str, str]:
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
                return last_status, text, final_url, ''
            last_err = f'HTTP {last_status}'
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
        try:
            resp = await client.get(gtm_url, timeout=6.0)
            if resp.status_code == 200 and resp.text:
                return resp.text[:450_000]
        except Exception:
            pass
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
        host = parsed.netloc.lower().replace('www.', '')
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
    soup = BeautifulSoup(html, 'lxml')

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
    for m in EMAIL_REGEX.findall(html):
        email_sources.setdefault(m, page_url)

    for cf_el in soup.find_all(attrs={'data-cfemail': True}):
        decoded = decode_cf_email(str(cf_el.get('data-cfemail', '')))
        if decoded and '@' in decoded:
            email_sources.setdefault(decoded, page_url)

    raw_tel_candidates: list[tuple[str, str]] = []
    for sm in SCHEMA_PHONE_REGEX.findall(html):
        raw_tel_candidates.append((sm, 'schema_telephone'))

    parsed_base = urlparse(page_url)
    base_host = re.sub(r':\d+$', '', parsed_base.netloc.lower()).replace('www.', '')
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
            if addr and '@' in addr:
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
            clean_u_host = re.sub(r':\d+$', '', u_host).replace('www.', '')
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

    main_text = ' '.join(soup.get_text(' ', strip=True).split())
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
    global _SHARED_PW, _SHARED_BROWSER
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
        return _SHARED_BROWSER


async def fetch_html_playwright_fallback(
    url: str,
    proxy_url: str | None = None,
    locale: str = 'en-US',
    accept_consent: bool = True,
    max_attempts: int = 2,
    start_residential: bool = False,
) -> tuple[str, str, str, bool, int]:
    if not _PLAYWRIGHT_AVAILABLE:
        return '', url, 'disabled', False, 0

    attempts_made = 0
    last_status = 'launched_failed'

    async with _PW_SEMAPHORE:
        for attempt_idx in range(1, max_attempts + 1):
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
                    'user_agent': (
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/131.0.0.0 Safari/537.36'
                    ),
                    'viewport': {'width': 1366, 'height': 768},
                }
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
                        if any(
                            tk in r_url.lower() for tk in (
                                'googletagmanager.com', 'google-analytics.com', 'analytics.google.com',
                                'doubleclick.net', 'googleadservices.com', 'connect.facebook.net',
                                'facebook.com/tr', 'analytics.tiktok.com', 'snap.licdn.com',
                                'clarity.ms', 'hotjar.com', 'hs-scripts.com', 'klaviyo.com', 'cdn.shopify.com'
                            )
                        ):
                            if len(captured_tracker_urls) < 40:
                                captured_tracker_urls.append(r_url[:240])
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
                        if attempt_idx < max_attempts:
                            continue
                except Exception as nav_err:
                    nav_incomplete = True
                    if 'timeout' in str(nav_err).lower():
                        last_status = 'launched_timeout'
                    else:
                        last_status = 'launched_error'

                if accept_consent:
                    try:
                        await page.wait_for_timeout(1200)
                    except Exception:
                        pass
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
                        if attempt_idx < max_attempts:
                            continue
                    return content[:MAX_HTML_BYTES], final_u, 'rendered', nav_incomplete, attempts_made

                last_status = 'launched_empty_shell'
            except Exception as e:
                last_status = 'launched_timeout' if 'timeout' in str(e).lower() else 'launched_error'
            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass

    return '', url, last_status, True, attempts_made
