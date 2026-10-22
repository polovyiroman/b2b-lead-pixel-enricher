import asyncio
import html as html_lib
import re
import textwrap
from urllib.parse import urljoin, urlparse
from apify import Actor
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

from .config import (
    CHECKOUT_REDIRECT_HOSTS,
    CONTACT_ANCHOR_TEXT_KEYWORDS,
    DM_SOURCE_BLACKLIST,
    EMAIL_REGEX,
    GTM_ID_REGEX,
    JUNK_EXTENSIONS,
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
    PLAYWRIGHT_INSTALLED = True
except ImportError:
    PLAYWRIGHT_INSTALLED = False

PW_SEMAPHORE = asyncio.Semaphore(3)
_PW_INIT_LOCK = asyncio.Lock()
_PW_INSTANCE = None
_PW_BROWSER = None

STRIPPABLE_SUBDOMAIN_PREFIXES = {
    'en', 'de', 'fr', 'uk', 'ua', 'us', 'eu', 'it', 'es', 'nl', 'pl',
    'pt', 'se', 'sv', 'no', 'dk', 'da', 'fi', 'at', 'ch', 'be', 'cz',
    'ro', 'hu', 'sk', 'ie', 'global', 'int', 'intl', 'm', 'mobile',
    'web', 'app', 'checkout', 'cart', 'pay', 'secure', 'shop', 'store'
}

SECOND_LEVEL_PUBLIC_SUFFIXES = {
    'com', 'co', 'org', 'net', 'edu', 'gov', 'ac', 'mil', 'biz', 'info',
    'in', 'kiev', 'kyiv', 'lviv', 'odesa', 'kharkiv', 'dnipro', 'zp'
}


def is_playwright_available() -> bool:
    return PLAYWRIGHT_INSTALLED


def prepare_domains(raw_domains: list[str]) -> list[tuple[str, str, list[str]]]:
    grouped: dict[str, dict] = {}
    for item in raw_domains:
        if not item or not isinstance(item, str):
            continue
        clean = item.strip()
        if not clean:
            continue
        if not clean.startswith(('http://', 'https://')):
            clean = f'https://{clean}'
        parsed = urlparse(clean)
        netloc = parsed.netloc.lower().strip()
        if not netloc or '.' not in netloc:
            continue
        domain_key = netloc.replace('www.', '')
        target_canon = KNOWN_DOMAIN_REDIRECT_ALIASES.get(domain_key, domain_key)

        if target_canon not in grouped:
            grouped[target_canon] = {
                'first_input': domain_key,
                'root_url': f'{parsed.scheme}://{target_canon}',
                'aliases': [domain_key]
            }
        else:
            if domain_key not in grouped[target_canon]['aliases']:
                grouped[target_canon]['aliases'].append(domain_key)

    result = []
    for target_canon, info in grouped.items():
        aliases = info['aliases']
        if target_canon not in aliases:
            aliases.append(target_canon)
        result.append((info['first_input'], info['root_url'], aliases))
    return result


def get_clean_canonical_domain(final_url: str, input_domain: str) -> str:
    """
    Bug 13 Fix: Очищує мовні та технічні піддомени (напр. en.zalando.de -> zalando.de),
    зберігаючи при цьому складені національні зони (.com.ua, .co.uk, .lviv.ua).
    """
    parsed = urlparse(final_url)
    netloc = re.sub(r':\d+$', '', parsed.netloc.lower().replace('www.', ''))
    if not netloc:
        netloc = input_domain.lower().replace('www.', '')

    parts = netloc.split('.')
    has_compound_tld = (
        len(parts) >= 3
        and len(parts[-1]) == 2
        and parts[-2] in SECOND_LEVEL_PUBLIC_SUFFIXES
    )
    min_parts = 3 if has_compound_tld else 2

    while len(parts) > min_parts and parts[0].lower() in STRIPPABLE_SUBDOMAIN_PREFIXES:
        parts.pop(0)

    return '.'.join(parts)


def is_soft_404_page(html: str, page_title: str) -> bool:
    t_clean = page_title.strip()
    if t_clean and SOFT_404_TITLE_REGEX.search(t_clean):
        return True
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html[:4000], re.I | re.S)
    if title_match and SOFT_404_TITLE_REGEX.search(title_match.group(1).strip()):
        return True
    return False


def extract_semantic_contact_links_from_html(html: str, page_url: str, canonical_domain: str) -> list[str]:
    found = []
    soup = BeautifulSoup(html, 'lxml')
    base_clean = (clean_url_port(page_url) or page_url).rstrip('/')

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            continue
        full_u = clean_url_port(urljoin(page_url, href))
        if not full_u or full_u.rstrip('/') == base_clean:
            continue

        parsed = urlparse(full_u)
        if parsed.scheme not in ('http', 'https'):
            continue
        host = re.sub(r':\d+$', '', parsed.netloc.lower().replace('www.', ''))
        path_low = parsed.path.lower()

        if any(path_low.endswith(ext) for ext in JUNK_EXTENSIONS) or DM_SOURCE_BLACKLIST.search(path_low):
            continue

        if host != canonical_domain and not host.endswith(f'.{canonical_domain}'):
            continue

        anchor_txt = f"{a_tag.get_text(' ', strip=True)} {a_tag.get('aria-label', '')} {a_tag.get('title', '')}".lower()
        is_contact_text = any(k in anchor_txt for k in CONTACT_ANCHOR_TEXT_KEYWORDS)
        is_contact_path = any(k in path_low for k in PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS)

        if (is_contact_text or is_contact_path) and full_u not in found:
            found.append(full_u)
            if len(found) >= 5:
                break

    return found


def parse_html_sync(
    html: str,
    page_url: str,
    default_region: str
) -> tuple[str, str, str, dict[str, str], list[tuple[str, int, str]], dict[str, tuple[str, str]], list[str]]:
    clean_page = clean_url_port(page_url) or page_url
    unescaped_html = html_lib.unescape(html)
    email_sources: dict[str, str] = {}
    for m in EMAIL_REGEX.findall(unescaped_html):
        email_sources[m] = clean_page

    raw_tel_candidates: list[tuple[str, str]] = [
        (m, 'schema_json_ld') for m in SCHEMA_PHONE_REGEX.findall(unescaped_html)
    ]
    social_candidates: dict[str, list[tuple[str, str]]] = {
        p: [] for p in ('linkedin', 'instagram', 'facebook', 'tiktok', 'telegram', 'youtube', 'twitter')
    }
    primary_links = set()
    secondary_links = set()

    soup = BeautifulSoup(html, 'lxml')
    base_domain = get_clean_canonical_domain(clean_page, urlparse(clean_page).netloc)
    brand_root = base_domain.split('.')[0] if base_domain else ''
    base_clean = clean_page.rstrip('/')

    page_title = ''
    if soup.title and soup.title.string:
        raw_title = ' '.join(soup.title.string.split())
        page_title = textwrap.shorten(raw_title, width=150, placeholder='…')
    if not page_title:
        og_title = (
            soup.find('meta', attrs={'property': re.compile(r'^og:title$', re.I)})
            or soup.find('meta', attrs={'property': re.compile(r'^og:site_name$', re.I)})
            or soup.find('meta', attrs={'name': re.compile(r'^application-name$', re.I)})
        )
        if og_title and og_title.get('content'):
            raw_og = ' '.join(str(og_title['content']).split())
            page_title = textwrap.shorten(raw_og, width=150, placeholder='…')

    meta_desc = ''
    desc_tag = (
        soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)})
        or soup.find('meta', attrs={'property': re.compile(r'^og:description$', re.I)})
    )
    if desc_tag and desc_tag.get('content'):
        raw_desc = ' '.join(str(desc_tag['content']).split())
        meta_desc = textwrap.shorten(raw_desc, width=300, placeholder='…')

    for cf_tag in soup.find_all(attrs={'data-cfemail': True}):
        decoded = decode_cf_email(cf_tag['data-cfemail'])
        if decoded and EMAIL_REGEX.match(decoded):
            email_sources[decoded] = clean_page

    spa_text_fragments = []
    for script_tag in soup.find_all('script'):
        sc_text = script_tag.string
        if not sc_text or len(sc_text) < 20:
            continue
        if (
            script_tag.get('id') == '__NEXT_DATA__'
            or '__NUXT__' in sc_text
            or '"contact"' in sc_text.lower()
            or '"email"' in sc_text.lower()
            or '"phone"' in sc_text.lower()
        ):
            unesc_sc = html_lib.unescape(sc_text).replace('\\/', '/')
            for em in EMAIL_REGEX.findall(unesc_sc):
                email_sources.setdefault(em, clean_page)
            for tel_m in SCHEMA_PHONE_REGEX.findall(unesc_sc):
                raw_tel_candidates.append((tel_m, 'spa_json_state'))
            for platform in social_candidates:
                for url_m in re.findall(r'https?://[^\s"\'<>\\]+', unesc_sc):
                    clean_soc = clean_and_validate_social_url(platform, url_m)
                    if clean_soc:
                        social_candidates[platform].append((clean_soc, clean_page))

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        href_lower = href.lower()

        if href_lower.startswith('mailto:'):
            mail = html_lib.unescape(href.split(':', 1)[1].split('?')[0]).strip()
            if EMAIL_REGEX.match(mail):
                email_sources[mail] = clean_page
            continue

        if href_lower.startswith('tel:'):
            tel = href.split(':', 1)[1].strip()
            parent = a_tag.find_parent(['li', 'p', 'div', 'td', 'section']) or a_tag.parent
            context_str = parent.get_text(' ', strip=True)[:200] if parent else a_tag.get_text(' ', strip=True)
            raw_tel_candidates.append((tel, context_str))
            continue

        for platform in social_candidates:
            clean_soc = clean_and_validate_social_url(platform, href)
            if clean_soc:
                social_candidates[platform].append((clean_soc, clean_page))

        full_url = clean_url_port(urljoin(clean_page, href)) or urljoin(clean_page, href)
        parsed = urlparse(full_url)
        link_domain = re.sub(r':\d+$', '', parsed.netloc.lower().replace('www.', ''))
        path_lower = parsed.path.lower()

        if any(path_lower.endswith(ext) for ext in JUNK_EXTENSIONS):
            continue

        if DM_SOURCE_BLACKLIST.search(path_lower):
            continue

        if base_domain and (link_domain == base_domain or link_domain.endswith(f'.{base_domain}')) and parsed.scheme in ('http', 'https'):
            normalized_link = clean_url_port(f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}")
            if not normalized_link or normalized_link.rstrip('/') == base_clean:
                continue

            anchor_txt = a_tag.get_text(' ', strip=True).lower()
            if any(k in path_lower for k in PRIMARY_CONTACT_KEYWORDS) or any(
                k in anchor_txt for k in ('contact', 'контакти', 'support', 'impressum', 'kontakt', 'mentions légales')
            ):
                primary_links.add(normalized_link)
            elif any(k in path_lower for k in SECONDARY_CONTACT_KEYWORDS):
                secondary_links.add(normalized_link)

    socials_with_source: dict[str, tuple[str, str]] = {}
    for platform, cand_list in social_candidates.items():
        best_soc, best_src = pick_best_social_candidate(cand_list, brand_root)
        if best_soc and best_src:
            socials_with_source[platform] = (best_soc, best_src)

    text_content = ' '.join([soup.get_text(' ', strip=True)] + spa_text_fragments)
    for m in EMAIL_REGEX.findall(text_content):
        email_sources.setdefault(m, clean_page)

    scored_phones = extract_valid_phones(text_content, raw_tel_candidates, default_region)
    phones_with_source = [(p, sc, clean_page) for p, sc in scored_phones]

    ordered_contact_links = sorted(primary_links) + sorted(secondary_links - primary_links)

    return page_title, meta_desc, text_content, email_sources, phones_with_source, socials_with_source, ordered_contact_links


async def get_shared_playwright_browser():
    global _PW_INSTANCE, _PW_BROWSER, PLAYWRIGHT_INSTALLED
    if not PLAYWRIGHT_INSTALLED:
        return None
    async with _PW_INIT_LOCK:
        if _PW_BROWSER is None:
            try:
                _PW_INSTANCE = await async_playwright().start()
                _PW_BROWSER = await _PW_INSTANCE.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-blink-features=AutomationControlled'
                    ]
                )
            except Exception as e:
                Actor.log.warning(f'Playwright launch failed ({e}); disabling browser fallback for this run.')
                if _PW_INSTANCE is not None:
                    try:
                        await _PW_INSTANCE.stop()
                    except Exception:
                        pass
                    _PW_INSTANCE = None
                PLAYWRIGHT_INSTALLED = False
                return None
    return _PW_BROWSER


async def close_shared_playwright_browser():
    global _PW_INSTANCE, _PW_BROWSER
    async with _PW_INIT_LOCK:
        if _PW_BROWSER is not None:
            try:
                await _PW_BROWSER.close()
            except Exception:
                pass
            _PW_BROWSER = None
        if _PW_INSTANCE is not None:
            try:
                await _PW_INSTANCE.stop()
            except Exception:
                pass
            _PW_INSTANCE = None


async def _fetch_pw_inner(url: str, proxy_url: str | None = None) -> tuple[str, str, str, bool]:
    browser = await get_shared_playwright_browser()
    if browser is None:
        return '', url, 'disabled', False

    ctx_kwargs = {
        'locale': 'en-US',
        'ignore_https_errors': True,
        'user_agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'
        )
    }
    if proxy_url:
        ctx_kwargs['proxy'] = {'server': proxy_url}

    context = await browser.new_context(**ctx_kwargs)
    await context.add_init_script(
        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
    )
    try:
        page = await context.new_page()
        resp = await page.goto(url, wait_until='domcontentloaded', timeout=12000)
        if resp and resp.status >= 400:
            return '', url, f'launched_blocked (HTTP {resp.status})', True

        await page.wait_for_timeout(900)

        consent_selectors = [
            '#shopify-pc__banner__btn-accept',
            '#onetrust-accept-btn-handler',
            '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
            '#uc-btn-accept-banner',
            '[data-testid="uc-accept-all-button"]',
            '[data-testid="cookie-accept"]',
            'button:has-text("Accept all")',
            'button:has-text("Accept")',
            'button:has-text("Alle akzeptieren")',
            'button:has-text("Tout accepter")',
            'button:has-text("Accetta tutto")',
            'button:has-text("Alles accepteren")',
            'button:has-text("Zaakceptuj wszystko")',
            'button:has-text("Прийняти")'
        ]
        for sel in consent_selectors:
            try:
                loc = page.locator(sel).first
                if await loc.is_visible(timeout=200):
                    await loc.click(timeout=500)
                    await page.wait_for_timeout(800)
                    break
            except Exception:
                continue

        try:
            await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
            await page.wait_for_timeout(400)
        except Exception:
            pass

        rendered_html = await page.content()
        final_u = clean_url_port(page.url) or url
        if not rendered_html or len(rendered_html) <= 500:
            return '', final_u, 'launched_empty', True
        return rendered_html, final_u, 'rendered', False
    finally:
        await context.close()


async def fetch_html_playwright_fallback(url: str, proxy_url: str | None = None) -> tuple[str, str, str, bool]:
    if not PLAYWRIGHT_INSTALLED:
        return '', url, 'disabled', False

    async with PW_SEMAPHORE:
        try:
            return await asyncio.wait_for(_fetch_pw_inner(url, proxy_url), timeout=20.0)
        except asyncio.TimeoutError:
            return '', url, 'launched_blocked (Page.goto: Timeout 20000ms exceeded.)', True
        except Exception as e:
            err_short = str(e).splitlines()[0][:60] if str(e) else 'error'
            return '', url, f'launched_blocked ({err_short})', True


async def load_robots_rules(client: AsyncSession, base_root: str) -> tuple[list[str], float]:
    disallowed: list[str] = []
    crawl_delay = 0.25
    try:
        resp = await client.get(f'{base_root}/robots.txt', impersonate='chrome', timeout=3.0)
        if resp.status_code == 200 and resp.text:
            active_for_all = False
            for raw_line in resp.text.splitlines():
                line = raw_line.split('#', 1)[0].strip()
                if not line or ':' not in line:
                    continue
                key, val = [x.strip() for x in line.split(':', 1)]
                k_low = key.lower()
                if k_low == 'user-agent':
                    active_for_all = (val == '*')
                elif active_for_all and k_low == 'disallow' and val.startswith('/'):
                    if val != '/':
                        disallowed.append(val)
                elif active_for_all and k_low == 'crawl-delay':
                    try:
                        crawl_delay = min(max(float(val), 0.25), 1.5)
                    except ValueError:
                        pass
    except Exception:
        pass
    return disallowed, crawl_delay


def is_allowed_by_robots(url: str, disallowed_prefixes: list[str]) -> bool:
    if not disallowed_prefixes:
        return True
    path = urlparse(url).path or '/'
    return not any(path.startswith(prefix) for prefix in disallowed_prefixes)


async def discover_links_from_sitemap(client: AsyncSession, base_root: str) -> list[str]:
    found_urls = []
    sitemap_url = f'{base_root}/sitemap.xml'
    try:
        resp = await client.get(sitemap_url, impersonate='chrome', timeout=4.5)
        if resp.status_code == 200 and resp.text:
            locs = re.findall(r'<loc>\s*(https?://[^<\s]+)\s*</loc>', resp.text, re.I)
            for url in locs:
                path_low = urlparse(url).path.lower()
                if DM_SOURCE_BLACKLIST.search(path_low):
                    continue
                if any(k in path_low for k in PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS):
                    clean_u = clean_url_port(url) or url
                    if clean_u not in found_urls:
                        found_urls.append(clean_u)
                    if len(found_urls) >= 5:
                        break
    except Exception:
        pass

    if not found_urls:
        dom_low = urlparse(base_root).netloc.lower()
        if dom_low.endswith(('.de', '.at', '.ch')):
            found_urls = [
                f'{base_root}/impressum/',
                f'{base_root}/kontakt/',
                f'{base_root}/ueber-uns/',
                f'{base_root}/about/'
            ]
        elif dom_low.endswith('.fr'):
            found_urls = [
                f'{base_root}/mentions-legales/',
                f'{base_root}/contact/',
                f'{base_root}/a-propos/'
            ]
        else:
            found_urls = [
                f'{base_root}/contacts/',
                f'{base_root}/kontakty/',
                f'{base_root}/about/',
                f'{base_root}/pro-nas/'
            ]
    return found_urls


async def fetch_html_safely(
    client: AsyncSession,
    url: str,
    proxy_config=None,
    timeout: float = 12.0,
    retries: int = 4
) -> tuple[int, str, str, str]:
    last_error = ''
    impersonations = ['chrome', 'safari', 'chrome110', 'edge99']
    current_target_url = url

    for attempt in range(retries):
        imp = impersonations[min(attempt, len(impersonations) - 1)]
        req_headers = {
            'Accept-Language': 'uk-UA,uk;q=0.9,en-GB;q=0.8,en;q=0.7,de-DE;q=0.6,de;q=0.5',
            'Referer': 'https://www.google.com/',
            'Upgrade-Insecure-Requests': '1'
        }
        use_proxy = None
        if attempt >= 1 and proxy_config is not None:
            try:
                use_proxy = await proxy_config.new_url(
                    session_id=f"retry_{attempt}_{abs(hash(current_target_url)) % 100000}"
                )
            except Exception:
                use_proxy = None

        try:
            async with client.stream(
                'GET',
                current_target_url,
                headers=req_headers,
                impersonate=imp,
                proxy=use_proxy,
                timeout=timeout
            ) as resp:
                status = resp.status_code
                final_url = clean_url_port(str(resp.url)) or str(resp.url)
                final_host = urlparse(final_url).netloc.lower()

                if CHECKOUT_REDIRECT_HOSTS.match(final_host) and attempt == 0:
                    clean_canon = get_clean_canonical_domain(final_url, urlparse(url).netloc)
                    current_target_url = f'https://www.{clean_canon}/'
                    continue

                if status in (403, 429, 502, 503, 504) and attempt < retries - 1:
                    await asyncio.sleep(1.2 * (1.5 ** attempt))
                    continue

                if status >= 400:
                    return status, '', final_url, f'HTTP Error {status}'

                content_type = resp.headers.get('content-type', '').lower()
                if content_type and not any(
                    t in content_type for t in (
                        'text/html', 'application/xhtml+xml', 'text/plain', 'javascript'
                    )
                ):
                    return status, '', final_url, f'Skipped non-HTML content: {content_type}'

                chunks = []
                bytes_read = 0
                async for chunk in resp.aiter_content():
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                    if bytes_read >= MAX_HTML_BYTES:
                        break

                raw_bytes = b''.join(chunks)
                encoding = getattr(resp, 'encoding', None) or 'utf-8'
                try:
                    html = raw_bytes.decode(encoding, errors='replace')
                except LookupError:
                    html = raw_bytes.decode('utf-8', errors='replace')

                if ('<title>' not in html.lower() or len(html) < 800) and attempt < retries - 1:
                    await asyncio.sleep(1.0)
                    continue

                return status, html, final_url, ''
        except Exception as e:
            last_error = str(e)
            if attempt < retries - 1:
                await asyncio.sleep(1.0)

    return 0, '', current_target_url, last_error or 'Connection failed'


async def fetch_gtm_scripts(
    client: AsyncSession,
    html: str
) -> tuple[list[str], str]:
    gtm_ids = sorted({
        m.upper() for m in GTM_ID_REGEX.findall(html)
        if is_valid_gtm_id(m)
    })
    if not gtm_ids:
        return [], ''

    gtm_contents = []
    for gtm_id in gtm_ids[:5]:
        gtm_url = f'https://www.googletagmanager.com/gtm.js?id={gtm_id}'
        try:
            resp = await client.get(gtm_url, impersonate='chrome', timeout=8.0)
            if resp.status_code == 200 and resp.text:
                gtm_contents.append(resp.text)
        except Exception:
            continue

    return gtm_ids, '\n'.join(gtm_contents)


def classify_failure_status(http_status: int, err_msg: str) -> str:
    err_lower = err_msg.lower()
    if http_status in (401, 403, 429):
        return 'blocked'
    if 'timeout' in err_lower or 'timed out' in err_lower:
        return 'timeout'
    return 'failed'
