import asyncio
import html as html_lib
import random
import re
import textwrap
import time
from urllib.parse import unquote, urljoin, urlparse
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
    from playwright.async_api import Error as PWError
    from playwright.async_api import TimeoutError as PWTimeoutError
    PLAYWRIGHT_INSTALLED = True
except ImportError:
    PLAYWRIGHT_INSTALLED = False
    PWError = Exception
    PWTimeoutError = Exception

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

TRACKING_NETWORK_DOMAINS = (
    'googletagmanager.com',
    'google-analytics.com',
    'analytics.google.com',
    'googleadservices.com',
    'doubleclick.net',
    'connect.facebook.net',
    'facebook.com/tr',
    'analytics.tiktok.com',
    'snap.licdn.com',
    'licdn.com',
    'pinimg.com',
    'clarity.ms',
    'hotjar.com',
    'hs-scripts.com',
    'hs-analytics.net',
    'klaviyo.com',
    'intercom.io',
)

_PW_MARKER_RE = re.compile(r'<!-- pw_[a-z_]+:.*?-->', re.S)

# Проблема 4 Fix: PW_ATTEMPT_BUDGET_S = 55.0, PW_TOTAL_BUDGET_S = 150.0 + 405 у PW_PERMANENT_STATUSES
PW_NAV_TIMEOUT_MS = 28_000
PW_ATTEMPT_BUDGET_S = 55.0
PW_TOTAL_BUDGET_S = 150.0
PW_MAX_ATTEMPTS = 3
PW_MAX_TRACKING_URLS = 120
PW_PERMANENT_STATUSES = frozenset({404, 405, 410})
PW_BLOCKED_RESOURCE_TYPES = frozenset({'image', 'media', 'font'})

_PW_ESCALATION_PROXY = None

PW_LOCALE_BY_REGION = {
    'DE': 'de-DE', 'AT': 'de-AT', 'CH': 'de-CH', 'UA': 'uk-UA', 'FR': 'fr-FR',
    'IT': 'it-IT', 'ES': 'es-ES', 'NL': 'nl-NL', 'BE': 'nl-BE', 'PL': 'pl-PL',
    'PT': 'pt-PT', 'SE': 'sv-SE', 'NO': 'nb-NO', 'DK': 'da-DK', 'FI': 'fi-FI',
    'CZ': 'cs-CZ', 'GB': 'en-GB', 'IE': 'en-IE', 'US': 'en-US',
}

_PW_CHALLENGE_TITLE_RE = re.compile(
    r'just a moment|attention required|access denied|pardon our interruption|'
    r'are you a robot|robot or human|verifying you are human|checking your browser|'
    r'security check|request unsuccessful|one more step',
    re.IGNORECASE,
)

_PW_CONSENT_CSS = ', '.join([
    '#onetrust-accept-btn-handler',
    '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
    '#CybotCookiebotDialogBodyButtonAccept',
    '#uc-btn-accept-banner',
    '[data-testid="uc-accept-all-button"]',
    '[data-testid="cookie-accept"]',
    '#didomi-notice-agree-button',
    '#shopify-pc__banner__btn-accept',
    '.cky-btn-accept',
    '.cmplz-btn.cmplz-accept',
    '#truste-consent-button',
    '.osano-cm-accept-all',
    '#axeptio_btn_acceptAll',
    '[data-cookiefirst-action="accept"]',
    '#tarteaucitronPersonalize2',
    '.iubenda-cs-accept-btn',
    '.fc-cta-consent',
    '.cm-btn-success',
])

_PW_ACCEPT_RE = re.compile(
    r'^\s*(?:accept(?: all)?(?: cookies)?|allow all(?: cookies)?|agree(?: and close)?|'
    r'i agree|got it|alle akzeptieren|alles akzeptieren|alle cookies akzeptieren|'
    r'akzeptieren|zustimmen|einverstanden|tout accepter|accepter(?: et fermer)?|'
    r'j.accepte|accetta(?: tutto| tutti)?|aceptar(?: todo| todas)?|'
    r'accepteer(?: alles| alle)?|accepteren|alles toestaan|zaakceptuj(?: wszystkie)?|'
    r'akceptuj[eę](?: wszystkie)?|прийняти(?: все| всі)?|погоджуюсь|згоден)\s*[.!]?\s*$',
    re.IGNORECASE,
)
_PW_REJECT_HINT_RE = re.compile(
    r'reject|decline|refuse|necessary|essential|only|settings|preferences|manage|'
    r'customi[sz]e|einstellungen|nur |ablehnen|refuser|rifiuta|rechazar|weigeren|'
    r'odrzu|відхил|налашт',
    re.IGNORECASE,
)

_PW_BUTTON_DEBUG_JS = """
() => {
    const btns = Array.from(document.querySelectorAll('button, a[role="button"], [class*="cookie"] button, [id*="cookie"] button'))
        .slice(0, 8)
        .map(el => (el.innerText || el.getAttribute('aria-label') || el.id || '').trim().replace(/\\s+/g, ' ').slice(0, 35))
        .filter(Boolean);
    const cmp = [];
    if (window.OneTrust) cmp.push('OneTrust');
    if (window.Cookiebot) cmp.push('Cookiebot');
    if (window.UC_UI || document.querySelector('#usercentrics-root')) cmp.push('Usercentrics');
    if (window.Didomi) cmp.push('Didomi');
    const hasShadowUc = !!document.querySelector('#usercentrics-root');
    return {
        buttons: btns.slice(0, 5),
        cmp: cmp,
        shadow_uc: hasShadowUc,
        iframes: document.querySelectorAll('iframe').length
    };
}
"""


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
    clean_html = _PW_MARKER_RE.sub('', html)
    soup = BeautifulSoup(clean_html, 'lxml')
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
    html = _PW_MARKER_RE.sub('', html)
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


def configure_pw(escalation_proxy=None, max_concurrent: int | None = None) -> None:
    global _PW_ESCALATION_PROXY, PW_SEMAPHORE
    _PW_ESCALATION_PROXY = escalation_proxy
    if max_concurrent:
        PW_SEMAPHORE = asyncio.Semaphore(max(1, int(max_concurrent)))


def pw_locale_for_region(region: str | None) -> str:
    return PW_LOCALE_BY_REGION.get((region or '').upper(), 'en-US')


async def get_shared_playwright_browser():
    global _PW_INSTANCE, _PW_BROWSER, PLAYWRIGHT_INSTALLED
    if not PLAYWRIGHT_INSTALLED:
        return None
    async with _PW_INIT_LOCK:
        if _PW_BROWSER is not None and not _PW_BROWSER.is_connected():
            _PW_BROWSER = None
        if _PW_BROWSER is None:
            try:
                if _PW_INSTANCE is None:
                    _PW_INSTANCE = await async_playwright().start()
                _PW_BROWSER = await _PW_INSTANCE.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-blink-features=AutomationControlled',
                    ],
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


async def reset_shared_playwright_browser():
    global _PW_BROWSER
    async with _PW_INIT_LOCK:
        if _PW_BROWSER is not None:
            try:
                await _PW_BROWSER.close()
            except Exception:
                pass
            _PW_BROWSER = None


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


def _is_tracking_url(u: str) -> bool:
    low = u.lower()
    return any(td in low for td in TRACKING_NETWORK_DOMAINS)


def _pw_looks_like_challenge(title: str) -> bool:
    return bool(title and _PW_CHALLENGE_TITLE_RE.search(title))


def _pw_proxy_dict(proxy_url: str | None) -> dict | None:
    if not proxy_url:
        return None
    try:
        p = urlparse(proxy_url)
        if not p.hostname:
            return None
        server = f'{p.scheme or "http"}://{p.hostname}'
        if p.port:
            server += f':{p.port}'
        out = {'server': server}
        if p.username:
            out['username'] = unquote(p.username)
        if p.password:
            out['password'] = unquote(p.password)
        return out
    except Exception:
        return None


async def _pw_safe_content(page, timeout_s: float = 8.0) -> str:
    try:
        return await asyncio.wait_for(page.content(), timeout_s)
    except Exception:
        return ''


async def _pw_safe_title(page) -> str:
    try:
        return await asyncio.wait_for(page.title(), 3.0)
    except Exception:
        return ''


async def _pw_try_accept_consent(page) -> bool:
    try:
        clicked_shadow = await asyncio.wait_for(
            page.evaluate("""() => {
                const uc = document.querySelector('#usercentrics-root');
                if (uc && uc.shadowRoot) {
                    const btn = uc.shadowRoot.querySelector('[data-testid="uc-accept-all-button"], button[aria-label*="accept" i], button[aria-label*="akzeptieren" i]');
                    if (btn) { btn.click(); return true; }
                }
                return false;
            }"""),
            timeout=1.5
        )
        if clicked_shadow:
            await page.wait_for_timeout(700)
            return True
    except Exception:
        pass

    try:
        scopes = [page] + [f for f in page.frames if f != page.main_frame][:4]
    except Exception:
        scopes = [page]

    for scope in scopes:
        try:
            loc = scope.locator(_PW_CONSENT_CSS).first
            if await loc.is_visible(timeout=400):
                await loc.click(timeout=1000)
                await page.wait_for_timeout(700)
                return True
        except Exception:
            pass
        for role in ('button', 'link'):
            try:
                cand = scope.get_by_role(role, name=_PW_ACCEPT_RE)
                cnt = min(await cand.count(), 3)
                for i in range(cnt):
                    el = cand.nth(i)
                    if not await el.is_visible(timeout=300):
                        continue
                    label = (await el.inner_text(timeout=400)).strip()
                    if _PW_REJECT_HINT_RE.search(label):
                        continue
                    await el.click(timeout=1000)
                    await page.wait_for_timeout(700)
                    return True
            except Exception:
                pass
    return False


async def _pw_accept_consent_guarded(page, max_s: float = 6.0) -> bool:
    try:
        return await asyncio.wait_for(_pw_try_accept_consent(page), timeout=max_s)
    except Exception:
        return False


async def _pw_debug_consent(page) -> str:
    try:
        info = await asyncio.wait_for(page.evaluate(_PW_BUTTON_DEBUG_JS), timeout=2.0)
        if isinstance(info, dict):
            return (
                f"buttons={info.get('buttons', [])} "
                f"cmp={info.get('cmp', [])} "
                f"shadow_uc={info.get('shadow_uc', False)} "
                f"iframes={info.get('iframes', 0)}"
            )
    except Exception:
        pass
    return 'debug_unavailable'


def _pw_finalize_html(html: str, hits: list[str], consent: bool, partial: bool) -> str:
    marks = []
    if consent:
        marks.append('<!-- pw_consent: accepted -->')
    if partial:
        marks.append('<!-- pw_partial: nav_timeout -->')
    for u in hits:
        marks.append(f'<!-- pw_net_req: {u.replace("-->", "%2D%2D%3E")} -->')
    return html + '\n' + '\n'.join(marks) if marks else html


def _pw_new_result(url: str) -> dict:
    return {
        'html': '', 'final_url': url, 'http': 0, 'err': '',
        'consent': False, 'consent_debug': '', 'partial': False,
        'hits': [], 'timings': {},
    }


async def _pw_render_once(
    res: dict,
    url: str,
    proxy_url: str | None,
    locale: str,
    nav_timeout_ms: int,
    accept_consent: bool,
) -> None:
    tm = res['timings']
    t0 = time.monotonic()
    browser = await get_shared_playwright_browser()
    if browser is None:
        res['err'] = 'disabled'
        return
    tm['browser'] = round(time.monotonic() - t0, 1)

    major = (getattr(browser, 'version', '') or '').split('.')[0] or '131'
    lang = locale.split('-')[0]
    ctx_kwargs = {
        'locale': locale,
        'ignore_https_errors': True,
        'viewport': {'width': 1366, 'height': 850},
        'user_agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            f'(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36'
        ),
        'extra_http_headers': {'Accept-Language': f'{locale},{lang};q=0.9,en;q=0.8'},
    }
    pw_proxy = _pw_proxy_dict(proxy_url)
    if pw_proxy:
        ctx_kwargs['proxy'] = pw_proxy

    hits = res['hits']
    seen: set[str] = set()

    def _record(u: str) -> None:
        if len(hits) >= PW_MAX_TRACKING_URLS or not _is_tracking_url(u):
            return
        key = u[:200]
        if key in seen:
            return
        seen.add(key)
        hits.append(u[:500])

    t1 = time.monotonic()
    context = await browser.new_context(**ctx_kwargs)
    tm['context'] = round(time.monotonic() - t1, 1)
    try:
        await context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )
        page = await context.new_page()
        page.on('request', lambda r: _record(r.url))

        async def _route(route):
            try:
                req = route.request
                tracking = _is_tracking_url(req.url)
                if tracking:
                    _record(req.url)
                if not tracking and req.resource_type in PW_BLOCKED_RESOURCE_TYPES:
                    await route.abort()
                else:
                    await route.continue_()
            except Exception:
                try:
                    await route.continue_()
                except Exception:
                    pass

        await page.route('**/*', _route)

        t2 = time.monotonic()
        nav_timed_out = False
        try:
            resp = await page.goto(url, wait_until='domcontentloaded', timeout=nav_timeout_ms)
            res['http'] = resp.status if resp else 0
        except PWTimeoutError:
            nav_timed_out = True
            res['err'] = f'Page.goto: Timeout {nav_timeout_ms}ms exceeded.'
        tm['goto'] = round(time.monotonic() - t2, 1)

        if nav_timed_out:
            if hits:
                res['html'] = await _pw_safe_content(page, 4.0) or '<html><head></head><body></body></html>'
                res['final_url'] = clean_url_port(page.url) or url
                res['partial'] = True
                res['err'] = ''
            return

        title = await _pw_safe_title(page)
        if res['http'] in (403, 429, 503) or _pw_looks_like_challenge(title):
            cleared = False
            for _ in range(6):
                await page.wait_for_timeout(1000)
                title = await _pw_safe_title(page)
                if not _pw_looks_like_challenge(title) and title:
                    cleared = True
                    break
            if not cleared:
                res['err'] = f'HTTP {res["http"]}' if res['http'] >= 400 else 'challenge'
                return
            res['http'] = 200
        elif res['http'] >= 400:
            res['err'] = f'HTTP {res["http"]}'
            return

        t3 = time.monotonic()
        if accept_consent:
            res['consent'] = await _pw_accept_consent_guarded(page, max_s=6.0)
            if not res['consent']:
                res['consent_debug'] = await _pw_debug_consent(page)
        try:
            await page.wait_for_load_state('networkidle', timeout=3500)
        except Exception:
            pass
        await page.wait_for_timeout(900 if res['consent'] else 400)
        try:
            await asyncio.wait_for(
                page.evaluate('window.scrollTo(0, document.body.scrollHeight)'),
                timeout=2.0
            )
            await page.wait_for_timeout(400)
        except Exception:
            pass
        tm['consent_settle'] = round(time.monotonic() - t3, 1)

        t4 = time.monotonic()
        html = await _pw_safe_content(page, 6.0)
        tm['content'] = round(time.monotonic() - t4, 1)
        res['final_url'] = clean_url_port(page.url) or url
        if not html or len(html) <= 500:
            res['err'] = 'launched_empty'
            return
        res['html'] = html
    except PWTimeoutError:
        res['err'] = 'Page.goto: Timeout (post-navigation step)'
    except PWError as e:
        msg = ' '.join(str(e).split())
        if any(k in msg.lower() for k in ('browser has been closed', 'target closed', 'connection closed')):
            res['err'] = 'browser_closed'
        elif 'crash' in msg.lower():
            res['err'] = 'Target crashed'
        else:
            res['err'] = msg[:60] or 'error'
    finally:
        try:
            await asyncio.wait_for(context.close(), timeout=5.0)
        except Exception:
            pass


async def fetch_html_playwright_fallback(
    url: str,
    proxy_url: str | None = None,
    locale: str = 'en-US',
    accept_consent: bool = True,
    max_attempts: int | None = None,
    start_residential: bool = False,
) -> tuple[str, str, str, bool, int]:
    if not PLAYWRIGHT_INSTALLED:
        return '', url, 'disabled', False, 0

    n_max = max_attempts or PW_MAX_ATTEMPTS
    if _PW_ESCALATION_PROXY is None:
        n_max = min(n_max, 2)
    host = urlparse(url).netloc or url
    started = time.monotonic()
    last_err = 'unknown'
    last_final = url
    best_partial: tuple[str, str] | None = None
    attempts_made = 0

    async with PW_SEMAPHORE:
        for attempt in range(1, n_max + 1):
            if attempt > 1 and time.monotonic() - started > PW_TOTAL_BUDGET_S:
                break

            attempts_made = attempt
            use_proxy, route_name = proxy_url, ('proxy' if proxy_url else 'direct')
            if (attempt >= 2 or start_residential) and _PW_ESCALATION_PROXY is not None:
                try:
                    use_proxy = await _PW_ESCALATION_PROXY.new_url(
                        session_id=f'pw{attempt}x{random.randint(0, 999999)}'
                    )
                    route_name = 'residential'
                except Exception:
                    use_proxy, route_name = proxy_url, ('proxy-retry' if proxy_url else 'direct-retry')
            elif attempt >= 2:
                route_name = 'direct-retry'

            res = _pw_new_result(url)
            try:
                await asyncio.wait_for(
                    _pw_render_once(res, url, use_proxy, locale, PW_NAV_TIMEOUT_MS, accept_consent),
                    timeout=PW_ATTEMPT_BUDGET_S,
                )
            except asyncio.TimeoutError:
                res['err'] = f'attempt_budget_exceeded ({int(PW_ATTEMPT_BUDGET_S)}s)'
                if res['hits'] and not res['html']:
                    res['html'] = '<html><head></head><body></body></html>'
                    res['partial'] = True
                    res['err'] = ''
            except Exception as e:
                res['err'] = (str(e).splitlines()[0][:60] if str(e) else 'error')

            last_final = res['final_url'] or url
            outcome = 'ok' if (res['html'] and not res['err']) else (res['err'] or 'empty')
            dbg_suffix = f" consent_debug={res['consent_debug']}" if res.get('consent_debug') else ''
            Actor.log.info(
                f'[pw] {host} try {attempt}/{n_max} via {route_name}: {outcome}'
                f'{" (partial)" if res["partial"] else ""} consent={res["consent"]} '
                f'trackers={len(res["hits"])} t={res["timings"]}{dbg_suffix}'
            )

            if res['html'] and not res['err']:
                html = _pw_finalize_html(res['html'], res['hits'], res['consent'], res['partial'])
                if not res['partial']:
                    return html, last_final, 'rendered', False, attempts_made
                if best_partial is None or len(html) > len(best_partial[0]):
                    best_partial = (html, last_final)
                last_err = 'Page.goto: Timeout (partial salvaged)'
            else:
                last_err = res['err'] or 'empty'

            if res['err'] == 'browser_closed':
                await reset_shared_playwright_browser()
            if res['http'] in PW_PERMANENT_STATUSES:
                break
            if attempt < n_max:
                await asyncio.sleep(random.uniform(0.8, 2.0))

    if best_partial is not None:
        return best_partial[0], best_partial[1], 'rendered', True, attempts_made
    if last_err == 'launched_empty':
        return '', last_final, 'launched_empty', True, attempts_made
    return '', last_final, f'launched_blocked ({last_err})', True, attempts_made


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
            sub_sitemaps = [u for u in locs if u.lower().endswith('.xml') and ('page' in u.lower() or 'main' in u.lower() or 'static' in u.lower())]
            for url in locs:
                if url.lower().endswith('.xml'):
                    continue
                path_low = urlparse(url).path.lower()
                if DM_SOURCE_BLACKLIST.search(path_low):
                    continue
                if any(k in path_low for k in PRIMARY_CONTACT_KEYWORDS + SECONDARY_CONTACT_KEYWORDS):
                    clean_u = clean_url_port(url) or url
                    if clean_u not in found_urls:
                        found_urls.append(clean_u)
                    if len(found_urls) >= 5:
                        break
            if not found_urls and sub_sitemaps:
                sub_resp = await client.get(sub_sitemaps[0], impersonate='chrome', timeout=4.0)
                if sub_resp.status_code == 200 and sub_resp.text:
                    sub_locs = re.findall(r'<loc>\s*(https?://[^<\s]+)\s*</loc>', sub_resp.text, re.I)
                    for url in sub_locs:
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
