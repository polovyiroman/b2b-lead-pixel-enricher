import asyncio
import re
from urllib.parse import urljoin, urlparse
from curl_cffi.requests import AsyncSession
import phonenumbers
from bs4 import BeautifulSoup
from apify import Actor

# Максимальний розмір сторінки для читання в пам'ять (1.5 МБ), щоб уникнути OOM
MAX_HTML_BYTES = 1_500_000

# Регулярні вирази для імейлів, телефонів у JSON-LD та рекламних ідентифікаторів
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
SCHEMA_PHONE_REGEX = re.compile(r'"telephone"\s*:\s*"([^"]{7,30})"', re.IGNORECASE)
GTM_ID_REGEX = re.compile(r'\bGTM-[A-Z0-9]{4,10}\b', re.IGNORECASE)
GA4_ID_REGEX = re.compile(r'\bG-[A-Z0-9]{6,12}\b')
GOOGLE_ADS_REGEX = re.compile(r'\bAW-\d{6,12}\b')

# Сміттєві домени, префікси та розширення
JUNK_EMAIL_DOMAINS = {
    'sentry.io', 'wixpress.com', 'example.com', 'domain.com',
    'email.com', 'yoursite.com', 'sentry.wixpress.com', 'godaddy.com',
    'sentry-next.wixpress.com', 'wordpress.org', 'w3.org', 'schema.org',
    'googleusercontent.com', 'cloudflare.com', 'shopify.com'
}
JUNK_EMAIL_PREFIXES = (
    'noreply@', 'no-reply@', 'donotreply@', 'mailer-daemon@',
    'postmaster@', 'hostmaster@', 'webmaster@', 'abuse@'
)
JUNK_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.avif',
    '.js', '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
    '.pdf', '.zip', '.rar', '.xml', '.json', '.docx', '.xlsx'
)

# Пріоритети поштових скриньок для B2B-продажів
HIGH_PRIORITY_PREFIXES = (
    'sales', 'hello', 'hi', 'contact', 'info', 'office', 'team',
    'inquiries', 'enquiry', 'enquiries', 'founder', 'ceo', 'owner',
    'partner', 'partnerships', 'marketing', 'kontakt', 'hallo', 'support', 'help'
)
LOW_PRIORITY_PREFIXES = (
    'privacy', 'legal', 'datenschutz', 'dpo', 'compliance', 'gdpr',
    'billing', 'invoice', 'invoices', 'accounting', 'finance',
    'jobs', 'careers', 'hr', 'recruiting', 'press', 'media', 'pr',
    'security', 'copyright', 'dmca'
)

# Ключові слова для пошуку контактних сторінок (за пріоритетом)
PRIMARY_CONTACT_KEYWORDS = (
    'contact', 'kontakt', 'impressum', 'contatti', 'contacto',
    'get-in-touch', 'contact-information'
)
SECONDARY_CONTACT_KEYWORDS = (
    'about', 'uber-uns', 'ueber-uns', 'team', 'company', 'support', 'help', 'faq'
)

# Сигнатури технологій та пікселів (включно з внутрішніми конфігами Shopify Trekkie/WPM)
TECH_SIGNATURES = {
    'Meta Pixel (Facebook)': [
        'connect.facebook.net', 'fbq(', 'facebook.com/tr?',
        '"facebook pixel"', 'facebook_pixel', 'fb_pixel_id'
    ],
    'TikTok Pixel': [
        'analytics.tiktok.com', 'ttq.load', 'ttq.page',
        '"tiktok pixel"', 'tiktok_pixel'
    ],
    'LinkedIn Insight Tag': [
        'snap.licdn.com/li.lms-analytics', '_linkedin_partner_id', 'linkedin_insight'
    ],
    'Pinterest Tag': ['s.pinimg.com/ct/core.js', 'pintrk('],
    'Microsoft Clarity': ['clarity.ms/tag/'],
    'Hotjar': ['static.hotjar.com', 'hjsettings'],
    'HubSpot': ['js.hs-scripts.com', 'hs-analytics', 'hbspt.forms'],
    'Intercom': ['widget.intercom.io', 'intercomsettings'],
    'Klaviyo': ['static.klaviyo.com', 'klaviyo.push', 'klaviyo'],
    'Shopify': ['cdn.shopify.com', 'shopify.theme', 'trekkie.integrations', 'shopify-pixel'],
    'WordPress': ['wp-content/', 'wp-includes/'],
    'WooCommerce': ['woocommerce', 'wc-blocks'],
    'Webflow': ['webflow.com', 'data-wf-site'],
    'Wix': ['wix.com', 'wixstatic.com'],
    'Tilda': ['tildacdn.com', 'tilda-blocks'],
    'Squarespace': ['squarespace.com', 'static1.squarespace.com']
}

SOCIAL_PLATFORMS = {
    'linkedin': ('linkedin.com/company/', 'linkedin.com/in/', 'linkedin.com/school/'),
    'instagram': ('instagram.com/',),
    'facebook': ('facebook.com/',),
    'twitter': ('twitter.com/', 'x.com/'),
    'youtube': ('youtube.com/@', 'youtube.com/c/', 'youtube.com/channel/', 'youtube.com/user/'),
    'tiktok': ('tiktok.com/@',),
    'telegram': ('t.me/', 'telegram.me/')
}

SOCIAL_JUNK_PATTERNS = (
    'sharer', 'share', 'intent/tweet', 'plugins/', '/status/',
    '/posts/', '/photos/', '/videos/', 'facebook.com/tr', 'dialog/feed',
    'instagram.com/p/', 'instagram.com/reel/'
)


def prepare_domains(raw_domains: list[str]) -> list[tuple[str, str]]:
    """Очищує, зводить до кореневого URL та дедуплікує вхідний список доменів."""
    seen = set()
    prepared = []
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
        if domain_key not in seen:
            seen.add(domain_key)
            root_url = f'{parsed.scheme}://{netloc}'
            prepared.append((domain_key, root_url))
    return prepared


def decode_cf_email(encoded_str: str) -> str:
    """Дешифрує імейли, сховані захистом Cloudflare (data-cfemail)."""
    try:
        r = int(encoded_str[:2], 16)
        return ''.join(
            chr(int(encoded_str[i:i + 2], 16) ^ r)
            for i in range(2, len(encoded_str), 2)
        )
    except Exception:
        return ''


def rank_and_clean_emails(raw_emails: set[str], base_domain: str) -> list[str]:
    """Фільтрує сміттєві імейли та сортує їх за комерційною цінністю для B2B."""
    valid = set()
    for email in raw_emails:
        email = email.lower().strip('.,;:()[]"\'<> \t\r\n')
        email = re.sub(r'^(?:%20|u003[ce]|3a)+', '', email)

        if any(email.endswith(ext) for ext in JUNK_EXTENSIONS):
            continue
        if any(email.startswith(prefix) for prefix in JUNK_EMAIL_PREFIXES):
            continue
        if '@' not in email:
            continue

        local_part, domain_part = email.split('@', 1)
        if not local_part or domain_part in JUNK_EMAIL_DOMAINS and base_domain != domain_part:
            continue
        if 6 <= len(email) <= 60:
            valid.add(email)

    def email_score(addr: str) -> tuple[int, str]:
        local, domain = addr.split('@', 1)
        score = 0

        # +20 балів, якщо пошта на домені самої компанії
        if base_domain and (domain == base_domain or domain.endswith(f'.{base_domain}')):
            score += 20

        # Оцінка префікса пошти
        if local.startswith(HIGH_PRIORITY_PREFIXES):
            score += 15
        elif local.startswith(LOW_PRIORITY_PREFIXES):
            score -= 30
        else:
            score += 10

        return (-score, addr)

    return sorted(valid, key=email_score)


def extract_valid_phones(text: str, raw_tel_links: set[str], default_region: str) -> list[str]:
    """Витягує та валідує реальні телефонні номери у міжнародному форматі E.164."""
    valid_phones = []
    seen = set()

    # 1. Пріоритет номерам із прямих посилань tel: та мікророзмітки Schema.org
    for raw_tel in raw_tel_links:
        try:
            parsed = phonenumbers.parse(raw_tel, default_region)
            if phonenumbers.is_valid_number(parsed):
                formatted = phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                )
                if formatted not in seen:
                    seen.add(formatted)
                    valid_phones.append(formatted)
        except phonenumbers.NumberParseException:
            continue

    # 2. Пошук номерів у видимому тексті сторінки
    for match in phonenumbers.PhoneNumberMatcher(text, default_region):
        if phonenumbers.is_valid_number(match.number):
            formatted = phonenumbers.format_number(
                match.number, phonenumbers.PhoneNumberFormat.E164
            )
            if formatted not in seen:
                seen.add(formatted)
                valid_phones.append(formatted)

    return valid_phones[:10]


def detect_tech_and_pixels(combined_source: str, gtm_ids: list[str]) -> dict:
    """Аналізує HTML та код GTM-контейнера на наявність технологій і рекламних пікселів."""
    source_lower = combined_source.lower()
    detected = []

    has_gtm = bool(gtm_ids) or 'googletagmanager.com/gtm.js' in source_lower
    if has_gtm:
        detected.append('Google Tag Manager')

    has_ga4 = (
        bool(GA4_ID_REGEX.search(combined_source))
        or 'googletagmanager.com/gtag/js' in source_lower
        or 'google-analytics.com/g/collect' in source_lower
    )
    if has_ga4:
        detected.append('Google Analytics (GA4)')

    has_google_ads = (
        bool(GOOGLE_ADS_REGEX.search(combined_source))
        or 'googleadservices.com/pagead/conversion' in source_lower
    )
    if has_google_ads:
        detected.append('Google Ads Conversion')

    for name, markers in TECH_SIGNATURES.items():
        if any(marker in source_lower for marker in markers):
            detected.append(name)

    return {
        'has_meta_pixel': 'Meta Pixel (Facebook)' in detected,
        'has_tiktok_pixel': 'TikTok Pixel' in detected,
        'has_google_ads': has_google_ads,
        'has_linkedin_pixel': 'LinkedIn Insight Tag' in detected,
        'has_ga4': has_ga4,
        'has_gtm': has_gtm,
        'gtm_container_ids': gtm_ids,
        'detected_technologies': detected
    }


def parse_html_sync(
    html: str,
    base_url: str,
    default_region: str
) -> tuple[str, str, set[str], list[str], dict[str, str], list[str]]:
    """Синхронна функція парсингу HTML (виконується в окремому потоці через asyncio.to_thread)."""
    emails = set(EMAIL_REGEX.findall(html))
    raw_tel_links = set(SCHEMA_PHONE_REGEX.findall(html))
    socials = {}
    primary_links = set()
    secondary_links = set()

    soup = BeautifulSoup(html, 'lxml')
    base_domain = urlparse(base_url).netloc.lower().replace('www.', '')
    base_clean = base_url.rstrip('/')

    # Витягування Title та Meta Description для AI-персоналізації
    page_title = ''
    if soup.title and soup.title.string:
        page_title = ' '.join(soup.title.string.split())[:150]

    meta_desc = ''
    desc_tag = (
        soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)})
        or soup.find('meta', attrs={'property': re.compile(r'^og:description$', re.I)})
    )
    if desc_tag and desc_tag.get('content'):
        meta_desc = ' '.join(str(desc_tag['content']).split())[:300]

    # Розшифровка Cloudflare-імейлів
    for cf_tag in soup.find_all(attrs={'data-cfemail': True}):
        decoded = decode_cf_email(cf_tag['data-cfemail'])
        if decoded and EMAIL_REGEX.match(decoded):
            emails.add(decoded)

    # Обхід усіх посилань
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        href_lower = href.lower()

        if href_lower.startswith('mailto:'):
            mail = href.split(':', 1)[1].split('?')[0].strip()
            if EMAIL_REGEX.match(mail):
                emails.add(mail)
            continue

        if href_lower.startswith('tel:'):
            tel = href.split(':', 1)[1].strip()
            raw_tel_links.add(tel)
            continue

        # Соцмережі
        for platform, domains in SOCIAL_PLATFORMS.items():
            if platform not in socials:
                if any(d in href_lower for d in domains):
                    if not any(junk in href_lower for junk in SOCIAL_JUNK_PATTERNS):
                        socials[platform] = href.split('?')[0].rstrip('/')

        # Внутрішні сторінки контактів (відсікаємо PDF, архіви та медіафайли)
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        link_domain = parsed.netloc.lower().replace('www.', '')
        path_lower = parsed.path.lower()

        if any(path_lower.endswith(ext) for ext in JUNK_EXTENSIONS):
            continue

        if base_domain and link_domain == base_domain and parsed.scheme in ('http', 'https'):
            normalized_link = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
            if normalized_link == base_clean:
                continue

            if any(k in path_lower for k in PRIMARY_CONTACT_KEYWORDS):
                primary_links.add(normalized_link)
            elif any(k in path_lower for k in SECONDARY_CONTACT_KEYWORDS):
                secondary_links.add(normalized_link)

    text_content = soup.get_text(' ', strip=True)
    emails.update(EMAIL_REGEX.findall(text_content))
    phones = extract_valid_phones(text_content, raw_tel_links, default_region)

    ordered_contact_links = sorted(primary_links) + sorted(secondary_links - primary_links)

    return page_title, meta_desc, emails, phones, socials, ordered_contact_links


async def fetch_html_safely(
    client: AsyncSession,
    url: str,
    timeout: float = 15.0,
    retries: int = 2
) -> tuple[int, str, str, str]:
    """
    Безпечно завантажує текстові HTML/JS сторінки (до 1.5 МБ) з TLS-відбитком Chrome.
    Захищає від блокувань Cloudflare (403) та падіння контейнера на великих PDF/архівах.
    """
    last_error = ''
    for attempt in range(retries):
        try:
            async with client.stream('GET', url, timeout=timeout) as resp:
                status = resp.status_code
                final_url = str(resp.url)

                if status in (429, 502, 503, 504) and attempt < retries - 1:
                    await asyncio.sleep(1.5 * (attempt + 1))
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
                return status, html, final_url, ''
        except Exception as e:
            last_error = str(e)
            if attempt < retries - 1:
                await asyncio.sleep(1.0)

    return 0, '', url, last_error or 'Connection failed'


async def fetch_gtm_scripts(client: AsyncSession, html: str) -> tuple[list[str], str]:
    """Завантажує JS-код контейнерів GTM для пошуку пікселів, схованих усередині."""
    gtm_ids = sorted({m.upper() for m in GTM_ID_REGEX.findall(html)})
    if not gtm_ids:
        return [], ''

    gtm_contents = []
    for gtm_id in gtm_ids[:2]:
        gtm_url = f'https://www.googletagmanager.com/gtm.js?id={gtm_id}'
        status, js_text, _, _ = await fetch_html_safely(client, gtm_url, timeout=8.0, retries=1)
        if status == 200 and js_text:
            gtm_contents.append(js_text)

    return gtm_ids, '\n'.join(gtm_contents)


async def process_domain(
    client: AsyncSession,
    domain_key: str,
    root_url: str,
    scan_contacts: bool,
    unpack_gtm: bool,
    default_region: str,
    semaphore: asyncio.Semaphore
) -> dict:
    empty_result = {
        'input_domain': domain_key,
        'website_url': root_url,
        'status': 'error',
        'error_message': '',
        'page_title': '',
        'meta_description': '',
        'best_email': None,
        'primary_phone': None,
        'linkedin_url': None,
        'instagram_url': None,
        'facebook_url': None,
        'has_meta_pixel': False,
        'has_tiktok_pixel': False,
        'has_google_ads': False,
        'has_linkedin_pixel': False,
        'has_ga4': False,
        'has_gtm': False,
        'detected_technologies': [],
        'gtm_container_ids': [],
        'emails': [],
        'phones': [],
        'socials': {}
    }

    async with semaphore:
        status, html, final_url, err_msg = await fetch_html_safely(client, root_url)

        if status == 0 or status >= 400 or not html:
            empty_result['website_url'] = final_url
            empty_result['status'] = f'http_{status}' if status >= 400 else 'error'
            empty_result['error_message'] = err_msg
            return empty_result

        # Парсимо HTML у фоновому потоці, щоб не блокувати asyncio Event Loop
        page_title, meta_desc, emails, phones_list, socials, contact_links = await asyncio.to_thread(
            parse_html_sync, html, final_url, default_region
        )

        # Розпаковка Google Tag Manager
        if unpack_gtm:
            gtm_ids, gtm_js = await fetch_gtm_scripts(client, html)
        else:
            gtm_ids = sorted({m.upper() for m in GTM_ID_REGEX.findall(html)})
            gtm_js = ''

        tech_info = detect_tech_and_pixels(f'{html}\n{gtm_js}', gtm_ids)

        # Обхід до 3 внутрішніх контактних сторінок (/contact, /impressum, /about, /faq)
        if scan_contacts and contact_links:
            for sub_url in contact_links[:3]:
                sub_status, sub_html, _, _ = await fetch_html_safely(
                    client, sub_url, timeout=10.0, retries=1
                )
                if 200 <= sub_status < 400 and sub_html:
                    _, _, sub_e, sub_p, sub_s, _ = await asyncio.to_thread(
                        parse_html_sync, sub_html, final_url, default_region
                    )
                    emails.update(sub_e)
                    for p in sub_p:
                        if p not in phones_list:
                            phones_list.append(p)
                    for k, v in sub_s.items():
                        socials.setdefault(k, v)

        base_domain = urlparse(final_url).netloc.lower().replace('www.', '')
        ranked_emails = rank_and_clean_emails(emails, base_domain)
        final_phones = phones_list[:10]

        return {
            'input_domain': domain_key,
            'website_url': final_url,
            'status': 'success',
            'error_message': '',
            'page_title': page_title,
            'meta_description': meta_desc,
            'best_email': ranked_emails[0] if ranked_emails else None,
            'primary_phone': final_phones[0] if final_phones else None,
            'linkedin_url': socials.get('linkedin'),
            'instagram_url': socials.get('instagram'),
            'facebook_url': socials.get('facebook'),
            **tech_info,
            'emails': ranked_emails,
            'phones': final_phones,
            'socials': socials
        }


async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}
        raw_domains = actor_input.get('domains', [])
        scan_contacts = actor_input.get('scanContactPages', True)
        unpack_gtm = actor_input.get('unpackGtmContainers', True)
        default_region = actor_input.get('defaultPhoneRegion', 'US').upper().strip()
        max_concurrency = actor_input.get('maxConcurrency', 15)
        proxy_settings = actor_input.get('proxyConfiguration')

        prepared_domains = prepare_domains(raw_domains)
        if not prepared_domains:
            Actor.log.warning('No valid domains provided in input!')
            return

        proxy_url = None
        if proxy_settings:
            proxy_config = await Actor.create_proxy_configuration(
                actor_proxy_input=proxy_settings
            )
            if proxy_config:
                proxy_url = await proxy_config.new_url()

        Actor.log.info(
            f'Processing {len(prepared_domains)} unique domains '
            f'(concurrency: {max_concurrency}, GTM unpack: {unpack_gtm})...'
        )
        semaphore = asyncio.Semaphore(max_concurrency)

        # curl_cffi з impersonate='chrome' автоматично виставляє нативні заголовки Chrome
        headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Upgrade-Insecure-Requests': '1'
        }

        batch = []
        batch_size = 25

        async with AsyncSession(
            impersonate='chrome',
            headers=headers,
            allow_redirects=True,
            verify=False,
            proxy=proxy_url
        ) as client:
            tasks = [
                process_domain(
                    client, domain_key, root_url, scan_contacts, unpack_gtm, default_region, semaphore
                )
                for domain_key, root_url in prepared_domains
            ]

            for coro in asyncio.as_completed(tasks):
                result = await coro
                batch.append(result)

                Actor.log.info(
                    f"[{result['status'].upper()}] {result['input_domain']} | "
                    f"Best Email: {result['best_email'] or '-'} | "
                    f"Phone: {result['primary_phone'] or '-'} | "
                    f"Tech: {len(result['detected_technologies'])}"
                )

                if len(batch) >= batch_size:
                    await Actor.push_data(batch)
                    batch.clear()

            if batch:
                await Actor.push_data(batch)


if __name__ == '__main__':
    asyncio.run(main())
