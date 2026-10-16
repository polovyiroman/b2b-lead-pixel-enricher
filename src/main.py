import asyncio
import re
from urllib.parse import urljoin, urlparse
from curl_cffi.requests import AsyncSession
import phonenumbers
from bs4 import BeautifulSoup
from apify import Actor

MAX_HTML_BYTES = 1_500_000

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
SCHEMA_PHONE_REGEX = re.compile(r'"telephone"\s*:\s*"([^"]{7,30})"', re.IGNORECASE)
GTM_ID_REGEX = re.compile(r'\bGTM-[A-Z0-9]{4,10}\b', re.IGNORECASE)
GA4_ID_REGEX = re.compile(r'\bG-[A-Z0-9]{6,12}\b')
GOOGLE_ADS_REGEX = re.compile(r'\bAW-\d{6,12}\b')

# Розширений список сміттєвих і тестових доменів
JUNK_EMAIL_DOMAINS = {
    'sentry.io', 'wixpress.com', 'example.com', 'domain.com', 'test.com',
    'email.com', 'yoursite.com', 'yourdomain.com', 'company.com', 'website.com',
    'sentry.wixpress.com', 'godaddy.com', 'sentry-next.wixpress.com',
    'wordpress.org', 'w3.org', 'schema.org', 'googleusercontent.com',
    'cloudflare.com', 'shopify.com', 'mysite.com', 'sample.com', 'mail.ru'
}

# Точні локальні частини тестових/фейкових пошт (відсікає test@..., example@... тощо)
JUNK_EMAIL_LOCALS = {
    'test', 'testing', 'example', 'user', 'username', 'name', 'firstname',
    'lastname', 'yourname', 'youremail', 'email', 'mail', 'sample', 'demo',
    'foo', 'bar', 'admin', 'root', 'webmaster', 'postmaster', 'hostmaster',
    'abuse', 'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'mailer-daemon',
    'xxx', 'abc', '123', 'null', 'none', 'undefined'
}

JUNK_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.avif',
    '.js', '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
    '.pdf', '.zip', '.rar', '.xml', '.json', '.docx', '.xlsx'
)

# Категорії поштових префіксів для класифікації та пріоритизації
SALES_PREFIXES = (
    'sales', 'sale', 'b2b', 'wholesale', 'opt', 'commercial', 'business',
    'partner', 'partners', 'partnerships', 'deals', 'enterprise', 'corporate',
    'hello', 'hi', 'contact', 'info', 'office', 'team', 'inquiries',
    'enquiry', 'enquiries', 'founder', 'ceo', 'owner', 'kontakt', 'hallo'
)
PR_MEDIA_PREFIXES = (
    'pr', 'press', 'media', 'comms', 'communications', 'marketing', 'ads', 'collab', 'brand'
)
SUPPORT_PREFIXES = (
    'support', 'help', 'service', 'care', 'customerservice', 'client', 'clients', 'orders', 'shop'
)
LOW_PRIORITY_PREFIXES = (
    'privacy', 'legal', 'datenschutz', 'dpo', 'compliance', 'gdpr',
    'billing', 'invoice', 'invoices', 'accounting', 'finance',
    'jobs', 'careers', 'hr', 'recruiting', 'security', 'copyright', 'dmca'
)

# Контекстні маркери для B2B vs Роздрібних телефонів (UA, EN, DE, PL)
B2B_PHONE_KEYWORDS = (
    'опт', 'гурт', 'гуртов', 'співпрац', 'партнер', 'корпоратив', 'b2b',
    'wholesale', 'commercial', 'corporate', 'sales', 'business', 'office',
    'офіс', 'відділ продажу', 'закупів', 'дилер', 'hurt', 'buro'
)
RETAIL_PHONE_KEYWORDS = (
    'роздріб', 'роздрібн', ' інтернет-магазин', 'шоурум', 'retail', 'store', 'shop', 'showroom'
)

PRIMARY_CONTACT_KEYWORDS = (
    'contact', 'kontakt', 'impressum', 'contatti', 'contacto',
    'get-in-touch', 'contact-information'
)
SECONDARY_CONTACT_KEYWORDS = (
    'about', 'uber-uns', 'ueber-uns', 'team', 'company', 'support', 'help', 'faq', 'wholesale', 'b2b'
)

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

# Заборонені сегменти URL соцмереж (каталоги партнерів, шаринг, службові сторінки)
SOCIAL_BAD_SEGMENTS = {
    'sharer', 'sharer.php', 'share', 'intent', 'plugins', 'status', 'posts',
    'photos', 'videos', 'tr', 'dialog', 'p', 'reel', 'reels', 'stories',
    'explore', 'watch', 'groups', 'events', 'marketplace', 'gaming',
    'business', 'partner-directory', 'ads', 'help', 'policies', 'privacy',
    'legal', 'login', 'signin', 'signup', 'hashtag', 'search', 'discover', 'about'
}


def prepare_domains(raw_domains: list[str]) -> list[tuple[str, str]]:
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
    try:
        r = int(encoded_str[:2], 16)
        return ''.join(
            chr(int(encoded_str[i:i + 2], 16) ^ r)
            for i in range(2, len(encoded_str), 2)
        )
    except Exception:
        return ''


def classify_email_type(email: str | None) -> str | None:
    """Визначає призначення контактної пошти для CRM та відділу продажу."""
    if not email or '@' not in email:
        return None
    local = email.split('@', 1)[0].lower()
    clean_local = re.split(r'[._+-]', local)[0]

    if local.startswith(LOW_PRIORITY_PREFIXES) or clean_local in LOW_PRIORITY_PREFIXES:
        return 'legal_or_hr'
    if local.startswith(PR_MEDIA_PREFIXES) or clean_local in PR_MEDIA_PREFIXES:
        return 'pr_and_media'
    if local.startswith(SUPPORT_PREFIXES) or clean_local in SUPPORT_PREFIXES:
        return 'customer_support'
    if local.startswith(SALES_PREFIXES) or clean_local in SALES_PREFIXES:
        return 'sales_or_general'
    return 'direct_or_corporate'


def rank_and_clean_emails(raw_emails: set[str], base_domain: str) -> list[str]:
    """Жорстко відсікає тестові/сміттєві пошти та ранжує реальні контакти за B2B-цінністю."""
    valid = set()
    for email in raw_emails:
        email = email.lower().strip('.,;:()[]"\'<> \t\r\n')
        email = re.sub(r'^(?:%20|u003[ce]|3a)+', '', email)

        if any(email.endswith(ext) for ext in JUNK_EXTENSIONS):
            continue
        if '@' not in email:
            continue

        local_part, domain_part = email.split('@', 1)
        if not local_part or not domain_part or '.' not in domain_part:
            continue

        # Відсікаємо сміттєві домени та тестові заглушки (наприклад, test@test.com)
        domain_root = domain_part.split('.')[0]
        clean_local = re.sub(r'[0-9._+-]+$', '', local_part)

        if domain_part in JUNK_EMAIL_DOMAINS and base_domain != domain_part:
            continue
        if local_part in JUNK_EMAIL_LOCALS or clean_local in JUNK_EMAIL_LOCALS:
            continue
        if local_part == domain_root and domain_part != base_domain:
            continue

        if 6 <= len(email) <= 60:
            valid.add(email)

    def email_score(addr: str) -> tuple[int, str]:
        local, domain = addr.split('@', 1)
        score = 0

        if base_domain and (domain == base_domain or domain.endswith(f'.{base_domain}')):
            score += 25

        email_type = classify_email_type(addr)
        if email_type == 'sales_or_general':
            score += 20
        elif email_type == 'direct_or_corporate':
            score += 15
        elif email_type == 'customer_support':
            score += 8
        elif email_type == 'pr_and_media':
            score += 5
        elif email_type == 'legal_or_hr':
            score -= 35

        return (-score, addr)

    return sorted(valid, key=email_score)


def clean_and_validate_social_url(platform: str, href: str) -> str | None:
    """Перевіряє, що посилання веде на реальний профіль компанії, а не каталог партнерів чи шаринг."""
    try:
        parsed = urlparse(href.strip())
    except Exception:
        return None

    if parsed.scheme not in ('http', 'https'):
        return None

    host = parsed.netloc.lower()
    if host.startswith('www.'):
        host = host[4:]
    if host.startswith('m.'):
        host = host[2:]

    segments = [s for s in parsed.path.split('/') if s]
    if not segments:
        return None

    segments_lower = [s.lower() for s in segments]
    if any(seg in SOCIAL_BAD_SEGMENTS for seg in segments_lower):
        return None

    if platform == 'facebook':
        if host not in ('facebook.com', 'fb.com'):
            return None
        if segments_lower[0] == 'profile.php':
            return None
        return f'https://www.facebook.com/{segments[0]}'

    if platform == 'instagram':
        if host != 'instagram.com':
            return None
        return f'https://www.instagram.com/{segments[0]}'

    if platform == 'linkedin':
        if not host.endswith('linkedin.com') or len(segments) < 2:
            return None
        if segments_lower[0] not in ('company', 'in', 'school'):
            return None
        return f'https://www.linkedin.com/{segments_lower[0]}/{segments[1]}'

    if platform == 'tiktok':
        if host != 'tiktok.com' or not segments[0].startswith('@'):
            return None
        return f'https://www.tiktok.com/{segments[0]}'

    if platform == 'telegram':
        if host not in ('t.me', 'telegram.me') or segments_lower[0] in ('share', 'joinchat', 'addstickers'):
            return None
        return f'https://t.me/{segments[0]}'

    if platform == 'youtube':
        if host != 'youtube.com':
            return None
        if segments[0].startswith('@'):
            return f'https://www.youtube.com/{segments[0]}'
        if segments_lower[0] in ('c', 'channel', 'user') and len(segments) >= 2:
            return f'https://www.youtube.com/{segments_lower[0]}/{segments[1]}'
        return None

    if platform == 'twitter':
        if host not in ('twitter.com', 'x.com'):
            return None
        return f'https://x.com/{segments[0]}'

    return None


def score_phone_context(context_text: str) -> int:
    """Оцінює текст навколо номера: підвищує пріоритет B2B/гуртових номерів над роздрібними."""
    ctx = context_text.lower()
    score = 0
    if any(k in ctx for k in B2B_PHONE_KEYWORDS):
        score += 25
    if any(k in ctx for k in RETAIL_PHONE_KEYWORDS):
        score -= 10
    return score


def extract_valid_phones(
    text: str,
    raw_tel_candidates: list[tuple[str, str]],
    default_region: str
) -> list[str]:
    """Валідує номери у форматі E.164 та сортує їх за B2B-релевантністю."""
    phone_scores: dict[str, int] = {}
    phone_order: dict[str, int] = {}
    order_counter = 0

    for raw_tel, context in raw_tel_candidates:
        try:
            parsed = phonenumbers.parse(raw_tel, default_region)
            if phonenumbers.is_valid_number(parsed):
                formatted = phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                )
                ctx_score = 10 + score_phone_context(context)
                if formatted not in phone_scores or ctx_score > phone_scores[formatted]:
                    phone_scores[formatted] = ctx_score
                if formatted not in phone_order:
                    phone_order[formatted] = order_counter
                    order_counter += 1
        except phonenumbers.NumberParseException:
            continue

    for match in phonenumbers.PhoneNumberMatcher(text, default_region):
        if phonenumbers.is_valid_number(match.number):
            formatted = phonenumbers.format_number(
                match.number, phonenumbers.PhoneNumberFormat.E164
            )
            start_idx = max(0, match.start - 90)
            end_idx = min(len(text), match.end + 90)
            context = text[start_idx:end_idx]
            ctx_score = score_phone_context(context)

            if formatted not in phone_scores or ctx_score > phone_scores[formatted]:
                phone_scores[formatted] = ctx_score
            if formatted not in phone_order:
                phone_order[formatted] = order_counter
                order_counter += 1

    sorted_phones = sorted(
        phone_scores.keys(),
        key=lambda p: (-phone_scores[p], phone_order[p])
    )
    return sorted_phones[:10]


def detect_tech_and_pixels(combined_source: str, gtm_ids: list[str]) -> dict:
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


def generate_sales_signal(tech_info: dict, best_email: str | None, primary_phone: str | None) -> str:
    """Формує готовий комерційний інсайт для відділу продажу на основі знайдених пікселів."""
    ad_pixels = []
    if tech_info.get('has_meta_pixel'):
        ad_pixels.append('Meta')
    if tech_info.get('has_google_ads'):
        ad_pixels.append('Google Ads')
    if tech_info.get('has_tiktok_pixel'):
        ad_pixels.append('TikTok')
    if tech_info.get('has_linkedin_pixel'):
        ad_pixels.append('LinkedIn')

    has_analytics = bool(tech_info.get('has_ga4') or tech_info.get('has_gtm'))
    has_contacts = bool(best_email or primary_phone)

    if len(ad_pixels) >= 2:
        signal = f"High Ad Spend ({' + '.join(ad_pixels)})"
    elif len(ad_pixels) == 1:
        if not has_analytics:
            signal = f"Running {ad_pixels[0]} Ads without GA4/GTM (Analytics Setup Pitch)"
        else:
            signal = f"Active {ad_pixels[0]} Advertiser (Cross-Channel Upsell)"
    elif has_analytics:
        signal = 'Organic/Analytics Only — No Ad Pixels Detected (Paid Ads Pitch)'
    else:
        signal = 'No Tracking Pixels Detected (Full Digital Marketing Pitch)'

    if not has_contacts:
        signal += ' [No Direct Contacts Found]'
    return signal


def parse_html_sync(
    html: str,
    base_url: str,
    default_region: str
) -> tuple[str, str, set[str], list[str], dict[str, str], list[str]]:
    emails = set(EMAIL_REGEX.findall(html))
    raw_tel_candidates: list[tuple[str, str]] = [
        (m, 'schema_json_ld') for m in SCHEMA_PHONE_REGEX.findall(html)
    ]
    socials = {}
    primary_links = set()
    secondary_links = set()

    soup = BeautifulSoup(html, 'lxml')
    base_domain = urlparse(base_url).netloc.lower().replace('www.', '')
    base_clean = base_url.rstrip('/')

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

    for cf_tag in soup.find_all(attrs={'data-cfemail': True}):
        decoded = decode_cf_email(cf_tag['data-cfemail'])
        if decoded and EMAIL_REGEX.match(decoded):
            emails.add(decoded)

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
            parent = a_tag.find_parent(['li', 'p', 'div', 'td', 'section']) or a_tag.parent
            context_str = parent.get_text(' ', strip=True)[:200] if parent else a_tag.get_text(' ', strip=True)
            raw_tel_candidates.append((tel, context_str))
            continue

        for platform in ('linkedin', 'instagram', 'facebook', 'tiktok', 'telegram', 'youtube', 'twitter'):
            if platform not in socials:
                clean_soc = clean_and_validate_social_url(platform, href)
                if clean_soc:
                    socials[platform] = clean_soc

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
    phones = extract_valid_phones(text_content, raw_tel_candidates, default_region)

    ordered_contact_links = sorted(primary_links) + sorted(secondary_links - primary_links)

    return page_title, meta_desc, emails, phones, socials, ordered_contact_links


async def fetch_html_safely(
    client: AsyncSession,
    url: str,
    timeout: float = 15.0,
    retries: int = 2
) -> tuple[int, str, str, str]:
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
    # При помилці або HTTP 403 прапорці технологій повертають None (unknown), а не False
    empty_result = {
        'input_domain': domain_key,
        'website_url': root_url,
        'status': 'error',
        'error_message': '',
        'sales_signal': 'Blocked or Unreachable (Enable Proxy to Retry)',
        'page_title': None,
        'meta_description': None,
        'best_email': None,
        'best_email_type': None,
        'primary_phone': None,
        'linkedin_url': None,
        'instagram_url': None,
        'facebook_url': None,
        'has_meta_pixel': None,
        'has_tiktok_pixel': None,
        'has_google_ads': None,
        'has_linkedin_pixel': None,
        'has_ga4': None,
        'has_gtm': None,
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

        page_title, meta_desc, emails, phones_list, socials, contact_links = await asyncio.to_thread(
            parse_html_sync, html, final_url, default_region
        )

        if unpack_gtm:
            gtm_ids, gtm_js = await fetch_gtm_scripts(client, html)
        else:
            gtm_ids = sorted({m.upper() for m in GTM_ID_REGEX.findall(html)})
            gtm_js = ''

        tech_info = detect_tech_and_pixels(f'{html}\n{gtm_js}', gtm_ids)

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
                    # Контакти зі спеціалізованої сторінки /contact мають високу цінність
                    for p in sub_p:
                        if p not in phones_list:
                            phones_list.append(p)
                    for k, v in sub_s.items():
                        socials.setdefault(k, v)

        base_domain = urlparse(final_url).netloc.lower().replace('www.', '')
        ranked_emails = rank_and_clean_emails(emails, base_domain)
        final_phones = phones_list[:10]

        best_email = ranked_emails[0] if ranked_emails else None
        best_email_type = classify_email_type(best_email)
        primary_phone = final_phones[0] if final_phones else None
        sales_signal = generate_sales_signal(tech_info, best_email, primary_phone)

        return {
            'input_domain': domain_key,
            'website_url': final_url,
            'status': 'success',
            'error_message': '',
            'sales_signal': sales_signal,
            'page_title': page_title,
            'meta_description': meta_desc,
            'best_email': best_email,
            'best_email_type': best_email_type,
            'primary_phone': primary_phone,
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

        headers = {
            'Accept-Language': 'en-US,en;q=0.9,uk;q=0.8',
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
                    f"Email: {result['best_email'] or '-'} ({result['best_email_type'] or '-'}) | "
                    f"Phone: {result['primary_phone'] or '-'} | "
                    f"Signal: {result['sales_signal']}"
                )

                if len(batch) >= batch_size:
                    await Actor.push_data(batch)
                    batch.clear()

            if batch:
                await Actor.push_data(batch)


if __name__ == '__main__':
    asyncio.run(main())
