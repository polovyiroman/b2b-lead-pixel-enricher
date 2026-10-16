import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import html as html_lib
import json
import re
import textwrap
from urllib.parse import urljoin, urlparse
from curl_cffi.requests import AsyncSession
import phonenumbers
from bs4 import BeautifulSoup
from apify import Actor

MAX_HTML_BYTES = 1_500_000
CACHE_SCHEMA_VERSION = 2

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
SCHEMA_PHONE_REGEX = re.compile(r'"telephone"\s*:\s*"([^"]{7,30})"', re.IGNORECASE)

GTM_ID_REGEX = re.compile(r'\bGTM-[A-Z0-9]{5,10}\b', re.IGNORECASE)
GA4_ID_REGEX = re.compile(r'\bG-(?=[A-Z0-9]*\d)[A-Z0-9]{6,12}\b')
GTAG_CONFIG_GA4_REGEX = re.compile(
    r"gtag\(\s*['\"]config['\"]\s*,\s*['\"](G-(?=[A-Z0-9]*\d)[A-Z0-9]{6,12})['\"]",
    re.IGNORECASE
)
GOOGLE_ADS_REGEX = re.compile(r'\bAW-\d{6,12}\b')

SOFT_404_TITLE_REGEX = re.compile(
    r'^\s*(?:404|error\s*404|page\s*not\s*found|not\s*found|'
    r'сторінк[уа]\s+не\s+знайдено|сторінка\s+не\s+знайдена|помилка\s*404)'
    r'(?:\s*[\|\-–—:!.]|\s*$)',
    re.IGNORECASE
)

# П.1: Строго юридичні сторінки без бізнес-контенту; оферти та послуги тепер дозволені!
DM_SOURCE_BLACKLIST = re.compile(
    r'/(?:privacy|policy|datenschutz|gdpr|cookie|dmca)\b',
    re.IGNORECASE
)
DM_LEGAL_SOURCE_FLAG = re.compile(
    r'/(?:oferta|offer|publichna|publichnaja|terms|dogovir|ugoda|conditions)\b',
    re.IGNORECASE
)

GTM_FALSE_POSITIVES = {
    'GTM-PAGE', 'GTM-SUITE', 'GTM-SECTION', 'GTM-WRAPPER', 'GTM-HEADER',
    'GTM-FOOTER', 'GTM-BUTTON', 'GTM-CLICK', 'GTM-EVENT', 'GTM-LOADER',
    'GTM-SCRIPT', 'GTM-DATA', 'GTM-CONTAINER', 'GTM-BLOCK', 'GTM-FORM',
    'GTM-MODAL', 'GTM-BANNER', 'GTM-SLIDER', 'GTM-MENU', 'GTM-NAV',
    'GTM-TRACK', 'GTM-NOSCRIPT', 'GTM-IFRAME', 'GTM-CUSTOM', 'GTM-CONFIG'
}

ROLES_REGEX_PART = (
    r'(?:CEO|Founder|Co-Founder|Owner|CMO|Chief Marketing Officer|Head of Marketing|'
    r'Marketing Director|Head of E-commerce|E-commerce Director|Head of Growth|'
    r'Head of Digital|Commercial Director|Managing Partner|General Manager|President|'
    r'Засновник|Засновниця|Співзасновник|Співзасновниця|Співзасновники|Власник|Власниця|'
    r'Генеральний директор|Директор з маркетингу|Керівник відділу маркетингу|'
    r'Маркетинг-директор|Комерційний директор|Керівник з розвитку|Директорка|Директор)'
)
NAME_REGEX_PART = (
    r'([A-ZА-ЯІЇЄҐ][a-zа-яіїєґ\’\'-]{2,20}'
    r'(?:\s+[A-ZА-ЯІЇЄҐ][a-zа-яіїєґ\’\'-]{2,25}){1,2})'
)

NAME_BEFORE_ROLE_PATTERN = re.compile(
    rf'\b{NAME_REGEX_PART}[\s,—–\-:|()•]{{1,25}}\b({ROLES_REGEX_PART})\b',
    re.UNICODE
)
ROLE_BEFORE_NAME_PATTERN = re.compile(
    rf'\b({ROLES_REGEX_PART})\b(?:\s+[a-zа-яіїєґA-ZА-ЯІЇЄҐ\’\'-]{{2,20}}){{0,3}}[\s,—–\-:|()•]{{1,20}}{NAME_REGEX_PART}\b',
    re.UNICODE
)
FOP_OWNER_PATTERN = re.compile(
    r'(?:ФОП|Фізична особа[\s-]підприємець)\s+'
    r'([A-ZА-ЯІЇЄҐ][a-zа-яіїєґ\’\'-]{2,25}\s+[A-ZА-ЯІЇЄҐ][a-zа-яіїєґ\’\'-]{2,20})',
    re.UNICODE
)

STOP_NAME_WORDS = {
    'Інтернет', 'Магазин', 'Онлайн', 'Бренд', 'Компанія', 'Агентство', 'Агенція',
    'Політика', 'Конфіденційності', 'Умови', 'Доставка', 'Оплата', 'Контакти',
    'Кабінет', 'Каталог', 'Колекція', 'Україна', 'Київ', 'Львів', 'Privacy',
    'Policy', 'Terms', 'Conditions', 'Customer', 'Service', 'Support', 'Contact',
    'About', 'Company', 'Digital', 'Marketing', 'Agency', 'Online', 'Store',
    'LinkedIn', 'Profile', 'View', 'Український', 'Перший', 'Жіночий', 'Official',
    'Наші', 'Ваші', 'Нова', 'Повна', 'Більше', 'Меню', 'Головна', 'Сторінка',
    'Публічна', 'Оферта', 'Договір', 'Персональних', 'Даних', 'Захисту', 'Права'
}

UA_TO_LATIN = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'h', 'ґ': 'g', 'д': 'd', 'е': 'e',
    'є': 'ye', 'ж': 'zh', 'з': 'z', 'и': 'y', 'і': 'i', 'ї': 'yi', 'й': 'y',
    'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r',
    'с': 's', 'т': 't', 'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch',
    'ш': 'sh', 'щ': 'shch', 'ь': '', 'ю': 'yu', 'я': 'ya', '\'': '', '’': ''
}

JUNK_EMAIL_DOMAINS = {
    'sentry.io', 'wixpress.com', 'example.com', 'domain.com', 'test.com',
    'email.com', 'yoursite.com', 'yourdomain.com', 'company.com', 'website.com',
    'sentry.wixpress.com', 'godaddy.com', 'sentry-next.wixpress.com',
    'wordpress.org', 'w3.org', 'schema.org', 'googleusercontent.com',
    'cloudflare.com', 'shopify.com', 'mysite.com', 'sample.com', 'mail.ru',
    'atlassian.net', 'janesbakery.com'
}

PUBLIC_WEBMAIL_DOMAINS = {
    'gmail.com', 'ukr.net', 'icloud.com', 'outlook.com', 'hotmail.com',
    'yahoo.com', 'proton.me', 'protonmail.com'
}

INVALID_EMAIL_TLDS = {
    'official', 'page', 'button', 'wrapper', 'container', 'png', 'jpg',
    'jpeg', 'svg', 'webp', 'js', 'css', 'html', 'php', 'json'
}

EU_GDPR_TLDS = (
    '.eu', '.de', '.fr', '.it', '.es', '.nl', '.pl', '.at', '.be', '.se',
    '.dk', '.fi', '.ie', '.pt', '.cz', '.ro', '.hu', '.sk', '.bg', '.hr',
    '.lt', '.lv', '.ee', '.si', '.lu', '.mt', '.cy', '.gr'
)

JUNK_EMAIL_LOCALS = {
    'test', 'testing', 'example', 'user', 'username', 'name', 'firstname',
    'lastname', 'yourname', 'youremail', 'email', 'mail', 'sample', 'demo',
    'foo', 'bar', 'admin', 'root', 'webmaster', 'postmaster', 'hostmaster',
    'abuse', 'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'mailer-daemon',
    'xxx', 'abc', '123', 'null', 'none', 'undefined', 'u002f', 'u003e', 'u003c', 'jira'
}

JUNK_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.avif',
    '.js', '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
    '.pdf', '.zip', '.rar', '.xml', '.json', '.docx', '.xlsx'
)

MARKETING_EXEC_PREFIXES = (
    'marketing', 'cmo', 'digital', 'growth', 'ecommerce', 'e-commerce',
    'performance', 'ppc', 'seo', 'analytics', 'ceo', 'founder', 'owner'
)
B2B_PARTNERSHIP_PREFIXES = (
    'partner', 'partners', 'partnerships', 'b2b', 'bizdev', 'bd', 'commercial',
    'corporate', 'corpcom', 'deals', 'tender', 'tenders'
)
WHOLESALE_MERCH_PREFIXES = (
    'wholesale', 'opt', 'orders', 'sales', 'sale', 'supply', 'procurement', 'buyer'
)
GENERAL_OFFICE_PREFIXES = (
    'info', 'contact', 'hello', 'hi', 'office', 'team', 'business',
    'company', 'general', 'mail', 'kontakt', 'hallo', 'welcome', 'inquiries',
    'enquiry', 'reception', 'secretariat', 'admin', 'kans', 'kanc'
)
DEPARTMENT_OR_ADMISSIONS_PREFIXES = (
    'vstup', 'admissions', 'admission', 'dekanat', 'rector', 'rectorate',
    'department', 'faculty', 'edu', 'study', 'courses', 'academy',
    'booking', 'reservation', 'delivery', 'logistics', 'export', 'import'
)
SUPPORT_PREFIXES = (
    'support', 'supportua', 'help', 'service', 'care', 'customerservice',
    'client', 'clients', 'shop', 'store', 'hotline', 'callcenter'
)
PR_MEDIA_PREFIXES = (
    'pr', 'press', 'media', 'comms', 'communications', 'ads', 'collab', 'brand', 'events'
)
LOW_PRIORITY_PREFIXES = (
    'privacy', 'legal', 'notices', 'notice', 'legalnotices', 'datenschutz',
    'dpo', 'compliance', 'gdpr', 'billing', 'invoice', 'invoices',
    'accounting', 'finance', 'jobs', 'careers', 'job', 'hr', 'recruiting',
    'security', 'copyright', 'dmca', 'jira'
)
REGIONAL_BRANCH_LOCALS = {
    'kyiv', 'kiev', 'lviv', 'odesa', 'odessa', 'kharkiv', 'dnipro', 'london', 'ny', 'berlin', 'warsaw'
}

NON_PERSON_TOKENS = (
    set(MARKETING_EXEC_PREFIXES)
    | set(B2B_PARTNERSHIP_PREFIXES)
    | set(WHOLESALE_MERCH_PREFIXES)
    | set(GENERAL_OFFICE_PREFIXES)
    | set(DEPARTMENT_OR_ADMISSIONS_PREFIXES)
    | set(SUPPORT_PREFIXES)
    | set(PR_MEDIA_PREFIXES)
    | set(LOW_PRIORITY_PREFIXES)
    | REGIONAL_BRANCH_LOCALS
    | {'corp', 'department', 'dept', 'official', 'press'}
)

B2B_PHONE_KEYWORDS = (
    'опт', 'гурт', 'гуртов', 'співпрац', 'партнер', 'корпоратив', 'b2b',
    'wholesale', 'commercial', 'corporate', 'sales', 'business', 'office',
    'офіс', 'відділ продажу', 'закупів', 'дилер', 'hurt', 'buro'
)
RETAIL_PHONE_KEYWORDS = (
    'роздріб', 'роздрібн', 'інтернет-магазин', 'шоурум', 'retail', 'store', 'shop', 'showroom'
)

PRIMARY_CONTACT_KEYWORDS = (
    'contact', 'kontakt', 'impressum', 'contatti', 'contacto',
    'get-in-touch', 'contact-information', 'kontakty', 'contacts'
)
SECONDARY_CONTACT_KEYWORDS = (
    'about', 'uber-uns', 'ueber-uns', 'team', 'komanda', 'company', 'leadership',
    'management', 'founders', 'our-story', 'pro-nas', 'o-nas', 'history', 'brand',
    'wholesale', 'b2b', 'investors'
)

AD_AND_ANALYTICS_SIGNATURES = {
    'Meta Pixel': [
        'connect.facebook.net', 'fbevents.js', 'fbq(', 'facebook.com/tr',
        '"facebook pixel"', 'facebook_pixel', 'fb_pixel_id', 'meta pixel'
    ],
    'TikTok Pixel': [
        'analytics.tiktok.com', 'ttq.load', 'ttq.page', 'ttq.track',
        '"tiktok pixel"', 'tiktok_pixel', 'tiktokanalytics'
    ],
    'LinkedIn Insight Tag': [
        'snap.licdn.com', 'li.lms-analytics', '_linkedin_partner_id',
        'linkedin_insight', 'linkedin insight', 'b.licdn.com'
    ],
    'Pinterest Tag': ['s.pinimg.com/ct/core.js', 'pintrk('],
    'Microsoft Clarity': ['clarity.ms/tag/'],
    'Hotjar': ['static.hotjar.com', 'hjsettings'],
    'HubSpot': ['js.hs-scripts.com', 'hs-analytics', 'hbspt.forms'],
    'Intercom': ['widget.intercom.io', 'intercomsettings'],
    'Klaviyo': ['static.klaviyo.com', 'klaviyo.push']
}

CMS_HTML_ONLY_SIGNATURES = {
    'Shopify': ['cdn.shopify.com', 'shopify.theme', 'shopify-digital-wallet'],
    'WooCommerce': [
        'wp-content/plugins/woocommerce', 'woocommerce-layout',
        'wc-cart-fragments', 'class="woocommerce'
    ],
    'WordPress': ['wp-content/themes/', 'wp-includes/js/'],
    'Webflow': ['data-wf-site', 'data-wf-page'],
    'Wix': ['wixstatic.com', 'wix-warmup-data'],
    'Tilda': ['tildacdn.com', 'tilda-blocks'],
    'Squarespace': ['static1.squarespace.com', 'squarespace-cdn.com']
}

COOKIE_CONSENT_MARKERS = (
    'cookiebot', 'onetrust', 'cookiefirst', 'usercentrics', 'complianz', 'cookieyes', 'didomi'
)

SOCIAL_BAD_SEGMENTS = {
    'sharer', 'sharer.php', 'share', 'intent', 'plugins', 'status', 'posts',
    'photos', 'videos', 'tr', 'dialog', 'p', 'reel', 'reels', 'stories',
    'explore', 'watch', 'groups', 'events', 'marketplace', 'gaming',
    'business', 'partner-directory', 'ads', 'help', 'policies', 'privacy',
    'legal', 'login', 'signin', 'signup', 'hashtag', 'search', 'discover', 'about'
}

DNS_MEMORY_CACHE: dict[str, tuple[str | None, bool, str]] = {}


def sanitize_kv_key(domain: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]', '_', domain.lower())


def clean_url_port(url: str | None) -> str | None:
    if not url:
        return None
    return re.sub(r':(?:443|80)(?=/|$)', '', url)


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


def get_clean_canonical_domain(final_url: str, input_domain: str) -> str:
    parsed = urlparse(final_url)
    netloc = re.sub(r':\d+$', '', parsed.netloc.lower().replace('www.', ''))
    if not netloc:
        netloc = input_domain.lower().replace('www.', '')

    parts = netloc.split('.')
    while len(parts) > 2 and parts[0] in ('checkout', 'cart', 'pay', 'secure', 'shop', 'store', 'us', 'eu', 'uk'):
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
    if not email or '@' not in email:
        return None
    local, domain = email.split('@', 1)
    local = local.lower()
    domain = domain.lower()
    domain_root = domain.split('.')[0]
    normalized_local = re.sub(r'[._+-]', '', local)
    tokens = [t for t in re.split(r'[._+-]', local) if t]
    first_token = tokens[0] if tokens else local

    if (
        normalized_local.startswith(B2B_PARTNERSHIP_PREFIXES)
        or local.startswith(B2B_PARTNERSHIP_PREFIXES)
        or first_token in B2B_PARTNERSHIP_PREFIXES
    ):
        return 'b2b_partnerships'
    if (
        normalized_local.startswith(LOW_PRIORITY_PREFIXES)
        or local.startswith(LOW_PRIORITY_PREFIXES)
        or first_token in LOW_PRIORITY_PREFIXES
    ):
        return 'legal_or_hr_inbox'
    if local in REGIONAL_BRANCH_LOCALS or first_token in REGIONAL_BRANCH_LOCALS:
        return 'regional_branch_inbox'
    if (
        normalized_local.startswith(DEPARTMENT_OR_ADMISSIONS_PREFIXES)
        or local.startswith(DEPARTMENT_OR_ADMISSIONS_PREFIXES)
        or first_token in DEPARTMENT_OR_ADMISSIONS_PREFIXES
    ):
        return 'admissions_or_department_inbox'
    if (
        normalized_local.startswith(MARKETING_EXEC_PREFIXES)
        or local.startswith(MARKETING_EXEC_PREFIXES)
        or first_token in MARKETING_EXEC_PREFIXES
    ):
        return 'marketing_or_exec_role'
    if (
        normalized_local.startswith(WHOLESALE_MERCH_PREFIXES)
        or local.startswith(WHOLESALE_MERCH_PREFIXES)
        or first_token in WHOLESALE_MERCH_PREFIXES
    ):
        return 'wholesale_or_sales_inbox'
    if (
        normalized_local.startswith(GENERAL_OFFICE_PREFIXES)
        or local.startswith(GENERAL_OFFICE_PREFIXES)
        or first_token in GENERAL_OFFICE_PREFIXES
    ):
        return 'general_office_inbox'
    if (
        normalized_local.startswith(SUPPORT_PREFIXES)
        or local.startswith(SUPPORT_PREFIXES)
        or first_token in SUPPORT_PREFIXES
    ):
        return 'customer_support_inbox'
    if (
        normalized_local.startswith(PR_MEDIA_PREFIXES)
        or local.startswith(PR_MEDIA_PREFIXES)
        or first_token in PR_MEDIA_PREFIXES
    ):
        return 'pr_and_media_inbox'

    if domain not in PUBLIC_WEBMAIL_DOMAINS and len(tokens) == 2 and all(t.isalpha() for t in tokens):
        if tokens[0] not in NON_PERSON_TOKENS and tokens[1] not in NON_PERSON_TOKENS and tokens[1] != domain_root:
            if (len(tokens[0]) == 1 and len(tokens[1]) >= 3) or (len(tokens[0]) >= 3 and len(tokens[1]) >= 3):
                return 'personal_or_named_inbox'

    return 'department_or_general_inbox'


def transliterate_ua_to_latin(text: str) -> str:
    return ''.join(UA_TO_LATIN.get(ch, ch) for ch in text.lower())


def verify_person_email_match(full_name: str | None, email: str | None) -> bool:
    if not full_name or not email or '@' not in email:
        return False
    local = email.split('@', 1)[0].lower()
    name_parts = [p.strip() for p in full_name.split() if len(p.strip()) >= 2]
    if len(name_parts) < 2:
        return False

    first_lat = transliterate_ua_to_latin(name_parts[0])
    last_lat = transliterate_ua_to_latin(name_parts[-1])
    if len(last_lat) < 3 or not first_lat:
        return False

    first_init = first_lat[0]
    last_prefix = last_lat[:5] if len(last_lat) >= 5 else last_lat

    if len(first_lat) >= 3 and first_lat in local and last_prefix in local:
        return True

    pattern = rf'^(?:{re.escape(first_init)}[._-]?{re.escape(last_prefix)}|{re.escape(last_prefix)}[._-]?{re.escape(first_init)})'
    if re.search(pattern, local):
        return True

    return False


def verify_person_linkedin_match(full_name: str | None, linkedin_url: str | None) -> bool:
    if not full_name or not linkedin_url or '/in/' not in linkedin_url.lower():
        return False
    slug = linkedin_url.lower().split('/in/', 1)[1].split('/')[0].split('?')[0]
    name_parts = [p.strip() for p in full_name.split() if len(p.strip()) >= 2]
    if len(name_parts) < 2:
        return False

    first_lat = transliterate_ua_to_latin(name_parts[0])
    last_lat = transliterate_ua_to_latin(name_parts[-1])

    has_last = len(last_lat) >= 4 and last_lat[:4] in slug
    has_first = len(first_lat) >= 3 and first_lat[:3] in slug
    return has_last and has_first


async def verify_email_deliverability_deep(
    client: AsyncSession,
    email: str | None,
    source_url: str | None
) -> str | None:
    """П.2: Реєструє реальний DoH MX-lookup для всіх доменів без мізлідінгу MX_active."""
    if not email or '@' not in email:
        return None
    domain = email.split('@', 1)[1].strip().lower()
    is_public_webmail = domain in PUBLIC_WEBMAIL_DOMAINS

    if domain in DNS_MEMORY_CACHE:
        provider, has_spf, err_code = DNS_MEMORY_CACHE[domain]
    else:
        provider = None
        has_spf = False
        mx_data, err_code = await query_doh_json(client, domain, 'MX')
        if mx_data is not None:
            answers = mx_data.get('Answer', [])
            mx_hosts = [str(ans.get('data', '')).lower() for ans in answers if ans.get('type'] == 15]
            if mx_hosts:
                joined_mx = ' '.join(mx_hosts)
                if 'google.com' in joined_mx or 'googlemail.com' in joined_mx:
                    provider = 'Google' if is_public_webmail else 'Google Workspace'
                elif 'outlook.com' in joined_mx or 'protection.outlook.com' in joined_mx:
                    provider = 'Microsoft' if is_public_webmail else 'Microsoft 365'
                elif 'zoho.' in joined_mx:
                    provider = 'Zoho Mail'
                elif 'protonmail.' in joined_mx:
                    provider = 'ProtonMail'
                elif 'ukr.net' in joined_mx:
                    provider = 'Ukr.net'
                else:
                    provider = mx_hosts[0].split()[-1].rstrip('.')
            else:
                err_code = 'dns_no_mx_records'

            txt_data, _ = await query_doh_json(client, domain, 'TXT')
            if txt_data is not None:
                txt_ans = [str(a.get('data', '')).lower() for a in txt_data.get('Answer', [])]
                has_spf = any('v=spf1' in t for t in txt_ans)

        DNS_MEMORY_CACHE[domain] = (provider, has_spf, err_code)

    if provider:
        spf_tag = 'SPF_present' if has_spf else 'SPF_missing'
        src_tag = 'published_in_site_html' if source_url else 'extracted'
        if is_public_webmail:
            return f'public_webmail_domain ({domain}; MX_found={provider}; {spf_tag}; {src_tag}; mailbox_unverified_by_smtp)'
        return f'domain_accepts_email ({provider}; MX_found; {spf_tag}; {src_tag})'

    if err_code == 'dns_no_mx_records':
        return 'invalid_no_mx_records (domain_cannot_receive_email)'
    return f'{err_code} (lookup_failed)'


def rank_and_clean_emails(
    email_sources: dict[str, str],
    base_domain: str
) -> list[tuple[str, str]]:
    valid: dict[str, str] = {}
    base_brand = base_domain.split('.')[0].lower() if base_domain else ''

    for raw_email, source_url in email_sources.items():
        email = raw_email.lower().strip('.,;:()[]"\'<> \t\r\n')
        email = re.sub(r'^(?:%20|u002[0-9a-f]|u003[0-9a-f]|3a|2f)+', '', email)

        if any(email.endswith(ext) for ext in JUNK_EXTENSIONS):
            continue
        if '@' not in email:
            continue

        local_part, domain_part = email.split('@', 1)
        if not local_part or not domain_part or '.' not in domain_part:
            continue

        tld = domain_part.rsplit('.', 1)[-1].lower()
        if tld in INVALID_EMAIL_TLDS or len(tld) < 2 or not tld.isalpha():
            continue

        domain_root = domain_part.split('.')[0]
        clean_local = re.sub(r'[0-9._+-]+$', '', local_part)

        if domain_part in JUNK_EMAIL_DOMAINS and base_domain not in domain_part:
            continue
        if local_part in JUNK_EMAIL_LOCALS or clean_local in JUNK_EMAIL_LOCALS:
            continue
        if local_part == domain_root and domain_part != base_domain:
            continue

        if 6 <= len(email) <= 60 and email not in valid:
            valid[email] = clean_url_port(source_url) or source_url

    has_native_brand_email = any(
        base_brand and (
            dom == base_domain
            or dom.endswith(f'.{base_domain}')
            or dom.split('.')[0] == base_brand
        )
        for addr in valid
        for _, dom in [addr.split('@', 1)]
    )

    if has_native_brand_email:
        filtered_valid = {}
        for addr, src in valid.items():
            _, dom = addr.split('@', 1)
            is_native = (
                dom == base_domain
                or dom.endswith(f'.{base_domain}')
                or dom.split('.')[0] == base_brand
                or dom in PUBLIC_WEBMAIL_DOMAINS
            )
            if is_native:
                filtered_valid[addr] = src
        if filtered_valid:
            valid = filtered_valid

    type_weights = {
        'marketing_or_exec_role': 35,
        'personal_or_named_inbox': 32,
        'b2b_partnerships': 28,
        'general_office_inbox': 24,
        'wholesale_or_sales_inbox': 18,
        'department_or_general_inbox': 15,
        'regional_branch_inbox': 14,
        'admissions_or_department_inbox': 10,
        'customer_support_inbox': 8,
        'pr_and_media_inbox': 5,
        'legal_or_hr_inbox': -40
    }

    def email_score(addr: str) -> tuple[int, str]:
        _, domain = addr.split('@', 1)
        score = 0
        if base_domain and (domain == base_domain or domain.endswith(f'.{base_domain}')):
            score += 25
        elif base_brand and domain.split('.')[0] == base_brand:
            score += 20
        email_type = classify_email_type(addr)
        score += type_weights.get(email_type or '', 0)
        return (-score, addr)

    sorted_addrs = sorted(valid.keys(), key=email_score)
    return [(addr, valid[addr]) for addr in sorted_addrs]


def clean_and_validate_social_url(platform: str, href: str) -> str | None:
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
        if host not in ('facebook.com', 'fb.com') or segments_lower[0] == 'profile.php':
            return None
        return f'https://www.facebook.com/{segments[0]}'

    if platform == 'instagram':
        if host != 'instagram.com':
            return None
        return f'https://www.instagram.com/{segments[0]}'

    if platform == 'linkedin':
        if not host.endswith('linkedin.com') or len(segments) < 2:
            return None
        if segments_lower[0] not in ('company', 'school'):
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


def pick_best_social_candidate(
    candidates: list[tuple[str, str]],
    brand_root: str
) -> tuple[str | None, str | None]:
    if not candidates:
        return None, None
    brand_low = brand_root.lower()
    for url, src in candidates:
        if brand_low and brand_low in url.lower():
            return url, clean_url_port(src) or src
    return candidates[0][0], clean_url_port(candidates[0][1]) or candidates[0][1]


def score_phone_context(context_text: str) -> int:
    ctx = context_text.lower()
    score = 0
    if any(k in ctx for k in B2B_PHONE_KEYWORDS):
        score += 25
    if any(k in ctx for k in RETAIL_PHONE_KEYWORDS):
        score -= 10
    return score


def is_junk_phone(e164: str) -> bool:
    """П.5: Відсікає номери-заглушки на кшталт +380441234567."""
    digits = re.sub(r'\D', '', e164)
    if not digits:
        return True
    if re.search(r'(?:1234567|123456|1111111|0000000|9999999)$', digits):
        return True
    if len(set(digits)) <= 2 and len(digits) >= 6:
        return True
    return False


def extract_valid_phones(
    text: str,
    raw_tel_candidates: list[tuple[str, str]],
    default_region: str
) -> list[tuple[str, int]]:
    phone_scores: dict[str, int] = {}
    phone_order: dict[str, int] = {}
    order_counter = 0

    for raw_tel, context in raw_tel_candidates:
        try:
            parsed = phonenumbers.parse(raw_tel, default_region)
            if phonenumbers.is_valid_number(parsed):
                formatted = phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                )
                if is_junk_phone(phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)):
                    continue
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
                match.number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            e164_chk = phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164)
            if is_junk_phone(e164_chk):
                continue
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
    return [(p, phone_scores[p]) for p in sorted_phones[:10]]


def detect_tech_with_evidence(
    html: str,
    gtm_js: str,
    gtm_ids: list[str],
    page_url: str
) -> dict:
    """П.3: Стабільний вибір GA4 ID через GTAG_CONFIG_GA4_REGEX у GTM JS та HTML."""
    clean_gtm = gtm_js.replace('\\/', '/')
    html_lower = html.lower().replace('\\/', '/')
    gtm_lower = clean_gtm.lower()
    clean_page_url = clean_url_port(page_url) or page_url

    detected = []
    evidence_items = []

    has_cookie_banner = any(cm in html_lower for cm in COOKIE_CONSENT_MARKERS)

    has_gtm = bool(gtm_ids) or 'googletagmanager.com/gtm.js' in html_lower
    if has_gtm:
        detected.append('Google Tag Manager')
        ev_str = f"GTM ({', '.join(gtm_ids)})" if gtm_ids else 'GTM (gtm.js)'
        evidence_items.append(f'{ev_str} [Direct HTML] on {clean_page_url}')

    ga4_cfg_html = [m.upper() for m in GTAG_CONFIG_GA4_REGEX.findall(html)]
    ga4_cfg_gtm = [m.upper() for m in GTAG_CONFIG_GA4_REGEX.findall(clean_gtm)]
    ga4_in_html = ga4_cfg_html or [m.upper() for m in GA4_ID_REGEX.findall(html)]
    ga4_in_gtm = ga4_cfg_gtm or [m.upper() for m in GA4_ID_REGEX.findall(clean_gtm)]

    has_ga4 = (
        bool(ga4_in_html or ga4_in_gtm)
        or 'google-analytics.com/g/collect' in html_lower
        or 'google-analytics.com/g/collect' in gtm_lower
    )
    if has_ga4:
        detected.append('Google Analytics (GA4)')
        if ga4_in_html:
            evidence_items.append(f'GA4 ({ga4_in_html[0]} in Direct HTML)')
        elif ga4_in_gtm:
            evidence_items.append(f'GA4 ({ga4_in_gtm[0]} in GTM Container)')
        else:
            evidence_items.append('GA4 (g/collect endpoint)')

    aw_in_html = [m.upper() for m in GOOGLE_ADS_REGEX.findall(html)]
    aw_in_gtm = [m.upper() for m in GOOGLE_ADS_REGEX.findall(clean_gtm)]
    has_google_ads = (
        bool(aw_in_html or aw_in_gtm)
        or 'googleadservices.com/pagead/conversion' in html_lower
        or 'googleadservices.com/pagead/conversion' in gtm_lower
    )
    if has_google_ads:
        detected.append('Google Ads Conversion')
        if aw_in_html:
            evidence_items.append(f'Google Ads ({aw_in_html[0]} in Direct HTML)')
        elif aw_in_gtm:
            evidence_items.append(f'Google Ads ({aw_in_gtm[0]} in GTM Container)')
        else:
            evidence_items.append('Google Ads (pagead/conversion script)')

    for name, markers in AD_AND_ANALYTICS_SIGNATURES.items():
        matched_in_html = next((m for m in markers if m in html_lower), None)
        matched_in_gtm = next((m for m in markers if m in gtm_lower), None)
        if matched_in_html or matched_in_gtm:
            detected.append(name)
            if matched_in_html:
                evidence_items.append(f"{name} ('{matched_in_html}' in Direct HTML)")
            else:
                evidence_items.append(f"{name} ('{matched_in_gtm}' in GTM Container)")

    for cms_name, cms_markers in CMS_HTML_ONLY_SIGNATURES.items():
        matched_cms = next((m for m in cms_markers if m in html_lower), None)
        if matched_cms:
            detected.append(cms_name)
            evidence_items.append(f"{cms_name} ('{matched_cms}' in Direct HTML)")

    if not evidence_items:
        if has_cookie_banner:
            ev_summary = 'No static tags visible (Consent Mode / Cookie banner detected; tags may fire post-consent)'
        else:
            ev_summary = 'No tracking markers detected in static HTML'
    else:
        ev_summary = ' | '.join(evidence_items)

    all_ga4_list = sorted(list(set(ga4_in_html + ga4_in_gtm)))

    return {
        'has_meta_pixel': 'Meta Pixel' in detected,
        'has_tiktok_pixel': 'TikTok Pixel' in detected,
        'has_google_ads': has_google_ads,
        'has_linkedin_pixel': 'LinkedIn Insight Tag' in detected,
        'has_pinterest_tag': 'Pinterest Tag' in detected,
        'has_hubspot': 'HubSpot' in detected,
        'has_klaviyo': 'Klaviyo' in detected,
        'has_ga4': has_ga4,
        'has_gtm': has_gtm,
        'all_ga4_ids': '; '.join(all_ga4_list) if all_ga4_list else None,
        'detected_technologies_list': detected,
        'technology_evidence': ev_summary
    }


def classify_company_category(
    domain: str,
    page_title: str,
    meta_desc: str,
    detected_tech: list[str],
    html_sample: str = ''
) -> str:
    text = f'{domain} {page_title} {meta_desc}'.lower()
    html_low = html_sample[:15000].lower()

    if domain.endswith(('.edu', '.edu.ua', '.ac.uk', '.gov', '.gov.ua', '.org', '.org.ua')) or any(
        w in text for w in (
            'університет', 'university', 'college', 'академія', 'інститут',
            'благодійний фонд', 'charitable', 'foundation', 'ngo', 'громадська організація'
        )
    ):
        return 'Non-Profit / Education / Institution'

    agency_keywords = (
        'агентство', 'агенція', 'agency', 'digital marketing', 'діджитал-маркетинг',
        'онлайн-маркетинг', 'маркетингова агенція', 'seo agency', 'ppc agency',
        'web studio', 'веб-студія', 'розробка сайтів', 'software development',
        'медіа про інтернет-маркетинг', 'performance marketing agency'
    )
    if any(k in text for k in agency_keywords):
        return 'B2B Agency / Marketing Media'

    ecom_keywords = (
        'інтернет-магазин', 'интернет-магазин', 'онлайн магазин', 'online store',
        'shop', 'купити', 'купить', 'доставка по', 'колекція', 'бренд одягу',
        'бренд взуття', 'жіночого одягу', 'женского белья', 'каталог товарів',
        'checkout', 'add to cart', 'кошик', 'shoes', 'apparel', 'clothing'
    )
    has_product_schema = '"@type":"product"' in html_low or '"@type": "product"' in html_low or 'og:type" content="product"' in html_low
    if any(cms in detected_tech for cms in ('Shopify', 'WooCommerce')) or has_product_schema or any(k in text for k in ecom_keywords):
        return 'E-commerce / Retail Brand'

    saas_keywords = (
        'saas', 'cloud platform', 'crm', 'api', 'b2b software', 'automation platform',
        'майданчик', 'тендер', 'prozorro', 'прозорро', 'закупівлі', 'mobility app'
    )
    if any(k in text for k in saas_keywords):
        return 'SaaS / Marketplace / Tech Platform'

    return 'General Business / Corporate'


def is_valid_person_name(candidate: str) -> bool:
    """П.1: Перевіряє кандидатів на ім'я за допомогою ROLE_TOKEN_BLACKLIST та STOP_NAME_WORDS."""
    words = [w.strip('.,;:()[]"\'') for w in candidate.strip().split() if w.strip('.,;:()[]"\'')]
    if len(words) not in (2, 3):
        return False
    if not all(w and w[0].isupper() and len(w) >= 2 for w in words):
        return False
    if any(w in STOP_NAME_WORDS for w in words):
        return False
    if any(w.lower() in ROLE_TOKEN_BLACKLIST for w in words):
        return False
    if any(re.fullmatch(ROLES_REGEX_PART, w, re.UNICODE) for w in words):
        return False
    return True


def normalize_executive_role(raw_role: str | None) -> str | None:
    if not raw_role:
        return None
    clean = raw_role.strip(' .,;:|-–—')
    return ROLE_NORMALIZATION_MAP.get(clean.lower(), clean)


def extract_decision_maker_deep(
    pages_with_urls: list[tuple[str, str, str]]
) -> tuple[str | None, str | None, str | None, str | None]:
    """
    П.1: Очищує ім'я від рольових префіксів через strip_role_tokens_from_name,
    а також використовує DM_LEGAL_SOURCE_FLAG для маркування юридичних джерел.
    """
    candidate_li_urls = []

    for page_url, html, _ in pages_with_urls:
        soup = BeautifulSoup(html, 'lxml')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            if 'linkedin.com/in/' in href.lower():
                parsed = urlparse(href)
                if parsed.scheme in ('http', 'https'):
                    clean_li = f"https://www.linkedin.com{parsed.path.rstrip('/')}"
                    if clean_li not in candidate_li_urls:
                        candidate_li_urls.append(clean_li)

        for script in soup.find_all('script', type=re.compile(r'ld\+json', re.I)):
            raw_json = script.string
            if not raw_json:
                continue
            try:
                data = json.loads(raw_json)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    for key, default_role in (('founder', 'Founder'), ('founders', 'Founder'), ('employee', 'Executive')):
                        val = item.get(key)
                        if isinstance(val, dict) and val.get('name'):
                            cand = strip_role_tokens_from_name(str(val['name']))
                            role = normalize_executive_role(str(val.get('jobTitle') or default_role))
                            if is_valid_person_name(cand):
                                matched_li = next((u for u in candidate_li_urls if verify_person_linkedin_match(cand, u)), None)
                                src_label = f'{role} (Source: {page_url})'
                                if DM_LEGAL_SOURCE_FLAG.search(urlparse(page_url).path):
                                    src_label += ' [Legal Document/Offer]'
                                return cand, src_label, matched_li, clean_url_port(page_url)
                        elif isinstance(val, list):
                            for sub in val:
                                if isinstance(sub, dict) and sub.get('name'):
                                    cand = strip_role_tokens_from_name(str(sub['name']))
                                    role = normalize_executive_role(str(sub.get('jobTitle') or default_role))
                                    if is_valid_person_name(cand):
                                        matched_li = next((u for u in candidate_li_urls if verify_person_linkedin_match(cand, u)), None)
                                        src_label = f'{role} (Source: {page_url})'
                                        if DM_LEGAL_SOURCE_FLAG.search(urlparse(page_url).path):
                                            src_label += ' [Legal Document/Offer]'
                                        return cand, src_label, matched_li, clean_url_port(page_url)
            except Exception:
                continue

    for page_url, _, page_text in pages_with_urls:
        for m in NAME_BEFORE_ROLE_PATTERN.finditer(page_text):
            cand_name = strip_role_tokens_from_name(m.group(1))
            cand_role = normalize_executive_role(m.group(2))
            if is_valid_person_name(cand_name):
                matched_li = next((u for u in candidate_li_urls if verify_person_linkedin_match(cand_name, u)), None)
                src_label = f'{cand_role} (Source: {page_url})'
                if DM_LEGAL_SOURCE_FLAG.search(urlparse(page_url).path):
                    src_label += ' [Legal Document/Offer]'
                return cand_name, src_label, matched_li, clean_url_port(page_url)

        for m in ROLE_BEFORE_NAME_PATTERN.finditer(page_text):
            cand_role = normalize_executive_role(m.group(1))
            cand_name = strip_role_tokens_from_name(m.group(2))
            if is_valid_person_name(cand_name):
                matched_li = next((u for u in candidate_li_urls if verify_person_linkedin_match(cand_name, u)), None)
                src_label = f'{cand_role} (Source: {page_url})'
                if DM_LEGAL_SOURCE_FLAG.search(urlparse(page_url).path):
                    src_label += ' [Legal Document/Offer]'
                return cand_name, src_label, matched_li, clean_url_port(page_url)

        for m in FOP_OWNER_PATTERN.finditer(page_text):
            cand_name = strip_role_tokens_from_name(m.group(1))
            if is_valid_person_name(cand_name):
                matched_li = next((u for u in candidate_li_urls if verify_person_linkedin_match(cand_name, u)), None)
                src_label = f'Registered Business Owner / ФОП (Source: {page_url})'
                if DM_LEGAL_SOURCE_FLAG.search(urlparse(page_url).path):
                    src_label += ' [Legal Document/Offer]'
                return cand_name, src_label, matched_li, clean_url_port(page_url)

    return None, None, None, None


def strip_role_tokens_from_name(candidate: str) -> str:
    words = [w.strip('.,;:()[]"\'') for w in candidate.strip().split() if w.strip('.,;:()[]"\'')]
    while words and (
        words[0].lower() in ROLE_TOKEN_BLACKLIST
        or re.fullmatch(ROLES_REGEX_PART, words[0], re.UNICODE)
    ):
        words.pop(0)
    while words and (
        words[-1].lower() in ROLE_TOKEN_BLACKLIST
        or re.fullmatch(ROLES_REGEX_PART, words[-1], re.UNICODE)
    ):
        words.pop(-1)
    return ' '.join(words)


def build_linkedin_xray_query(canonical_domain: str, page_title: str | None) -> str:
    brand_root = canonical_domain.split('.')[0].capitalize()
    return (
        f'site:linkedin.com/in ("{canonical_domain}" OR "{brand_root}") '
        f'("CMO" OR "Chief Marketing Officer" OR "Head of Marketing" OR "Marketing Director" '
        f'OR "Head of E-commerce" OR "Founder" OR "CEO")'
    )


def evaluate_qualification_v42(
    company_category: str,
    tech_info: dict,
    best_email: str | None,
    best_email_type: str | None,
    primary_phone: str | None,
    dm_name: str | None,
    dm_role: str | None,
    dm_linkedin_url: str | None,
    linkedin_url: str | None
) -> tuple[str, str, str, str, str, str, str, str, str]:
    ad_tags = []
    if tech_info.get('has_meta_pixel'):
        ad_tags.append('Meta Pixel')
    if tech_info.get('has_google_ads'):
        ad_tags.append('Google Ads Conversion')
    if tech_info.get('has_tiktok_pixel'):
        ad_tags.append('TikTok Pixel')
    if tech_info.get('has_linkedin_pixel'):
        ad_tags.append('LinkedIn Insight Tag')
    if tech_info.get('has_pinterest_tag'):
        ad_tags.append('Pinterest Tag')

    analytics_tags = []
    if tech_info.get('has_ga4'):
        analytics_tags.append('GA4')
    if tech_info.get('has_gtm'):
        analytics_tags.append('GTM')

    detected_list = tech_info.get('detected_technologies_list', [])
    for ux_tool in ('Microsoft Clarity', 'Hotjar', 'HubSpot', 'Klaviyo'):
        if ux_tool in detected_list:
            analytics_tags.append(ux_tool)

    all_signals = ad_tags + analytics_tags
    detected_signals_str = ', '.join(all_signals) if all_signals else 'None detected'

    if company_category == 'E-commerce / Retail Brand':
        icp_fit_tier = 'Tier 1: Target ICP (E-commerce / Retail Brand)'
    elif company_category in ('SaaS / Marketplace / Tech Platform', 'General Business / Corporate'):
        icp_fit_tier = f'Tier 2: Secondary ICP ({company_category})'
    elif company_category == 'B2B Agency / Marketing Media':
        icp_fit_tier = 'Partner / Competitor Segment (Agency / Media — Exclude from Standard Client Outreach)'
    else:
        icp_fit_tier = 'Non-Target ICP (Non-Profit / Education / Institution)'

    if len(ad_tags) >= 2 and analytics_tags:
        tech_signal = (
            f"High Stack Maturity: Multi-pixel ad tracking ({', '.join(ad_tags)}) + {'/'.join(analytics_tags[:2])} "
            "(Verified in HTML/GTM; confirms tracking infrastructure, not current ad spend)"
        )
    elif len(ad_tags) == 1:
        tech_signal = (
            f"Moderate Stack Maturity: Single ad pixel ({ad_tags[0]}) detected "
            "(Secondary tags not found in static HTML/GTM or gated by Cookie Consent)"
        )
    elif analytics_tags:
        tech_signal = (
            f"Basic Analytics Only ({', '.join(analytics_tags)}) — "
            "ad pixels not found in static HTML/GTM (not proof of absence if server-side/consent-gated)"
        )
    else:
        tech_signal = (
            'Low / Unverified Tech Signal: No tracking tags found in static HTML '
            '(Tag absence is not confirmed if site uses strict Cookie Consent or custom JS loader)'
        )

    is_same_person_email = verify_person_email_match(dm_name, best_email)
    is_same_person_li = verify_person_linkedin_match(dm_name, dm_linkedin_url)

    if dm_name and is_same_person_email:
        contact_quality = f'Tier A (Verified Match: {dm_name} + Direct Personal Email)'
        enrichment_status = 'verified_decision_maker_and_matching_email'
        confidence_warning = 'None'
    elif dm_name and is_same_person_li:
        contact_quality = (
            f'Tier A- (Decision-Maker {dm_name} + Name-Matched LinkedIn URL Verified; '
            f'Site Email is {best_email_type or "None"})'
        )
        enrichment_status = 'decision_maker_linkedin_verified_paired_with_site_contact'
        confidence_warning = 'Note: Decision-maker LinkedIn slug matches person name; site email is a company/department inbox.'
    elif dm_name and best_email_type == 'marketing_or_exec_role':
        contact_quality = f'Tier A- (Decision-Maker Found: {dm_name} + Direct Marketing Role Inbox: {best_email})'
        enrichment_status = 'decision_maker_found_plus_marketing_role_inbox'
        confidence_warning = 'Note: Executive identified on site and paired with dedicated marketing@ department inbox.'
    elif dm_name and best_email_type == 'personal_or_named_inbox' and not is_same_person_email:
        contact_quality = (
            f'Tier B+ (Named Staff Inbox {best_email} Found, '
            f'Different from Listed Executive {dm_name})'
        )
        enrichment_status = 'unmatched_executive_and_staff_email'
        confidence_warning = (
            f'Warning: Email {best_email} belongs to a different person than '
            f'the executive found ({dm_name}). Do not address {best_email} as {dm_name}.'
        )
    elif dm_name and best_email_type in ('legal_or_hr_inbox', 'customer_support_inbox', 'pr_and_media_inbox'):
        contact_quality = (
            f'Tier C- (Executive {dm_name} Identified on Site, '
            f'but Email {best_email} is {best_email_type} — Do Not Cold Pitch Email)'
        )
        enrichment_status = 'executive_named_but_only_non_sales_inbox_on_site'
        confidence_warning = (
            f'Warning: {dm_name} found on site, but {best_email} is {best_email_type}. '
            f'Use LinkedIn X-Ray to contact {dm_name} rather than emailing {best_email}.'
        )
    elif dm_name and (best_email or primary_phone):
        contact_quality = f'Tier B (Decision-Maker Found: {dm_name}, Paired with Generic/B2B Inbox)'
        enrichment_status = 'decision_maker_named_separately_from_generic_inbox'
        confidence_warning = 'Warning: Person name verified on site; email is company role/generic inbox (not direct personal email).'
    elif best_email_type in ('personal_or_named_inbox', 'marketing_or_exec_role'):
        contact_quality = f'Tier B+ (Direct / Named Role Inbox: {best_email_type}, Full Name Unlisted)'
        enrichment_status = 'named_or_role_email_found_needs_title_match'
        confidence_warning = 'None'
    elif best_email_type == 'b2b_partnerships':
        contact_quality = 'Tier B (B2B / Corporate Partnership Inbox — Good for B2B Pitch, Needs Referral for Analytics/Tech)'
        enrichment_status = 'b2b_role_inbox_only_needs_linkedin_dm'
        confidence_warning = 'Note: B2B/Corporate inbox is for commercial partnerships; request referral to CMO/Head of Digital.'
    elif best_email_type == 'general_office_inbox':
        contact_quality = 'Tier C (Generic Office Inbox — Suitable for Gatekeeper Routing Only)'
        enrichment_status = 'generic_inbox_only_needs_linkedin_dm'
        confidence_warning = 'None'
    elif best_email_type in ('wholesale_or_sales_inbox', 'regional_branch_inbox', 'department_or_general_inbox', 'admissions_or_department_inbox'):
        contact_quality = f'Tier C- ({best_email_type} — Non-Marketing Department Channel)'
        enrichment_status = 'non_marketing_department_inbox_needs_linkedin_dm'
        confidence_warning = f'Warning: Email belongs to {best_email_type}, not marketing decision-maker.'
    elif best_email_type in ('customer_support_inbox', 'pr_and_media_inbox', 'legal_or_hr_inbox'):
        contact_quality = f'Tier D (Low Sales Fit: {best_email_type} — Do Not Cold Pitch Services Here)'
        enrichment_status = 'support_or_pr_inbox_only_requires_dm_enrichment'
        confidence_warning = f'Warning: Email is {best_email_type}; avoid direct cold sales pitch.'
    elif primary_phone:
        contact_quality = 'Tier D (Phone Only — No Email Found on Public Pages)'
        enrichment_status = 'phone_only_requires_email_and_dm_enrichment'
        confidence_warning = 'Warning: No public email found; phone routing or LinkedIn required.'
    else:
        contact_quality = 'Tier F (No Actionable Contacts Found on Website)'
        enrichment_status = 'no_public_contacts_found'
        confidence_warning = 'Warning: Zero public contacts on site; requires external B2B enrichment.'

    if company_category == 'Non-Profit / Education / Institution':
        readiness_verdict = 'Disqualified (Non-Target Institutional / NGO Segment)'
    elif company_category == 'B2B Agency / Marketing Media':
        readiness_verdict = 'Partner Pipeline Only (Agency / Media Segment)'
    elif dm_name and is_same_person_email:
        readiness_verdict = 'Sales-Ready Tier 1 (Verified Decision-Maker + Matching Direct Email)'
    elif dm_name and is_same_person_li:
        readiness_verdict = f'Sales-Ready via LinkedIn Outbound ({dm_name} Profile Verified + Tech Stack Confirmed)'
    elif best_email_type == 'marketing_or_exec_role':
        readiness_verdict = 'Sales-Ready Tier 2 (Direct Marketing / Executive Role Inbox)'
    elif best_email_type == 'b2b_partnerships':
        readiness_verdict = 'Partnership-Ready Only (B2B Inbox Found — Needs CMO Referral for Analytics/Tech Pitch)'
    elif best_email_type == 'general_office_inbox':
        readiness_verdict = 'Gatekeeper-Ready Only (Generic Office Inbox — Needs DM Lookup for Cold Outbound)'
    else:
        readiness_verdict = 'Tech-Qualified Account Only (Needs LinkedIn DM Enrichment Before Outbound)'

    if company_category == 'B2B Agency / Marketing Media':
        opportunity = (
            'Agency/Media Segment: Explore white-label analytics partnership, '
            'data enrichment API integration, or B2B referral collaboration'
        )
    elif company_category == 'Non-Profit / Education / Institution':
        opportunity = 'Non-commercial / Institutional organization — disqualify from standard B2B sales'
    elif len(ad_tags) >= 2:
        opportunity = (
            f"Hypothesis for discovery audit: company uses multi-channel tracking ({', '.join(ad_tags)}); "
            "offer complimentary tracking/attribution review or CRO benchmark to verify if optimization is needed"
        )
    elif len(ad_tags) == 1:
        opportunity = (
            f"Hypothesis for discovery audit: single ad network ({ad_tags[0]}) visible; "
            "verify paid channel mix and explore cross-channel acquisition or tracking review"
        )
    else:
        opportunity = 'Verify manually if tags are gated by Cookie Consent before proposing GA4/GTM implementation'

    if company_category == 'B2B Agency / Marketing Media':
        next_action = f"Route to Agency Partnership pipeline; reach out via {best_email or linkedin_url or primary_phone}"
    elif company_category == 'Non-Profit / Education / Institution':
        next_action = 'Exclude from commercial B2B cold outreach'
    elif dm_name and is_same_person_li:
        next_action = (
            f"Send personalized LinkedIn message to {dm_name} ({dm_role}) at {dm_linkedin_url} "
            f"referencing detected stack ({detected_signals_str})"
        )
    elif best_email_type in (
        'customer_support_inbox', 'pr_and_media_inbox', 'wholesale_or_sales_inbox',
        'regional_branch_inbox', 'admissions_or_department_inbox', 'legal_or_hr_inbox'
    ):
        next_action = (
            f"DO NOT send marketing pitch to {best_email} ({best_email_type}); "
            f"use decision_maker_search_query on LinkedIn or call {primary_phone or 'company'} to reach Marketing Lead"
        )
    elif best_email_type == 'b2b_partnerships':
        next_action = (
            f"Send partnership/referral inquiry to {best_email} asking for introduction to Head of Marketing/Analytics, "
            f"or locate CMO via decision_maker_search_query"
        )
    elif best_email:
        next_action = (
            f"Send discovery audit intro to {best_email} ({best_email_type}) "
            f"and use decision_maker_search_query to connect with CMO/Head of E-commerce on LinkedIn"
        )
    elif primary_phone:
        next_action = f"Use decision_maker_search_query on LinkedIn or call {primary_phone} for routing"
    else:
        next_action = 'Run decision_maker_search_query in LinkedIn / Apollo to locate marketing decision-maker'

    return (
        readiness_verdict,
        icp_fit_tier,
        tech_signal,
        contact_quality,
        enrichment_status,
        confidence_warning,
        detected_signals_str,
        opportunity,
        next_action
    )


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
    base_domain = re.sub(r':\d+$', '', urlparse(clean_page).netloc.lower().replace('www.', ''))
    brand_root = base_domain.split('.')[0] if base_domain else ''
    base_clean = clean_page.rstrip('/')

    page_title = ''
    if soup.title and soup.title.string:
        raw_title = ' '.join(soup.title.string.split())
        page_title = textwrap.shorten(raw_title, width=150, placeholder='…')

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

        if base_domain and link_domain == base_domain and parsed.scheme in ('http', 'https'):
            normalized_link = clean_url_port(f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}")
            if not normalized_link or normalized_link == base_clean:
                continue

            if any(k in path_lower for k in PRIMARY_CONTACT_KEYWORDS):
                primary_links.add(normalized_link)
            elif any(k in path_lower for k in SECONDARY_CONTACT_KEYWORDS):
                secondary_links.add(normalized_link)

    socials_with_source: dict[str, tuple[str, str]] = {}
    for platform, cand_list in social_candidates.items():
        best_soc, best_src = pick_best_social_candidate(cand_list, brand_root)
        if best_soc and best_src:
            socials_with_source[platform] = (best_soc, best_src)

    text_content = soup.get_text(' ', strip=True)
    for m in EMAIL_REGEX.findall(text_content):
        email_sources.setdefault(m, clean_page)

    scored_phones = extract_valid_phones(text_content, raw_tel_candidates, default_region)
    phones_with_source = [(p, sc, clean_page) for p, sc in scored_phones]

    ordered_contact_links = sorted(primary_links) + sorted(secondary_links - primary_links)

    return page_title, meta_desc, text_content, email_sources, phones_with_source, socials_with_source, ordered_contact_links


async def load_robots_rules(client: AsyncSession, base_root: str) -> tuple[list[str], float]:
    disallowed: list[str] = []
    crawl_delay = 0.25
    try:
        resp = await client.get(f'{base_root}/robots.txt', impersonate='chrome', timeout=3.5)
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
                        crawl_delay = min(max(float(val), 0.25), 2.0)
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
        resp = await client.get(sitemap_url, impersonate='chrome', timeout=5.0)
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
        found_urls = [
            f'{base_root}/contacts',
            f'{base_root}/kontakty',
            f'{base_root}/about',
            f'{base_root}/pro-nas'
        ]
    return found_urls


async def fetch_html_safely(
    client: AsyncSession,
    url: str,
    proxy_config=None,
    timeout: float = 15.0,
    retries: int = 4
) -> tuple[int, str, str, str]:
    last_error = ''
    impersonations = ['chrome', 'safari', 'chrome110', 'chrome']

    for attempt in range(retries):
        imp = impersonations[min(attempt, len(impersonations) - 1)]
        req_headers = {
            'Accept-Language': 'uk-UA,uk;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': 'https://www.google.com.ua/',
            'Upgrade-Insecure-Requests': '1'
        }
        use_proxy = None
        if attempt >= 1 and proxy_config is not None:
            try:
                use_proxy = await proxy_config.new_url(
                    session_id=f"retry_{attempt}_{abs(hash(url)) % 100000}"
                )
            except Exception:
                use_proxy = None

        try:
            async with client.stream(
                'GET',
                url,
                headers=req_headers,
                impersonate=imp,
                proxy=use_proxy,
                timeout=timeout
            ) as resp:
                status = resp.status_code
                final_url = clean_url_port(str(resp.url)) or str(resp.url)

                if status in (403, 429, 502, 503, 504) and attempt < retries - 1:
                    await asyncio.sleep(1.0 * (attempt + 1))
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

    return 0, '', url, last_error or 'Connection failed'


async def fetch_gtm_scripts(
    client: AsyncSession,
    html: str
) -> tuple[list[str], str]:
    gtm_ids = sorted({
        m.upper() for m in GTM_ID_REGEX.findall(html)
        if m.upper() not in GTM_FALSE_POSITIVES
    })
    if not gtm_ids:
        return [], ''

    gtm_contents = []
    for gtm_id in gtm_ids[:5]:
        gtm_url = f'https://www.googletagmanager.com/gtm.js?id={gtm_id}'
        try:
            resp = await client.get(gtm_url, impersonate='chrome', timeout=10.0)
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


async def process_domain(
    client: AsyncSession,
    domain_key: str,
    root_url: str,
    scan_contacts: bool,
    unpack_gtm: bool,
    default_region: str,
    proxy_config,
    cache_store,
    thread_pool: ThreadPoolExecutor,
    semaphore: asyncio.Semaphore
) -> dict:
    checked_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    loop = asyncio.get_running_loop()

    async with semaphore:
        status, html, final_url, err_msg = await fetch_html_safely(
            client, root_url, proxy_config=proxy_config
        )
        canonical_domain = get_clean_canonical_domain(final_url, domain_key)
        parsed_final = urlparse(final_url)
        scheme = parsed_final.scheme or 'https'
        clean_website_url = f'{scheme}://{canonical_domain}/'
        canonical_kv_key = sanitize_kv_key(canonical_domain)
        input_kv_key = sanitize_kv_key(domain_key)
        is_eu_gdpr = canonical_domain.endswith(EU_GDPR_TLDS)

        if status == 0 or status >= 400 or not html:
            fail_status = classify_failure_status(status, err_msg)
            if cache_store is not None:
                for candidate_key in (canonical_kv_key, input_kv_key):
                    try:
                        cached_record = await cache_store.get_value(candidate_key)
                        if (
                            isinstance(cached_record, dict)
                            and cached_record.get('_schema') == CACHE_SCHEMA_VERSION
                            and cached_record.get('status') in ('success', 'no_contacts_found')
                        ):
                            cached_copy = {k: v for k, v in cached_record.items() if k != '_schema'}
                            prev_time = cached_copy.get('last_checked_at', 'previous run')
                            cached_copy['input_domain'] = domain_key
                            cached_copy['status'] = f"cached_{cached_copy['status']} (live_{fail_status})"
                            cached_copy['error_message'] = (
                                f'Live request returned {err_msg}; preserved verified v{CACHE_SCHEMA_VERSION} snapshot from {prev_time}'
                            )
                            cached_copy['data_confidence_warning'] = (
                                f'Note: Live scan encountered {err_msg}; returning cached snapshot from {prev_time}.'
                            )
                            return cached_copy
                    except Exception:
                        pass

            cat = classify_company_category(domain_key, '', '', [])
            return {
                'input_domain': domain_key,
                'canonical_domain': canonical_domain,
                'website_url': clean_website_url,
                'final_redirect_url': final_url,
                'status': fail_status,
                'error_message': err_msg,
                'sales_readiness_verdict': 'Unverified (Scan Blocked by WAF)',
                'company_category': cat,
                'icp_fit_tier': 'Unverified (Site Blocked / Unreachable)',
                'technical_signal_strength': None,
                'contact_quality_tier': 'Tier F (Site Blocked)',
                'contact_enrichment_status': 'scan_blocked_by_waf',
                'data_confidence_warning': 'Site blocked by WAF/Cloudflare and no prior cached v2 snapshot available.',
                'gdpr_eu_domain': is_eu_gdpr,
                'page_title': None,
                'meta_description': None,
                'best_email': None,
                'email_domain': None,
                'best_email_type': None,
                'email_deliverability_check': None,
                'email_source_url': None,
                'primary_phone': None,
                'phone_source_url': None,
                'decision_maker_name': None,
                'decision_maker_role': None,
                'decision_maker_source_url': None,
                'decision_maker_linkedin_url': None,
                'decision_maker_search_query': build_linkedin_xray_query(canonical_domain, None),
                'linkedin_url': None,
                'instagram_url': None,
                'facebook_url': None,
                'telegram_url': None,
                'tiktok_url': None,
                'youtube_url': None,
                'social_source_url': None,
                'detected_signals': None,
                'sales_opportunity': f'Scan {fail_status} ({err_msg}) — cannot verify stack without access',
                'next_best_action': 'Retry with residential proxy or run decision_maker_search_query on LinkedIn',
                'technology_evidence': None,
                'has_meta_pixel': None,
                'has_tiktok_pixel': None,
                'has_google_ads': None,
                'has_linkedin_pixel': None,
                'has_pinterest_tag': None,
                'has_hubspot': None,
                'has_klaviyo': None,
                'has_ga4': None,
                'has_gtm': None,
                'detected_technologies': None,
                'all_emails': None,
                'all_phones': None,
                'last_checked_at': checked_at
            }

        (
            page_title,
            meta_desc,
            main_text,
            email_sources,
            phones_with_source,
            socials_with_source,
            contact_links
        ) = await loop.run_in_executor(
            thread_pool, parse_html_sync, html, final_url, default_region
        )

        if is_soft_404_page(html, page_title):
            page_title = ''

        if unpack_gtm:
            gtm_ids, gtm_js = await fetch_gtm_scripts(client, html)
        else:
            gtm_ids = sorted({
                m.upper() for m in GTM_ID_REGEX.findall(html)
                if m.upper() not in GTM_FALSE_POSITIVES
            })
            gtm_js = ''

        tech_info = detect_tech_with_evidence(html, gtm_js, gtm_ids, final_url)

        phone_map: dict[str, tuple[int, str]] = {}
        for p, sc, src in phones_with_source:
            if p not in phone_map or sc > phone_map[p][0]:
                phone_map[p] = (sc, src)

        pages_with_urls = [(final_url, html, main_text)]
        base_root = f"{scheme}://{re.sub(r':\d+$', '', parsed_final.netloc) or canonical_domain}"

        disallowed_paths, crawl_delay = await load_robots_rules(client, base_root)

        if scan_contacts and not contact_links:
            contact_links = await discover_links_from_sitemap(client, base_root)

        if scan_contacts and contact_links:
            allowed_sub_links = [
                u for u in contact_links
                if is_allowed_by_robots(u, disallowed_paths) and not DM_SOURCE_BLACKLIST.search(urlparse(u).path)
            ]
            for sub_url in allowed_sub_links[:5]:
                await asyncio.sleep(crawl_delay)
                sub_status, sub_html, sub_final_url, _ = await fetch_html_safely(
                    client, sub_url, proxy_config=proxy_config, timeout=10.0, retries=2
                )
                if 200 <= sub_status < 400 and sub_html:
                    sub_title, sub_desc, sub_text, sub_e, sub_p, sub_s, _ = await loop.run_in_executor(
                        thread_pool, parse_html_sync, sub_html, sub_final_url, default_region
                    )
                    if is_soft_404_page(sub_html, sub_title):
                        continue

                    # П.7: Забороняємо підсторінкам перезаписувати заголовок головної сторінки
                    pages_with_urls.append((sub_final_url, sub_html, sub_text))
                    for em, src in sub_e.items():
                        email_sources.setdefault(em, src)
                    for p, sc, src in sub_p:
                        if p not in phone_map or sc > phone_map[p][0]:
                            phone_map[p] = (sc, src)
                    for k, v in sub_s.items():
                        socials_with_source.setdefault(k, v)

        ranked_emails_with_src = rank_and_clean_emails(email_sources, canonical_domain)

        # П.12: Обмежуємо all_phones до 3 найрелевантніших B2B-номерів
        sorted_phones_with_src = sorted(
            phone_map.items(),
            key=lambda item: -item[1][0]
        )[:3]

        best_email = ranked_emails_with_src[0][0] if ranked_emails_with_src else None
        email_source_url = ranked_emails_with_src[0][1] if ranked_emails_with_src else None
        best_email_type = classify_email_type(best_email)

        email_domain = None
        if best_email and '@' in best_email:
            raw_em_dom = best_email.split('@', 1)[1].lower()
            brand_token = canonical_domain.split('.')[0].lower()
            normalized_em_local = re.sub(r'[._+-]', '', best_email.split('@', 1)[0].lower())
            if raw_em_dom == canonical_domain or raw_em_dom.endswith(f'.{canonical_domain}'):
                email_domain = f'{raw_em_dom} (matches_site)'
            elif raw_em_dom in PUBLIC_WEBMAIL_DOMAINS:
                if brand_token and brand_token in normalized_em_local:
                    email_domain = f'{raw_em_dom} (brand_webmail)'
                else:
                    email_domain = f'{raw_em_dom} (public_webmail)'
            elif brand_token and raw_em_dom.split('.')[0] == brand_token:
                email_domain = f'{raw_em_dom} (brand_alias_domain)'
            else:
                email_domain = f'{raw_em_dom} (external_domain)'

        deliverability_check = (
            await verify_email_deliverability_deep(client, best_email, email_source_url)
            if best_email else None
        )

        primary_phone = sorted_phones_with_src[0][0] if sorted_phones_with_src else None
        phone_source_url = sorted_phones_with_src[0][1][1] if sorted_phones_with_src else None

        social_source_url = None
        for platform in ('linkedin', 'instagram', 'facebook', 'telegram', 'tiktok', 'youtube'):
            if platform in socials_with_source:
                social_source_url = socials_with_source[platform][1]
                break

        detected_tech_list = tech_info['detected_technologies_list']
        company_category = classify_company_category(
            domain_key, page_title, meta_desc, detected_tech_list, html
        )

        dm_name, dm_role, dm_linkedin_url, dm_source_url = await loop.run_in_executor(
            thread_pool, extract_decision_maker_deep, pages_with_urls
        )

        dm_search_query = build_linkedin_xray_query(canonical_domain, page_title)

        linkedin_url = socials_with_source.get('linkedin', (None, None))[0]
        (
            sales_readiness_verdict,
            icp_fit_tier,
            technical_signal_strength,
            contact_quality_tier,
            enrichment_status,
            confidence_warning,
            detected_signals,
            sales_opportunity,
            next_best_action
        ) = evaluate_qualification_v41(
            company_category,
            tech_info,
            best_email,
            best_email_type,
            primary_phone,
            dm_name,
            dm_role,
            dm_linkedin_url,
            linkedin_url
        )

        has_any_contact = bool(best_email or primary_phone or socials_with_source)
        final_status = 'success' if has_any_contact else 'no_contacts_found'

        all_emails_list = [em for em, _ in ranked_emails_with_src[:5]]
        all_phones_list = [p for p, _ in sorted_phones_with_src]

        result_record = {
            'input_domain': domain_key,
            'canonical_domain': canonical_domain,
            'website_url': clean_website_url,
            'final_redirect_url': final_url,
            'status': final_status,
            'error_message': '',
            'sales_readiness_verdict': sales_readiness_verdict,
            'company_category': company_category,
            'icp_fit_tier': icp_fit_tier,
            'technical_signal_strength': technical_signal_strength,
            'contact_quality_tier': contact_quality_tier,
            'contact_enrichment_status': enrichment_status,
            'data_confidence_warning': confidence_warning,
            'gdpr_eu_domain': is_eu_gdpr,
            'page_title': page_title or None,
            'meta_description': meta_desc or None,
            'best_email': best_email,
            'email_domain': email_domain,
            'best_email_type': best_email_type,
            'email_deliverability_check': deliverability_check,
            'email_source_url': email_source_url,
            'primary_phone': primary_phone,
            'phone_source_url': phone_source_url,
            'decision_maker_name': dm_name,
            'decision_maker_role': dm_role,
            'decision_maker_source_url': dm_source_url,
            'decision_maker_linkedin_url': dm_linkedin_url,
            'decision_maker_search_query': dm_search_query,
            'linkedin_url': linkedin_url,
            'instagram_url': socials_with_source.get('instagram', (None, None))[0],
            'facebook_url': socials_with_source.get('facebook', (None, None))[0],
            'telegram_url': socials_with_source.get('telegram', (None, None))[0],
            'tiktok_url': socials_with_source.get('tiktok', (None, None))[0],
            'youtube_url': socials_with_source.get('youtube', (None, None))[0],
            'social_source_url': social_source_url,
            'detected_signals': detected_signals,
            'sales_opportunity': sales_opportunity,
            'next_best_action': next_best_action,
            'technology_evidence': tech_info['technology_evidence'],
            'has_meta_pixel': tech_info['has_meta_pixel'],
            'has_tiktok_pixel': tech_info['has_tiktok_pixel'],
            'has_google_ads': tech_info['has_google_ads'],
            'has_linkedin_pixel': tech_info['has_linkedin_pixel'],
            'has_pinterest_tag': tech_info['has_pinterest_tag'],
            'has_hubspot': tech_info['has_hubspot'],
            'has_klaviyo': tech_info['has_klaviyo'],
            'has_ga4': tech_info['has_ga4'],
            'has_gtm': tech_info['has_gtm'],
            'detected_technologies': '; '.join(detected_tech_list) if detected_tech_list else None,
            'all_emails': '; '.join(all_emails_list) if all_emails_list else None,
            'all_phones': '; '.join(all_phones_list) if all_phones_list else None,
            'last_checked_at': checked_at
        }

        if cache_store is not None and final_status in ('success', 'no_contacts_found'):
            cache_payload = {'_schema': CACHE_SCHEMA_VERSION, **result_record}
            try:
                await cache_store.set_value(canonical_kv_key, cache_payload)
                if input_kv_key != canonical_kv_key:
                    await cache_store.set_value(input_kv_key, cache_payload)
            except Exception:
                pass

        return result_record


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

        cache_store = None
        try:
            cache_store = await Actor.open_key_value_store(name='b2b-domain-cache-v1')
        except Exception:
            cache_store = None

        proxy_config = None
        primary_proxy_url = None
        try:
            if proxy_settings and proxy_settings.get('useApifyProxy'):
                proxy_config = await Actor.create_proxy_configuration(actor_proxy_input=proxy_settings)
                if proxy_config:
                    primary_proxy_url = await proxy_config.new_url()
            else:
                proxy_config = await Actor.create_proxy_configuration()
        except Exception:
            proxy_config = None

        Actor.log.info(
            f'Processing {len(prepared_domains)} unique domains '
            f'(concurrency: {max_concurrency}, GTM unpack: {unpack_gtm}, cache schema: v{CACHE_SCHEMA_VERSION})...'
        )
        semaphore = asyncio.Semaphore(max_concurrency)
        thread_pool = ThreadPoolExecutor(max_workers=max(16, max_concurrency * 2))

        batch = []
        batch_size = 5

        try:
            async with AsyncSession(
                impersonate='chrome',
                allow_redirects=True,
                verify=False,
                proxy=primary_proxy_url
            ) as client:
                tasks = [
                    process_domain(
                        client,
                        domain_key,
                        root_url,
                        scan_contacts,
                        unpack_gtm,
                        default_region,
                        proxy_config,
                        cache_store,
                        thread_pool,
                        semaphore
                    )
                    for domain_key, root_url in prepared_domains
                ]

                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    batch.append(result)

                    Actor.log.info(
                        f"[{result['status'].upper()}] {result['canonical_domain']} | "
                        f"DM: {result['decision_maker_name'] or '-'} ({result['decision_maker_role'] or '-'}) | "
                        f"Email: {result['best_email'] or '-'}"
                    )

                    if len(batch) >= batch_size:
                        await Actor.push_data(batch)
                        batch.clear()

                if batch:
                    await Actor.push_data(batch)
        finally:
            thread_pool.shutdown(wait=False)


if __name__ == '__main__':
    asyncio.run(main())
