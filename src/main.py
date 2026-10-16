import asyncio
from datetime import datetime, timezone
import re
import socket
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

# Строгий патерн для реального Імені + Прізвища поруч із B2B-посадою
NAME_NEAR_ROLE_PATTERN = re.compile(
    r'\b([A-ZА-ЯІЇЄҐ][a-zа-яіїєґ\']{2,20}\s+[A-ZА-ЯІЇЄҐ][a-zа-яіїєґ\']{2,25})'
    r'[\s,—–\-:|()]{1,15}'
    r'(CEO|Founder|Co-Founder|CMO|Chief Marketing Officer|Head of Marketing|'
    r'Marketing Director|Head of E-commerce|Commercial Director|Managing Partner|'
    r'Засновник|Співзасновник|Генеральний директор|Директор з маркетингу|Комерційний директор)\b',
    re.UNICODE
)

JUNK_EMAIL_DOMAINS = {
    'sentry.io', 'wixpress.com', 'example.com', 'domain.com', 'test.com',
    'email.com', 'yoursite.com', 'yourdomain.com', 'company.com', 'website.com',
    'sentry.wixpress.com', 'godaddy.com', 'sentry-next.wixpress.com',
    'wordpress.org', 'w3.org', 'schema.org', 'googleusercontent.com',
    'cloudflare.com', 'shopify.com', 'mysite.com', 'sample.com', 'mail.ru'
}

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

# Чіткий поділ поштових скриньок очима покупця маркетингових послуг
MARKETING_EXEC_PREFIXES = (
    'marketing', 'cmo', 'digital', 'growth', 'ecommerce', 'e-commerce',
    'performance', 'ppc', 'seo', 'analytics', 'ceo', 'founder', 'owner'
)
B2B_PARTNERSHIP_PREFIXES = (
    'partner', 'partners', 'partnerships', 'b2b', 'bizdev', 'bd', 'commercial', 'corporate', 'deals'
)
WHOLESALE_MERCH_PREFIXES = (
    'wholesale', 'opt', 'orders', 'sales', 'sale', 'supply', 'procurement', 'buyer'
)
GENERAL_OFFICE_PREFIXES = (
    'info', 'contact', 'hello', 'hi', 'office', 'team', 'business',
    'company', 'general', 'mail', 'kontakt', 'hallo', 'welcome', 'inquiries', 'enquiry'
)
SUPPORT_PREFIXES = (
    'support', 'help', 'service', 'care', 'customerservice', 'client', 'clients', 'shop', 'store'
)
PR_MEDIA_PREFIXES = (
    'pr', 'press', 'media', 'comms', 'communications', 'ads', 'collab', 'brand'
)
LOW_PRIORITY_PREFIXES = (
    'privacy', 'legal', 'datenschutz', 'dpo', 'compliance', 'gdpr',
    'billing', 'invoice', 'invoices', 'accounting', 'finance',
    'jobs', 'careers', 'job', 'hr', 'recruiting', 'security', 'copyright', 'dmca'
)
REGIONAL_BRANCH_LOCALS = {
    'kyiv', 'kiev', 'lviv', 'odesa', 'odessa', 'kharkiv', 'dnipro', 'london', 'ny', 'berlin', 'warsaw'
}

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
    'get-in-touch', 'contact-information'
)
SECONDARY_CONTACT_KEYWORDS = (
    'about', 'uber-uns', 'ueber-uns', 'team', 'company', 'leadership', 'management', 'wholesale', 'b2b'
)

AD_AND_ANALYTICS_SIGNATURES = {
    'Meta Pixel': [
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
    'cookiebot', 'onetrust', 'cookiefirst', 'usercentrics', 'complianz', 'cookieyes', 'Didomi'
)

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
    """Точна класифікація поштової скриньки без змішування гуртових замовлень та особистих пошт."""
    if not email or '@' not in email:
        return None
    local = email.split('@', 1)[0].lower()
    clean_local = re.split(r'[._+-]', local)[0]

    if local.startswith(LOW_PRIORITY_PREFIXES) or clean_local in LOW_PRIORITY_PREFIXES:
        return 'legal_or_hr'
    if local in REGIONAL_BRANCH_LOCALS or clean_local in REGIONAL_BRANCH_LOCALS:
        return 'regional_branch'
    if local.startswith(MARKETING_EXEC_PREFIXES) or clean_local in MARKETING_EXEC_PREFIXES:
        return 'marketing_or_exec_role'
    if local.startswith(B2B_PARTNERSHIP_PREFIXES) or clean_local in B2B_PARTNERSHIP_PREFIXES:
        return 'b2b_partnerships'
    if local.startswith(WHOLESALE_MERCH_PREFIXES) or clean_local in WHOLESALE_MERCH_PREFIXES:
        return 'wholesale_or_sales_inbox'
    if local.startswith(GENERAL_OFFICE_PREFIXES) or clean_local in GENERAL_OFFICE_PREFIXES:
        return 'general_office_inbox'
    if local.startswith(SUPPORT_PREFIXES) or clean_local in SUPPORT_PREFIXES:
        return 'customer_support_inbox'
    if local.startswith(PR_MEDIA_PREFIXES) or clean_local in PR_MEDIA_PREFIXES:
        return 'pr_and_media_inbox'

    # Якщо формат схожий на ім'я (наприклад, n.koshel@... або roman.polovyi@...)
    if '.' in local or len(local) >= 4:
        return 'personal_or_named_inbox'
    return 'general_office_inbox'


def check_domain_deliverability_status(email: str | None) -> str | None:
    """Чесно розділяє перевірку DNS домену та неперевірене існування конкретної скриньки."""
    if not email or '@' not in email:
        return None
    domain = email.split('@', 1)[1].strip()
    try:
        socket.getaddrinfo(domain, None)
        return 'domain_dns_active (mailbox_unverified_by_smtp)'
    except Exception:
        return 'domain_dns_failed'


def rank_and_clean_emails(
    email_sources: dict[str, str],
    base_domain: str
) -> list[tuple[str, str]]:
    valid: dict[str, str] = {}
    for raw_email, source_url in email_sources.items():
        email = raw_email.lower().strip('.,;:()[]"\'<> \t\r\n')
        email = re.sub(r'^(?:%20|u003[ce]|3a)+', '', email)

        if any(email.endswith(ext) for ext in JUNK_EXTENSIONS):
            continue
        if '@' not in email:
            continue

        local_part, domain_part = email.split('@', 1)
        if not local_part or not domain_part or '.' not in domain_part:
            continue

        domain_root = domain_part.split('.')[0]
        clean_local = re.sub(r'[0-9._+-]+$', '', local_part)

        if domain_part in JUNK_EMAIL_DOMAINS and base_domain != domain_part:
            continue
        if local_part in JUNK_EMAIL_LOCALS or clean_local in JUNK_EMAIL_LOCALS:
            continue
        if local_part == domain_root and domain_part != base_domain:
            continue

        if 6 <= len(email) <= 60 and email not in valid:
            valid[email] = source_url

    # Пріоритизація саме для продажу B2B/Digital послуг:
    # Іменні та маркетингові -> Партнерські -> Загальні офісні -> Гуртові -> Регіональні -> Саппорт -> PR
    type_weights = {
        'marketing_or_exec_role': 35,
        'personal_or_named_inbox': 32,
        'b2b_partnerships': 28,
        'general_office_inbox': 22,
        'wholesale_or_sales_inbox': 18,
        'regional_branch': 14,
        'customer_support_inbox': 8,
        'pr_and_media_inbox': 5,
        'legal_or_hr': -40
    }

    def email_score(addr: str) -> tuple[int, str]:
        _, domain = addr.split('@', 1)
        score = 0
        if base_domain and (domain == base_domain or domain.endswith(f'.{base_domain}')):
            score += 25
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
    combined = f'{html}\n{gtm_js}'
    html_lower = html.lower()
    gtm_lower = gtm_js.lower()

    detected = []
    evidence_items = []

    has_cookie_banner = any(cm.lower() in html_lower for cm in COOKIE_CONSENT_MARKERS)

    has_gtm = bool(gtm_ids) or 'googletagmanager.com/gtm.js' in html_lower
    if has_gtm:
        detected.append('Google Tag Manager')
        ev_str = f"GTM ({', '.join(gtm_ids)})" if gtm_ids else 'GTM (gtm.js)'
        evidence_items.append(f'{ev_str} [Direct HTML] on {page_url}')

    ga4_matches = sorted({m.upper() for m in GA4_ID_REGEX.findall(combined)})
    has_ga4 = (
        bool(ga4_matches)
        or 'googletagmanager.com/gtag/js' in html_lower
        or 'googletagmanager.com/gtag/js' in gtm_lower
        or 'google-analytics.com/g/collect' in html_lower
    )
    if has_ga4:
        detected.append('Google Analytics (GA4)')
        in_html = bool(GA4_ID_REGEX.search(html) or 'gtag/js' in html_lower)
        src_where = 'Direct HTML' if in_html else 'GTM Container'
        ev_id = ga4_matches[0] if ga4_matches else 'gtag/js'
        evidence_items.append(f'GA4 ({ev_id} in {src_where})')

    aw_matches = sorted({m.upper() for m in GOOGLE_ADS_REGEX.findall(combined)})
    has_google_ads = (
        bool(aw_matches)
        or 'googleadservices.com/pagead/conversion' in html_lower
        or 'googleadservices.com/pagead/conversion' in gtm_lower
    )
    if has_google_ads:
        detected.append('Google Ads Conversion')
        in_html = bool(GOOGLE_ADS_REGEX.search(html))
        src_where = 'Direct HTML' if in_html else 'GTM Container'
        ev_id = aw_matches[0] if aw_matches else 'conversion.js'
        evidence_items.append(f'Google Ads ({ev_id} in {src_where})')

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

    return {
        'has_meta_pixel': 'Meta Pixel' in detected,
        'has_tiktok_pixel': 'TikTok Pixel' in detected,
        'has_google_ads': has_google_ads,
        'has_linkedin_pixel': 'LinkedIn Insight Tag' in detected,
        'has_ga4': has_ga4,
        'has_gtm': has_gtm,
        'detected_technologies_list': detected,
        'technology_evidence': ev_summary
    }


def classify_company_category(
    domain: str,
    page_title: str,
    meta_desc: str,
    detected_tech: list[str]
) -> str:
    text = f'{domain} {page_title} {meta_desc}'.lower()

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
        'медіа про інтернет-маркетинг', 'netpeak', 'promodo'
    )
    if any(k in text for k in agency_keywords):
        return 'B2B Agency / Marketing Media'

    ecom_keywords = (
        'інтернет-магазин', 'интернет-магазин', 'онлайн магазин', 'online store',
        'shop', 'купити', 'купить', 'доставка по', 'колекція', 'бренд одягу',
        'бренд взуття', 'жіночого одягу', 'женского белья', 'каталог товарів',
        'checkout', 'add to cart', 'кошик', 'shoes', 'apparel', 'clothing'
    )
    if any(cms in detected_tech for cms in ('Shopify', 'WooCommerce')) or any(k in text for k in ecom_keywords):
        return 'E-commerce / Retail Brand'

    saas_keywords = ('saas', 'cloud platform', 'crm', 'api', 'b2b software', 'automation platform')
    if any(k in text for k in saas_keywords):
        return 'SaaS / Tech Platform'

    return 'General Business / Corporate'


def extract_decision_maker_clean(text: str) -> tuple[str | None, str | None]:
    """
    Повертає ТІЛЬКИ реальне Ім'я та Посаду або (None, None) для чистого імпорту в CRM!
    Ніяких службових фраз у полях імені.
    """
    match = NAME_NEAR_ROLE_PATTERN.search(text)
    if match:
        name = match.group(1).strip()
        role = match.group(2).strip()
        return name, role
    return None, None


def evaluate_three_dimensional_qualification(
    company_category: str,
    tech_info: dict,
    best_email: str | None,
    best_email_type: str | None,
    primary_phone: str | None,
    dm_name: str | None,
    linkedin_url: str | None
) -> tuple[str, str, str, str, str, str, str]:
    """
    Замість одного умовного 100/100 повертає три незалежні осі оцінки (як вимагає покупець):
    1. icp_fit_tier (Хто ця компанія)
    2. buying_signal_strength (Технічна потреба / Стек)
    3. contact_quality_tier (Якість знайденого контакту та готовність до аутрічу)
    + contact_enrichment_status, detected_signals, sales_opportunity, next_best_action
    """
    ad_tags = []
    if tech_info.get('has_meta_pixel'):
        ad_tags.append('Meta Pixel')
    if tech_info.get('has_google_ads'):
        ad_tags.append('Google Ads Conversion')
    if tech_info.get('has_tiktok_pixel'):
        ad_tags.append('TikTok Pixel')
    if tech_info.get('has_linkedin_pixel'):
        ad_tags.append('LinkedIn Insight Tag')

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

    # Вісь 1: ICP Fit Tier (Відповідність профілю цільового клієнта)
    if company_category == 'E-commerce / Retail Brand':
        icp_fit_tier = 'Tier 1: Target ICP (E-commerce / Retail Brand)'
    elif company_category in ('SaaS / Tech Platform', 'General Business / Corporate'):
        icp_fit_tier = 'Tier 2: Secondary ICP (Corporate / Digital Business)'
    elif company_category == 'B2B Agency / Marketing Media':
        icp_fit_tier = 'Partner / Competitor Segment (Agency / Media — Exclude from Standard Client Outreach)'
    else:
        icp_fit_tier = 'Non-Target ICP (Non-Profit / Education / Institution)'

    # Вісь 2: Buying Signal Strength (Сила технічного сигналу)
    if len(ad_tags) >= 2 and analytics_tags:
        buying_signal = (
            f"Strong Technical Signal: Multi-pixel ad stack ({', '.join(ad_tags)}) + { '/'.join(analytics_tags[:2]) } "
            "(Note: confirms tracking setup, not active ad spend budget)"
        )
    elif len(ad_tags) == 1:
        buying_signal = (
            f"Moderate Technical Signal: Single ad network ({ad_tags[0]}) detected — "
            "potential omnichannel expansion or Consent Mode hiding secondary tags"
        )
    elif analytics_tags:
        buying_signal = (
            f"Analytics-Only Signal ({', '.join(analytics_tags)}) — "
            "no paid ad pixels visible in static HTML"
        )
    else:
        buying_signal = (
            'Weak / Unverified Signal: No tracking tags visible in static DOM '
            '(may lack tracking or block scripts behind Cookie Consent)'
        )

    # Вісь 3: Contact Quality Tier & Enrichment Status (Реальна придатність контакту для B2B-продажу)
    if dm_name and best_email_type in ('personal_or_named_inbox', 'marketing_or_exec_role'):
        contact_quality = 'Tier A (Decision-Maker Named + Direct Email)'
        enrichment_status = 'verified_decision_maker_on_site'
    elif best_email_type in ('personal_or_named_inbox', 'marketing_or_exec_role'):
        contact_quality = f'Tier B+ (Direct / Named Inbox: {best_email_type}, No Full Name on Site)'
        enrichment_status = 'named_or_role_email_found_needs_title_match'
    elif best_email_type == 'b2b_partnerships':
        contact_quality = 'Tier B (B2B / Partnership Inbox — Good for Commercial/Partnership Pitch, Needs CMO Referral for Tech)'
        enrichment_status = 'b2b_role_inbox_only_needs_linkedin_dm'
    elif best_email_type == 'general_office_inbox':
        contact_quality = 'Tier C (Generic Office Inbox — Suitable for Gatekeeper Routing Only)'
        enrichment_status = 'generic_inbox_only_needs_linkedin_dm'
    elif best_email_type in ('wholesale_or_sales_inbox', 'regional_branch'):
        contact_quality = f'Tier C- ({best_email_type} — Merchandise/Regional Channel, Not Marketing Buyer)'
        enrichment_status = 'non_marketing_department_inbox_needs_linkedin_dm'
    elif best_email_type in ('customer_support_inbox', 'pr_and_media_inbox', 'legal_or_hr'):
        contact_quality = f'Tier D (Low Sales Fit: {best_email_type} — Do Not Cold Pitch Services Here)'
        enrichment_status = 'support_or_pr_inbox_only_requires_dm_enrichment'
    elif primary_phone:
        contact_quality = 'Tier D (Phone Only — No Email Found on Public Pages)'
        enrichment_status = 'phone_only_requires_email_and_dm_enrichment'
    else:
        contact_quality = 'Tier F (No Actionable Contacts Found on Website)'
        enrichment_status = 'no_public_contacts_found'

    # Комерційна гіпотеза (Sales Opportunity)
    if company_category == 'B2B Agency / Marketing Media':
        opportunity = (
            'Agency/Media Segment: Pitch white-label analytics implementation, '
            'data enrichment partnership, or B2B co-marketing'
        )
    elif company_category == 'Non-Profit / Education / Institution':
        opportunity = 'Non-commercial / Institutional organization — disqualify or route to pro-bono / grant segment'
    elif len(ad_tags) >= 2:
        opportunity = (
            f"Active multi-channel tracking ({', '.join(ad_tags)}) — "
            "qualify for Server-Side GTM (CAPI), cross-channel attribution audit, or CRO"
        )
    elif len(ad_tags) == 1:
        opportunity = (
            f"Single ad pixel ({ad_tags[0]}) — "
            "qualify for Google Ads / Meta / TikTok channel expansion & conversion tracking audit"
        )
    else:
        opportunity = 'Manual site verification needed: check if tracking is blocked by Cookie Consent before pitching GA4/GTM setup'

    # Конкретний Next Best Action для SDR/Sales-менеджера
    if company_category == 'B2B Agency / Marketing Media':
        next_action = f"Move to Agency Partnership pipeline; reach out via {best_email or linkedin_url or primary_phone}"
    elif company_category == 'Non-Profit / Education / Institution':
        next_action = 'Exclude from commercial B2B cold outreach'
    elif best_email_type in ('customer_support_inbox', 'pr_and_media_inbox', 'wholesale_or_sales_inbox', 'regional_branch'):
        next_action = (
            f"DO NOT send marketing pitch to {best_email} ({best_email_type}); "
            f"enrich CMO / Head of E-commerce via LinkedIn {('(' + linkedin_url + ')') if linkedin_url else ''} "
            f"or call {primary_phone or 'company'} to ask for Marketing Lead"
        )
    elif best_email:
        next_action = (
            f"Send tailored audit intro to {best_email} ({best_email_type}) "
            f"and enrich specific CMO/Head of Digital on LinkedIn in parallel"
        )
    elif primary_phone:
        next_action = f"Enrich decision-maker email via LinkedIn/Apollo or call {primary_phone} for routing"
    else:
        next_action = 'Enrich company contacts via LinkedIn Sales Navigator / external B2B database'

    return (
        icp_fit_tier,
        buying_signal,
        contact_quality,
        enrichment_status,
        detected_signals_str,
        opportunity,
        next_action
    )


def parse_html_sync(
    html: str,
    page_url: str,
    default_region: str
) -> tuple[str, str, str, dict[str, str], list[tuple[str, int, str]], dict[str, tuple[str, str]], list[str]]:
    email_sources: dict[str, str] = {}
    for m in EMAIL_REGEX.findall(html):
        email_sources[m] = page_url

    raw_tel_candidates: list[tuple[str, str]] = [
        (m, 'schema_json_ld') for m in SCHEMA_PHONE_REGEX.findall(html)
    ]
    socials_with_source: dict[str, tuple[str, str]] = {}
    primary_links = set()
    secondary_links = set()

    soup = BeautifulSoup(html, 'lxml')
    base_domain = urlparse(page_url).netloc.lower().replace('www.', '')
    base_clean = page_url.rstrip('/')

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
            email_sources[decoded] = page_url

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        href_lower = href.lower()

        if href_lower.startswith('mailto:'):
            mail = href.split(':', 1)[1].split('?')[0].strip()
            if EMAIL_REGEX.match(mail):
                email_sources[mail] = page_url
            continue

        if href_lower.startswith('tel:'):
            tel = href.split(':', 1)[1].strip()
            parent = a_tag.find_parent(['li', 'p', 'div', 'td', 'section']) or a_tag.parent
            context_str = parent.get_text(' ', strip=True)[:200] if parent else a_tag.get_text(' ', strip=True)
            raw_tel_candidates.append((tel, context_str))
            continue

        for platform in ('linkedin', 'instagram', 'facebook', 'tiktok', 'telegram', 'youtube', 'twitter'):
            if platform not in socials_with_source:
                clean_soc = clean_and_validate_social_url(platform, href)
                if clean_soc:
                    socials_with_source[platform] = (clean_soc, page_url)

        full_url = urljoin(page_url, href)
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
    for m in EMAIL_REGEX.findall(text_content):
        email_sources.setdefault(m, page_url)

    scored_phones = extract_valid_phones(text_content, raw_tel_candidates, default_region)
    phones_with_source = [(p, sc, page_url) for p, sc in scored_phones]

    ordered_contact_links = sorted(primary_links) + sorted(secondary_links - primary_links)

    return page_title, meta_desc, text_content, email_sources, phones_with_source, socials_with_source, ordered_contact_links


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
    semaphore: asyncio.Semaphore
) -> dict:
    checked_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    async with semaphore:
        status, html, final_url, err_msg = await fetch_html_safely(client, root_url)

        if status == 0 or status >= 400 or not html:
            fail_status = classify_failure_status(status, err_msg)
            cat = classify_company_category(domain_key, '', '', [])
            return {
                'input_domain': domain_key,
                'website_url': final_url,
                'status': fail_status,
                'error_message': err_msg,
                'company_category': cat,
                'icp_fit_tier': 'Unverified (Site Blocked / Unreachable)',
                'buying_signal_strength': None,
                'contact_quality_tier': 'Tier F (Site Blocked)',
                'contact_enrichment_status': 'scan_blocked_by_waf',
                'page_title': None,
                'meta_description': None,
                'best_email': None,
                'best_email_type': None,
                'email_deliverability_check': None,
                'email_source_url': None,
                'primary_phone': None,
                'phone_source_url': None,
                'decision_maker_name': None,
                'decision_maker_role': None,
                'linkedin_url': None,
                'instagram_url': None,
                'facebook_url': None,
                'telegram_url': None,
                'tiktok_url': None,
                'youtube_url': None,
                'social_source_url': None,
                'detected_signals': None,
                'sales_opportunity': f'Scan {fail_status} ({err_msg}) — cannot verify stack without access',
                'next_best_action': 'Retry with residential proxy or enrich company via LinkedIn directly',
                'technology_evidence': None,
                'has_meta_pixel': None,
                'has_tiktok_pixel': None,
                'has_google_ads': None,
                'has_linkedin_pixel': None,
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
        ) = await asyncio.to_thread(parse_html_sync, html, final_url, default_region)

        if unpack_gtm:
            gtm_ids, gtm_js = await fetch_gtm_scripts(client, html)
        else:
            gtm_ids = sorted({m.upper() for m in GTM_ID_REGEX.findall(html)})
            gtm_js = ''

        tech_info = detect_tech_with_evidence(html, gtm_js, gtm_ids, final_url)

        phone_map: dict[str, tuple[int, str]] = {}
        for p, sc, src in phones_with_source:
            if p not in phone_map or sc > phone_map[p][0]:
                phone_map[p] = (sc, src)

        combined_text_parts = [main_text]

        if scan_contacts and contact_links:
            for sub_url in contact_links[:3]:
                sub_status, sub_html, sub_final_url, _ = await fetch_html_safely(
                    client, sub_url, timeout=10.0, retries=1
                )
                if 200 <= sub_status < 400 and sub_html:
                    _, _, sub_text, sub_e, sub_p, sub_s, _ = await asyncio.to_thread(
                        parse_html_sync, sub_html, sub_final_url, default_region
                    )
                    combined_text_parts.append(sub_text)
                    for em, src in sub_e.items():
                        email_sources.setdefault(em, src)
                    for p, sc, src in sub_p:
                        if p not in phone_map or sc > phone_map[p][0]:
                            phone_map[p] = (sc, src)
                    for k, v in sub_s.items():
                        socials_with_source.setdefault(k, v)

        base_domain = urlparse(final_url).netloc.lower().replace('www.', '')
        ranked_emails_with_src = rank_and_clean_emails(email_sources, base_domain)

        sorted_phones_with_src = sorted(
            phone_map.items(),
            key=lambda item: -item[1][0]
        )[:10]

        best_email = ranked_emails_with_src[0][0] if ranked_emails_with_src else None
        email_source_url = ranked_emails_with_src[0][1] if ranked_emails_with_src else None
        best_email_type = classify_email_type(best_email)
        deliverability_check = (
            await asyncio.to_thread(check_domain_deliverability_status, best_email)
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
            domain_key, page_title, meta_desc, detected_tech_list
        )

        # Чисте витягнення Імені та Посади (або None, None без засмічення CRM-полів)
        dm_name, dm_role = extract_decision_maker_clean(' '.join(combined_text_parts))

        linkedin_url = socials_with_source.get('linkedin', (None, None))[0]
        (
            icp_fit_tier,
            buying_signal_strength,
            contact_quality_tier,
            enrichment_status,
            detected_signals,
            sales_opportunity,
            next_best_action
        ) = evaluate_three_dimensional_qualification(
            company_category,
            tech_info,
            best_email,
            best_email_type,
            primary_phone,
            dm_name,
            linkedin_url
        )

        has_any_contact = bool(best_email or primary_phone or socials_with_source)
        final_status = 'success' if has_any_contact else 'no_contacts_found'

        all_emails_list = [em for em, _ in ranked_emails_with_src]
        all_phones_list = [p for p, _ in sorted_phones_with_src]

        return {
            'input_domain': domain_key,
            'website_url': final_url,
            'status': final_status,
            'error_message': '',
            'company_category': company_category,
            'icp_fit_tier': icp_fit_tier,
            'buying_signal_strength': buying_signal_strength,
            'contact_quality_tier': contact_quality_tier,
            'contact_enrichment_status': enrichment_status,
            'page_title': page_title,
            'meta_description': meta_desc,
            'best_email': best_email,
            'best_email_type': best_email_type,
            'email_deliverability_check': deliverability_check,
            'email_source_url': email_source_url,
            'primary_phone': primary_phone,
            'phone_source_url': phone_source_url,
            'decision_maker_name': dm_name,
            'decision_maker_role': dm_role,
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
            'has_ga4': tech_info['has_ga4'],
            'has_gtm': tech_info['has_gtm'],
            'detected_technologies': '; '.join(detected_tech_list) if detected_tech_list else None,
            'all_emails': '; '.join(all_emails_list) if all_emails_list else None,
            'all_phones': '; '.join(all_phones_list) if all_phones_list else None,
            'last_checked_at': checked_at
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
                    f"{result['icp_fit_tier']} | "
                    f"Contact: {result['contact_quality_tier']}"
                )

                if len(batch) >= batch_size:
                    await Actor.push_data(batch)
                    batch.clear()

            if batch:
                await Actor.push_data(batch)


if __name__ == '__main__':
    asyncio.run(main())
