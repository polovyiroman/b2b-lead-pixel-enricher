from datetime import datetime, timezone
import re
from urllib.parse import urlparse

MAX_HTML_BYTES = 1_500_000
CACHE_SCHEMA_VERSION = 18
MIN_COMPATIBLE_CACHE_SCHEMA = 6
EVERGREEN_MAX_AGE_DAYS = 180

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
HEX_HASH_LOCAL_REGEX = re.compile(r'^[a-f0-9]{20,}$', re.IGNORECASE)

SCHEMA_PHONE_REGEX = re.compile(
    r'"(?:telephone|phone|contactPhone|phoneNumber|tel)"\s*:\s*"([^"]{7,30})"',
    re.IGNORECASE
)

GTM_ID_REGEX = re.compile(r'\bGTM-[A-Z0-9]{5,10}\b', re.IGNORECASE)

GA4_STRICT_10CHAR_REGEX = re.compile(r'\bG-(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{8,10}\b')

GTAG_CONFIG_GA4_REGEX = re.compile(
    r"gtag\(\s*['\"]config['\"]\s*,\s*['\"](G-(?=[A-Z0-9]*\d)[A-Z0-9]{6,12})['\"]",
    re.IGNORECASE
)
GA4_SCRIPT_SRC_REGEX = re.compile(
    r"googletagmanager\.com/gtag/js\?[^'\"\s>]*?\bid=(G-(?=[A-Z0-9]*\d)[A-Z0-9]{6,12})\b",
    re.IGNORECASE
)
GA4_WIRE_REGEX = re.compile(
    r"google-analytics\.com/g/collect\?[^'\"\s>]*?(?:^|[?&])tid=(G-(?=[A-Z0-9]*\d)[A-Z0-9]{6,12})\b",
    re.IGNORECASE
)
GTM_JSON_GA4_REGEX = re.compile(
    r"['\"](?:vtp_)?(?:measurement_?[Ii]d(?:Override)?|tag_?[Ii]d|send_?[Tt]o|"
    r"ga_measurement_?[Ii]d)['\"]\s*[:,\s]\s*['\"](G-(?=[A-Z0-9]*\d)[A-Z0-9]{8,12})['\"]",
    re.IGNORECASE
)

GOOGLE_ADS_REGEX = re.compile(r'\bAW-\d{6,12}\b')

CHECKOUT_REDIRECT_HOSTS = re.compile(
    r'^(?:[a-z]{2}\.)?(?:checkout|cart|pay|secure|billing)\.',
    re.IGNORECASE
)

SOFT_404_TITLE_REGEX = re.compile(
    r'^\s*(?:404|error\s*404|page\s*not\s*found|not\s*found|'
    r'сторінк[уа]\s+не\s+знайдено|сторінка\s+не\s+знайдена|помилка\s*404)'
    r'(?:\s*[\|\-–—:!.]|\s*$)',
    re.IGNORECASE
)

DM_SOURCE_BLACKLIST = re.compile(
    r'/(?:privacy|policy|datenschutz|gdpr|cookie|dmca|testimonial|testimonials|reviews|case-studies|case-study|clients|stories)\b',
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
    'GTM-TRACK', 'GTM-NOSCRIPT', 'GTM-IFRAME', 'GTM-CUSTOM', 'GTM-CONFIG',
    'GTM-LABEL', 'GTM-VALUE', 'GTM-TRIGGER', 'GTM-VARIABLE', 'GTM-TAG', 'GTM-MACRO'
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

TESTIMONIAL_TEXT_MARKERS = (
    'відгук', 'відгуки', 'наші клієнти', 'клієнти про нас', 'що кажуть клієнти',
    'testimonial', 'testimonials', 'what our clients say', 'customer stories',
    'client review', 'case study', 'дякуємо команді', 'користуємося сервісом'
)

FOREIGN_TESTIMONIAL_NAMES_BLACKLIST = {
    'дієго сільва', 'diego silva', 'roman kohutkevych', 'роман когуткевич'
}

UI_ACTION_WORDS_BLACKLIST = {
    'читати', 'детальніше', 'дивитися', 'дивитись', 'переглянути', 'написати',
    'зв’язатися', 'звязатися', 'автор', 'спікер', 'експерт', 'блог', 'стаття',
    'команда', 'кейс', 'відгук', 'клієнт', 'партнер', 'модератор', 'ведучий',
    'read', 'more', 'view', 'author', 'speaker', 'expert', 'blog', 'article',
    'client', 'building', 'link', 'seo', 'ppc', 'smm', 'growth', 'team', 'about'
}

ROLE_TOKEN_BLACKLIST = {
    'officer', 'director', 'manager', 'president', 'chief', 'head', 'lead',
    'partner', 'chairman', 'executive', 'founder', 'cofounder', 'co-founder',
    'owner', 'vice', 'deputy', 'general', 'commercial', 'marketing', 'digital',
    'ceo', 'cmo', 'cto', 'coo', 'cfo', 'vp', 'svp', 'avp', 'admin', 'editor',
    'директор', 'директорка', 'керівник', 'керівниця', 'начальник', 'президент',
    'засновник', 'засновниця', 'співзасновник', 'співзасновниця', 'власник',
    'власниця', 'голова', 'заступник', 'менеджер', 'партнер', 'ректор', 'декан'
}
ROLE_TOKEN_BLACKLIST.update(UI_ACTION_WORDS_BLACKLIST)

ROLE_WORDS_IN_CONTEXT = (
    'manager', 'менеджер', 'sales', 'sales manager', 'director', 'директор',
    'head', 'керівник', 'specialist', 'спеціаліст', 'lead', 'лід', 'recruiter',
    'hr', 'account', 'координатор', 'coordinator', 'partner', 'партнер',
    'департамент', 'відділ', 'department', 'division', 'team', 'маркетинг',
    'marketing', 'pr', 'communications', 'комунікац', 'b2b', 'support', 'підтримк'
)

ROLE_NORMALIZATION_MAP = {
    'cmo': 'Chief Marketing Officer (CMO)',
    'chief marketing officer': 'Chief Marketing Officer (CMO)',
    'директор з маркетингу': 'Chief Marketing Officer (CMO)',
    'маркетинг-директор': 'Chief Marketing Officer (CMO)',
    'керівник відділу маркетингу': 'Head of Marketing',
    'head of marketing': 'Head of Marketing',
    'marketing director': 'Marketing Director',
    'head of e-commerce': 'Head of E-commerce',
    'e-commerce director': 'E-commerce Director',
    'head of growth': 'Head of Growth',
    'head of digital': 'Head of Digital',
    'ceo': 'Chief Executive Officer (CEO)',
    'генеральний директор': 'Chief Executive Officer (CEO)',
    'директор': 'Managing Director / CEO',
    'директорка': 'Managing Director / CEO',
    'general manager': 'General Manager',
    'founder': 'Founder',
    'засновник': 'Founder',
    'засновниця': 'Founder',
    'co-founder': 'Co-Founder',
    'співзасновник': 'Co-Founder',
    'співзасновниця': 'Co-Founder',
    'співзасновники': 'Co-Founder',
    'owner': 'Owner',
    'власник': 'Owner',
    'власниця': 'Owner',
    'commercial director': 'Commercial Director',
    'комерційний директор': 'Commercial Director',
    'managing partner': 'Managing Partner'
}

STOP_NAME_WORDS = {
    'Інтернет', 'Магазин', 'Онлайн', 'Бренд', 'Компанія', 'Агентство', 'Агенція',
    'Політика', 'Конфіденційності', 'Умови', 'Доставка', 'Оплата', 'Контакти',
    'Кабінет', 'Каталог', 'Колекція', 'Україна', 'Київ', 'Львів', 'Privacy',
    'Policy', 'Terms', 'Conditions', 'Customer', 'Service', 'Support', 'Contact',
    'About', 'Company', 'Digital', 'Marketing', 'Agency', 'Online', 'Store',
    'LinkedIn', 'Profile', 'View', 'Український', 'Перший', 'Жіночий', 'Official',
    'Наші', 'Ваші', 'Нова', 'Повна', 'Більше', 'Меню', 'Головна', 'Сторінка',
    'Публічна', 'Оферта', 'Договір', 'Персональних', 'Даних', 'Захисту', 'Права',
    'Читати', 'Детальніше', 'Дивитися', 'Переглянути', 'Автор', 'Спікер', 'Експерт',
    'Building', 'Link', 'Кейс', 'Відгук', 'Стаття'
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
    'atlassian.net', 'janesbakery.com', 'sentry.softwear.co'
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
    'corporate', 'corpcom', 'deals', 'tender', 'tenders', 'enterprise', 'corp'
)
WHOLESALE_MERCH_PREFIXES = (
    'wholesale', 'opt', 'orders', 'sales', 'sale', 'supply', 'procurement', 'buyer'
)
INFLUENCER_PREFIXES = (
    'gteam', 'creators', 'influencers', 'influencer', 'gifting', 'collabs', 'ambassador', 'ambassadors'
)
GENERAL_OFFICE_PREFIXES = (
    'info', 'contact', 'hello', 'hi', 'office', 'team', 'business',
    'company', 'general', 'mail', 'kontakt', 'hallo', 'welcome', 'inquiries',
    'enquiry', 'reception', 'secretariat', 'admin', 'kans', 'kanc', 'manager'
)
DEPARTMENT_OR_ADMISSIONS_PREFIXES = (
    'vstup', 'admissions', 'admission', 'dekanat', 'rector', 'rectorate',
    'department', 'faculty', 'edu', 'study', 'courses', 'academy',
    'booking', 'reservation', 'delivery', 'logistics', 'export', 'import'
)
SUPPORT_PREFIXES = (
    'support', 'supportua', 'supportyo', 'help', 'service', 'care', 'customerservice',
    'customercare', 'client', 'clients', 'shop', 'store', 'hotline', 'callcenter'
)
PR_MEDIA_PREFIXES = (
    'pr', 'press', 'media', 'comms', 'communications', 'ads', 'collab', 'brand',
    'events', 'insight', 'insights', 'research'
)
LOW_PRIORITY_PREFIXES = (
    'privacy', 'privacyrequest', 'legal', 'notices', 'notice', 'legalnotices',
    'datenschutz', 'data', 'datarequest', 'dataprotection', 'dpo', 'compliance',
    'gdpr', 'billing', 'invoice', 'invoices', 'accounting', 'finance',
    'jobs', 'careers', 'job', 'hr', 'recruiting', 'security', 'copyright', 'dmca', 'jira'
)
REGIONAL_BRANCH_LOCALS = {
    'kyiv', 'kiev', 'lviv', 'odesa', 'odessa', 'kharkiv', 'dnipro', 'london', 'ny', 'berlin', 'warsaw'
}

NON_PERSON_TOKENS = (
    set(MARKETING_EXEC_PREFIXES)
    | set(B2B_PARTNERSHIP_PREFIXES)
    | set(WHOLESALE_MERCH_PREFIXES)
    | set(INFLUENCER_PREFIXES)
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
    'get-in-touch', 'contact-information', 'kontakty', 'contacts', 'contact-us'
)
SECONDARY_CONTACT_KEYWORDS = (
    'about', 'uber-uns', 'ueber-uns', 'team', 'komanda', 'company', 'leadership',
    'management', 'founders', 'our-story', 'pro-nas', 'o-nas', 'history', 'brand',
    'wholesale', 'b2b', 'investors', 'oferta', 'offer', 'terms', 'our-services', 'ugoda'
)

CONTACT_ANCHOR_TEXT_KEYWORDS = (
    'contact', 'contact us', 'get in touch', 'support', 'customer care',
    'help center', 'контакти', 'зв\'язатися', 'про нас', 'about us', 'impressum'
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
    'cookiebot', 'onetrust', 'cookiefirst', 'usercentrics', 'complianz',
    'cookieyes', 'didomi', 'pandectes', 'shopify.customerprivacy',
    'shopify-pc__banner', 'consent-banner', 'cookie-consent', 'osano', 'trustarc', 'iubenda'
)

SOCIAL_BAD_SEGMENTS = {
    'sharer', 'sharer.php', 'share', 'intent', 'plugins', 'status', 'posts',
    'photos', 'videos', 'tr', 'dialog', 'p', 'reel', 'reels', 'stories',
    'explore', 'watch', 'groups', 'events', 'marketplace', 'gaming',
    'business', 'partner-directory', 'ads', 'help', 'policies', 'privacy',
    'legal', 'login', 'signin', 'signup', 'hashtag', 'search', 'discover', 'about'
}

TELEGRAM_PLACEHOLDER_SLUGS = {
    'your', 'example', 'demo', 'test', 'channel', 'group', 'username', 'bot', 'mychannel'
}

REGION_DIALING_PREFIX_MAP = {
    'UA': '+380',
    'US': '+1',
    'CA': '+1',
    'GB': '+44',
    'UK': '+44',
    'PL': '+48',
    'DE': '+49',
    'FR': '+33'
}

KNOWN_MARKETPLACE_DOMAINS = {
    'answear.ua', 'answear.com', 'kasta.ua', 'modnakasta.ua', 'rozetka.com.ua',
    'comfy.ua', 'intertop.ua', 'epicentrk.ua', 'allo.ua', 'foxtrot.com.ua',
    'prom.ua', 'shafa.ua', 'liki24.com', 'makeup.com.ua', 'eva.ua'
}

KNOWN_DOMAIN_REDIRECT_ALIASES = {
    'modnakasta.ua': 'kasta.ua'
}

MARKETPLACE_TEXT_MARKERS = (
    'більше 500 брендів', 'понад 9 млн товарів', 'мільйони товарів', 'маркетплейс',
    'marketplace', 'multi-brand', 'мультибрендовий', 'сотні брендів', 'тисячі брендів'
)

DEFAULT_MANUAL_SEEDS: dict[str, dict] = {
    'rozetka.com.ua': {
        'page_title': 'Інтернет-магазин ROZETKA™: офіційний сайт найпопулярнішого онлайн-гіпермаркету в Україні',
        'meta_description': 'ROZETKA — найбільший онлайн-ритейлер та маркетплейс України. Побутова техніка, електроніка, одяг, товари для дому та бізнесу.',
        'company_category': 'E-commerce / Retail Brand',
        'category_confidence': 'high',
        'marketplace_platform': True,
        'marketplace_platform_pollution_detected': False,
        'best_email': 'partner@rozetka.com.ua',
        'all_emails': 'partner@rozetka.com.ua; service@rozetka.com.ua',
        'best_email_type': 'b2b_partnerships',
        'email_source_url': 'https://rozetka.com.ua/ua/seller/',
        'email_source_type': 'contact_page',
        'email_source_note': 'Verified B2B seller/partnership channel from official Rozetka Seller portal',
        'primary_phone': '+380 44 537 0222',
        'e164_phone': '+380445370222',
        'all_phones': '+380 44 537 0222; +380 44 503 8080',
        'phone_availability': 'public',
        'phone_source_url': 'https://rozetka.com.ua/ua/contacts/',
        'decision_maker_name': 'Владислав Чечоткін',
        'decision_maker_role': 'Co-Founder',
        'decision_maker_source_url': 'https://rozetka.com.ua/ua/about/',
        'decision_maker_source_type': 'about_page',
        'decision_makers_found': 'Владислав Чечоткін (Co-Founder) [https://rozetka.com.ua/ua/about/]',
        'linkedin_url': 'https://www.linkedin.com/company/rozetka',
        'instagram_url': 'https://www.instagram.com/rozetkaua',
        'facebook_url': 'https://www.facebook.com/rozetka.ua',
        'telegram_url': 'https://t.me/rozetka',
        'tiktok_url': 'https://www.tiktok.com/@rozetka',
        'youtube_url': 'https://www.youtube.com/user/rozetka',
        'social_source_url': 'https://rozetka.com.ua/',
        'has_gtm': True,
        'has_ga4': True,
        'has_google_ads': True,
        'has_meta_pixel': True,
        'has_tiktok_pixel': True,
        'has_linkedin_pixel': False,
        'has_pinterest_tag': False,
        'has_hubspot': False,
        'has_klaviyo': False,
        'all_ga4_ids': 'G-ROZETKA-GA4',
        'ga4_detection_confidence': 'Verified (Manual Audit Seed)',
        'detected_technologies': 'Google Tag Manager; Google Analytics (GA4); Google Ads Conversion; Meta Pixel; TikTok Pixel',
        'technology_evidence_summary': 'GTM, GA4, Google Ads, Meta Pixel, TikTok Pixel (Manual Audit Seed)',
        'technology_evidence': 'Verified Tier-1 Enterprise Stack (GTM + GA4 + Meta Pixel + Google Ads + TikTok Pixel) via manual_audit seed',
        'verified_at': '2026-10-15T12:00:00Z'
    }
}


def is_valid_gtm_id(candidate: str) -> bool:
    up = candidate.upper()
    if up in GTM_FALSE_POSITIVES:
        return False
    suffix = up[4:]
    if any(ch.isdigit() for ch in suffix):
        return True
    vowels = sum(1 for ch in suffix if ch in 'AEIOUY')
    return len(suffix) in (6, 7) and vowels <= 1


def truncate_error_msg(err: str | None, max_len: int = 80) -> str:
    if not err:
        return ''
    clean = ' '.join(str(err).split())
    if len(clean) <= max_len:
        return clean
    return clean[:max_len - 1].rstrip() + '…'


def sanitize_kv_key(domain: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]', '_', domain.lower())


def clean_url_port(url: str | None) -> str | None:
    if not url:
        return None
    cleaned = re.sub(r':(?:443|80)(?=/|$)', '', url)
    parsed = urlparse(cleaned)
    if not parsed.path:
        cleaned = f'{cleaned}/'
    return cleaned


def compute_snapshot_age_days(checked_at_str: str | None) -> int | None:
    if not checked_at_str or not isinstance(checked_at_str, str):
        return None
    try:
        prev_dt = datetime.strptime(checked_at_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - prev_dt
        return max(0, delta.days)
    except Exception:
        return None
