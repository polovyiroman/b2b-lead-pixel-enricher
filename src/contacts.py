import asyncio
import json
import re
import textwrap
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession
import phonenumbers

from .config import (
    B2B_PARTNERSHIP_PREFIXES,
    B2B_PHONE_KEYWORDS,
    CITY_NAMES_BLACKLIST,
    CORPORATE_ENTITY_TOKENS,
    DEPARTMENT_OR_ADMISSIONS_PREFIXES,
    DEPARTMENT_PREFIX_BLACKLIST,
    DM_LEGAL_SOURCE_FLAG,
    DM_SOURCE_BLACKLIST,
    FOP_OWNER_PATTERN,
    FOREIGN_TESTIMONIAL_NAMES_BLACKLIST,
    GENERAL_OFFICE_PREFIXES,
    HEX_HASH_LOCAL_REGEX,
    INFLUENCER_PREFIXES,
    INVALID_EMAIL_TLDS,
    JUNK_EMAIL_DOMAINS,
    JUNK_EMAIL_LOCALS,
    JUNK_EXTENSIONS,
    LOW_PRIORITY_PREFIXES,
    MARKETING_EXEC_PREFIXES,
    NAME_BEFORE_ROLE_PATTERN,
    NON_PERSON_TOKENS,
    PR_MEDIA_PREFIXES,
    PUBLIC_WEBMAIL_DOMAINS,
    REGION_DIALING_PREFIX_MAP,
    REGIONAL_BRANCH_LOCALS,
    RETAIL_PHONE_KEYWORDS,
    ROLE_BEFORE_NAME_PATTERN,
    ROLE_NORMALIZATION_MAP,
    ROLE_TOKEN_BLACKLIST,
    ROLE_WORDS_IN_CONTEXT,
    ROLES_REGEX_PART,
    SOCIAL_BAD_SEGMENTS,
    STOP_NAME_WORDS,
    SUPPORT_PREFIXES,
    TELEGRAM_PLACEHOLDER_SLUGS,
    TESTIMONIAL_TEXT_MARKERS,
    UA_TO_LATIN,
    VERTRETEN_DURCH_PATTERN,
    WHOLESALE_MERCH_PREFIXES,
    clean_url_port,
)

DNS_MEMORY_CACHE: dict[str, tuple[str | None, bool, str]] = {}
_DNS_DOMAIN_LOCKS: dict[str, asyncio.Lock] = {}

IMPRESSUM_CANONICAL_PATH_REGEX = re.compile(
    r'/(?:impressum|mentions-legales|aviso-legal)\b',
    re.IGNORECASE
)

_STOP_NAME_WORDS_LOWER = {w.lower() for w in STOP_NAME_WORDS}

SENDER_SUBDOMAIN_PREFIXES = (
    'mail.', 'e.', 'email.', 'news.', 'newsletter.', 'newsletters.',
    'bounce.', 'bounces.', 'crm.', 'mktg.', 'em.', 'mailing.'
)

EU_DIACRITIC_MAP = {
    'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss',
    'á': 'a', 'à': 'a', 'â': 'a', 'ã': 'a', 'å': 'a', 'ą': 'a',
    'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'ę': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
    'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ø': 'o', 'ł': 'l',
    'ú': 'u', 'ù': 'u', 'û': 'u', 'ń': 'n', 'ñ': 'n',
    'ć': 'c', 'č': 'c', 'ç': 'c', 'ś': 's', 'š': 's', 'ź': 'z', 'ż': 'z', 'ž': 'z',
}


def decode_cf_email(encoded_str: str) -> str:
    try:
        r = int(encoded_str[:2], 16)
        return ''.join(
            chr(int(encoded_str[i:i + 2], 16) ^ r)
            for i in range(2, len(encoded_str), 2)
        )
    except Exception:
        return ''


def _matches_prefix_safely(
    local: str,
    normalized_local: str,
    tokens: list[str],
    prefixes: tuple[str, ...]
) -> bool:
    prefix_set = set(prefixes)
    if local in prefix_set or normalized_local in prefix_set:
        return True
    if any(t in prefix_set for t in tokens):
        return True
    long_prefixes = tuple(p for p in prefixes if len(p) >= 4)
    if long_prefixes and (local.startswith(long_prefixes) or normalized_local.startswith(long_prefixes)):
        return True
    return False


def classify_email_type(email: str | None, brand_token: str = '') -> str | None:
    if not email or '@' not in email:
        return None
    local, domain = email.split('@', 1)
    local = local.lower()
    domain = domain.lower()
    domain_root = domain.split('.')[0]
    normalized_local = re.sub(r'[._+-]', '', local)
    tokens = [t for t in re.split(r'[._+-]', local) if t]
    first_token = tokens[0] if tokens else local

    if domain in PUBLIC_WEBMAIL_DOMAINS and brand_token and brand_token in normalized_local:
        if _matches_prefix_safely(local, normalized_local, tokens, SUPPORT_PREFIXES):
            return 'brand_webmail_support_inbox'
        if _matches_prefix_safely(local, normalized_local, tokens, PR_MEDIA_PREFIXES):
            return 'pr_and_media_inbox'
        return 'brand_webmail_general_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, LOW_PRIORITY_PREFIXES):
        return 'legal_or_hr_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, INFLUENCER_PREFIXES):
        return 'influencer_gifting_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, B2B_PARTNERSHIP_PREFIXES):
        return 'b2b_partnerships'

    if local in REGIONAL_BRANCH_LOCALS or first_token in REGIONAL_BRANCH_LOCALS:
        return 'regional_branch_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, DEPARTMENT_OR_ADMISSIONS_PREFIXES):
        return 'admissions_or_department_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, MARKETING_EXEC_PREFIXES):
        return 'marketing_or_exec_role'

    if _matches_prefix_safely(local, normalized_local, tokens, WHOLESALE_MERCH_PREFIXES):
        return 'wholesale_or_sales_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, GENERAL_OFFICE_PREFIXES):
        return 'general_office_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, SUPPORT_PREFIXES):
        return 'customer_support_inbox'

    if _matches_prefix_safely(local, normalized_local, tokens, PR_MEDIA_PREFIXES):
        return 'pr_and_media_inbox'

    if domain not in PUBLIC_WEBMAIL_DOMAINS and len(tokens) == 2 and all(t.isalpha() for t in tokens):
        if tokens[0] not in NON_PERSON_TOKENS and tokens[1] not in NON_PERSON_TOKENS and tokens[1] != domain_root:
            if (len(tokens[0]) == 1 and len(tokens[1]) >= 3) or (len(tokens[0]) >= 3 and len(tokens[1]) >= 3):
                return 'personal_or_named_inbox'

    return 'department_or_general_inbox'


def transliterate_ua_to_latin(text: str) -> str:
    out = []
    for ch in text.lower():
        if ch in UA_TO_LATIN:
            out.append(UA_TO_LATIN[ch])
        elif ch in EU_DIACRITIC_MAP:
            out.append(EU_DIACRITIC_MAP[ch])
        else:
            out.append(ch)
    return ''.join(out)


def verify_person_email_match(full_name: str | None, email: str | None) -> bool:
    """
    P1 #9: Personal email match v2.
    Підтримує: first.last, flast, firstlast, last.first, lfirst, а також точний збіг імені (first@domain)
    або прізвища (last@domain), якщо токен не входить у NON_PERSON_TOKENS.
    """
    if not full_name or not email or '@' not in email:
        return False
    local = email.split('@', 1)[0].lower().strip()
    if local in NON_PERSON_TOKENS:
        return False

    name_parts = [p.strip() for p in full_name.split() if len(p.strip()) >= 2]
    if len(name_parts) < 2:
        return False

    first_lat = re.sub(r'[^a-z]', '', transliterate_ua_to_latin(name_parts[0]))
    last_raw = name_parts[-1].split('-')[0]
    last_lat = re.sub(r'[^a-z]', '', transliterate_ua_to_latin(last_raw))
    if len(last_lat) < 3 or len(first_lat) < 2:
        return False

    norm_local = re.sub(r'[^a-z]', '', local)
    first_init = first_lat[0]
    last_init = last_lat[0]
    last_prefix = last_lat[:5] if len(last_lat) >= 5 else last_lat

    # 1. Exact first+last або last+first
    if norm_local in (f'{first_lat}{last_lat}', f'{last_lat}{first_lat}'):
        return True

    # 2. Substring both first & last prefix
    if len(first_lat) >= 3 and first_lat in local and last_prefix in local:
        return True

    # 3. Initial + last_prefix або last_prefix + initial (flast, f.last, last.f)
    pattern = (
        rf'^(?:{re.escape(first_init)}[._-]?{re.escape(last_prefix)}'
        rf'|{re.escape(last_prefix)}[._-]?{re.escape(first_init)}'
        rf'|{re.escape(first_lat)}[._-]?{re.escape(last_init)})$'
    )
    if re.search(pattern, local):
        return True

    # 4. Exact first_name@domain або last_name@domain (для founder/exec пошт типу benjamin@ або kosovan@)
    if (local == first_lat and len(first_lat) >= 4) or (local == last_lat and len(last_lat) >= 4):
        return True

    return False


def verify_person_linkedin_match(full_name: str | None, linkedin_url: str | None) -> bool:
    if not full_name or not linkedin_url or '/in/' not in linkedin_url.lower():
        return False
    slug = linkedin_url.lower().split('/in/', 1)[1].split('/')[0].split('?')[0]
    slug_clean = re.sub(r'[^a-z]', '', slug)
    name_parts = [p.strip() for p in full_name.split() if len(p.strip()) >= 2]
    if len(name_parts) < 2:
        return False

    first_lat = re.sub(r'[^a-z]', '', transliterate_ua_to_latin(name_parts[0]))
    last_lat = re.sub(r'[^a-z]', '', transliterate_ua_to_latin(name_parts[-1].split('-')[0]))

    has_last = len(last_lat) >= 4 and last_lat[:4] in slug_clean
    has_first = len(first_lat) >= 3 and first_lat[:3] in slug_clean
    return has_last and has_first


async def query_doh_json(client: AsyncSession, domain: str, record_type: str) -> tuple[dict | None, str]:
    endpoints = [
        f'https://dns.google/resolve?name={domain}&type={record_type}',
        f'https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}',
        f'https://dns.quad9.net:5053/dns-query?name={domain}&type={record_type}',
    ]
    last_status = 'dns_error'
    for ep in endpoints:
        for use_direct in (False, True):
            try:
                kwargs = {
                    'headers': {'accept': 'application/dns-json'},
                    'timeout': 4.5,
                }
                if use_direct:
                    kwargs['proxy'] = None
                resp = await client.get(ep, **kwargs)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        return data, 'ok'
            except Exception as e:
                if 'timeout' in str(e).lower():
                    last_status = 'dns_timeout'
                continue
    return None, last_status


async def verify_email_deliverability_deep(
    client: AsyncSession,
    email: str | None,
    source_url: str | None
) -> str | None:
    if not email or '@' not in email:
        return None
    domain = email.split('@', 1)[1].strip().lower()
    is_public_webmail = domain in PUBLIC_WEBMAIL_DOMAINS

    dom_lock = _DNS_DOMAIN_LOCKS.setdefault(domain, asyncio.Lock())
    async with dom_lock:
        if domain in DNS_MEMORY_CACHE:
            provider, has_spf, err_code = DNS_MEMORY_CACHE[domain]
        else:
            provider = None
            has_spf = False
            mx_data, err_code = await query_doh_json(client, domain, 'MX')
            if mx_data is not None:
                answers = mx_data.get('Answer', [])
                mx_hosts = [str(ans.get('data', '')).lower() for ans in answers if ans.get('type') == 15]
                if mx_hosts:
                    joined_mx = ' '.join(mx_hosts)
                    if 'google.com' in joined_mx or 'googlemail.com' in joined_mx:
                        provider = 'Google' if is_public_webmail else 'Google Workspace'
                    elif 'outlook.com' in joined_mx or 'protection.outlook.com' in joined_mx:
                        provider = 'Microsoft' if is_public_webmail else 'Microsoft 365'
                    elif 'pphosted.com' in joined_mx or 'proofpoint' in joined_mx:
                        provider = 'Proofpoint Enterprise'
                    elif 'mimecast.com' in joined_mx:
                        provider = 'Mimecast Enterprise'
                    elif 'barracudanetworks.com' in joined_mx:
                        provider = 'Barracuda Gateway'
                    elif 'route.mx.cloudflare.net' in joined_mx:
                        provider = 'Cloudflare Email'
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

            if provider or err_code == 'dns_no_mx_records':
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


def reject_external_domain_pollution(
    valid: dict[str, str],
    base_domain: str
) -> tuple[dict[str, str], bool]:
    if not valid:
        return valid, False
    base_brand = base_domain.split('.')[0].lower() if base_domain else ''

    def is_native_or_brand_alias(addr: str) -> bool:
        local, dom = addr.split('@', 1)
        dom_root = dom.split('.')[0]
        norm_local = re.sub(r'[._+-]', '', local.lower())
        if dom == base_domain or dom.endswith(f'.{base_domain}'):
            return True
        if base_brand and len(base_brand) >= 3 and (dom_root == base_brand or base_brand in dom_root or dom_root in base_brand):
            return True
        if dom in PUBLIC_WEBMAIL_DOMAINS and base_brand and base_brand in norm_local:
            return True
        return False

    native_subset = {addr: src for addr, src in valid.items() if is_native_or_brand_alias(addr)}
    if native_subset:
        return native_subset, False

    return {}, True


def rank_and_clean_emails(
    email_sources: dict[str, str],
    base_domain: str
) -> tuple[list[tuple[str, str]], bool]:
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

        if 'sentry.' in domain_part or HEX_HASH_LOCAL_REGEX.match(local_part):
            continue

        if base_domain and domain_part != base_domain and domain_part.endswith(f'.{base_domain}'):
            sub_prefix = domain_part[:-len(base_domain)]
            if sub_prefix in SENDER_SUBDOMAIN_PREFIXES:
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

    valid, had_external_pollution = reject_external_domain_pollution(valid, base_domain)

    type_weights = {
        'marketing_or_exec_role': 35,
        'personal_or_named_inbox': 32,
        'b2b_partnerships': 28,
        'wholesale_or_sales_inbox': 25,
        'general_office_inbox': 24,
        'brand_webmail_general_inbox': 20,
        'department_or_general_inbox': 15,
        'regional_branch_inbox': 14,
        'brand_webmail_support_inbox': 12,
        'influencer_gifting_inbox': 11,
        'admissions_or_department_inbox': 10,
        'customer_support_inbox': 8,
        'pr_and_media_inbox': 5,
        'legal_or_hr_inbox': -40
    }

    def email_score(addr: str) -> tuple[int, str]:
        _, domain = addr.split('@', 1)
        dom_root = domain.split('.')[0]
        score = 0
        if base_domain and domain == base_domain:
            score += 25
        elif base_domain and domain.endswith(f'.{base_domain}'):
            score += 18
        elif base_brand and dom_root == base_brand:
            score += 20
        elif base_brand and base_brand in dom_root:
            score += 8
        email_type = classify_email_type(addr, base_brand)
        score += type_weights.get(email_type or '', 0)
        return (-score, addr)

    sorted_addrs = sorted(valid.keys(), key=email_score)
    return [(addr, valid[addr]) for addr in sorted_addrs], had_external_pollution


def classify_email_source_type_and_note(
    best_email: str | None,
    best_email_type: str | None,
    email_source_url: str | None,
    pages_with_urls: list[tuple[str, str, str]]
) -> tuple[str | None, str | None]:
    if not best_email or not email_source_url:
        return None, None
    em_low = best_email.lower()
    em_dom = em_low.split('@', 1)[1] if '@' in em_low else ''
    parsed_src = urlparse(email_source_url)
    src_host = re.sub(r':\d+$', '', parsed_src.netloc.lower().replace('www.', ''))
    path_low = parsed_src.path.lower()

    alias_suffix = ''
    if em_dom and src_host and em_dom != src_host and not em_dom.endswith(f'.{src_host}'):
        if em_dom in PUBLIC_WEBMAIL_DOMAINS:
            alias_suffix = f', mailbox hosted on public webmail ({em_dom})'
        else:
            alias_suffix = f', mailbox on brand alias {em_dom}'

    in_footer = False
    for p_url, html, _ in pages_with_urls:
        if (clean_url_port(p_url) or p_url) == (clean_url_port(email_source_url) or email_source_url):
            soup = BeautifulSoup(html, 'lxml')
            for f_tag in soup.find_all(['footer', 'nav']):
                if em_low in f_tag.get_text(' ', strip=True).lower() or em_low in str(f_tag).lower():
                    in_footer = True
                    break
            if not in_footer:
                for el in soup.find_all(attrs={'class': re.compile(r'footer|bottom-bar|copyright', re.I)}):
                    if em_low in el.get_text(' ', strip=True).lower() or em_low in str(el).lower():
                        in_footer = True
                        break
            if not in_footer:
                for el in soup.find_all(attrs={'id': re.compile(r'footer', re.I)}):
                    if em_low in el.get_text(' ', strip=True).lower() or em_low in str(el).lower():
                        in_footer = True
                        break

    if in_footer:
        return (
            'site_footer',
            f'Found in site footer/navigation on {email_source_url} ({best_email_type}){alias_suffix}'
        )

    if any(k in path_low for k in ('contact', 'kontakt', 'kontakty', 'impressum', 'get-in-touch')):
        return 'contact_page', f'Published on dedicated contact page ({email_source_url}){alias_suffix}'

    if DM_LEGAL_SOURCE_FLAG.search(path_low) or 'privacy' in path_low or 'terms' in path_low:
        if best_email_type in ('general_office_inbox', 'b2b_partnerships', 'wholesale_or_sales_inbox', 'customer_support_inbox'):
            return (
                'site_footer',
                f'General/B2B inbox ({best_email}) listed on {path_low} (safe for gatekeeper/routing){alias_suffix}'
            )
        return 'legal_or_terms_page', f'Listed on legal/terms page ({path_low}){alias_suffix}'

    if any(k in path_low for k in ('support', 'help', 'care', 'faq')):
        if best_email_type == 'b2b_partnerships':
            return (
                'support_or_footer',
                f'B2B/Corporate partnership email ({best_email}) listed in contact directory on {path_low}{alias_suffix}'
            )
        return 'support_or_footer', f'Listed on support/help directory page ({path_low}){alias_suffix}'

    if path_low in ('', '/', '/ua/', '/uk/', '/en/', '/uk-ua/'):
        if alias_suffix:
            return 'homepage', f'Published on {src_host} homepage{alias_suffix}'
        return 'homepage', 'Published directly on homepage'

    return 'page_body', f'Extracted from page body ({path_low}){alias_suffix}'


def extract_named_email_owner_hint(
    best_email: str | None,
    best_email_type: str | None,
    pages_with_urls: list[tuple[str, str, str]]
) -> str | None:
    if not best_email or best_email_type != 'personal_or_named_inbox':
        return None
    em_low = best_email.lower()
    local_part = best_email.split('@', 1)[0]

    for _, html, text in pages_with_urls:
        soup = BeautifulSoup(html, 'lxml')
        for a_tag in soup.find_all('a', href=True):
            if em_low in a_tag['href'].lower() or em_low in a_tag.get_text().lower():
                curr = a_tag
                for _ in range(4):
                    curr = curr.find_parent(['li', 'tr', 'td', 'p', 'div', 'article', 'section'])
                    if not curr:
                        break
                    c_txt = ' '.join(curr.get_text(' ', strip=True).split())
                    cleaned_ctx = re.sub(re.escape(best_email), '', c_txt, flags=re.IGNORECASE).strip(' —–-:|,;')
                    has_role = any(rw in cleaned_ctx.lower() for rw in ROLE_WORDS_IN_CONTEXT)
                    if has_role and 8 <= len(cleaned_ctx) <= 220:
                        return textwrap.shorten(f'{local_part}: {cleaned_ctx}', width=140, placeholder='…')

        idx = text.lower().find(em_low)
        if idx != -1:
            start = max(0, idx - 110)
            end = min(len(text), idx + len(best_email) + 90)
            snippet = ' '.join(text[start:end].split())
            cleaned_snip = re.sub(re.escape(best_email), '', snippet, flags=re.IGNORECASE).strip(' —–-:|,;')
            if any(rw in cleaned_snip.lower() for rw in ROLE_WORDS_IN_CONTEXT) and len(cleaned_snip) >= 8:
                return textwrap.shorten(f'{local_part}: {cleaned_snip}', width=140, placeholder='…')

    return f'Named staff inbox ({local_part}) — role not found on site, verify on LinkedIn'


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
        tg_slug = segments_lower[0]
        if tg_slug.startswith('+') or len(tg_slug) < 4:
            return None
        if tg_slug in TELEGRAM_PLACEHOLDER_SLUGS:
            return None
        tg_parts = [p for p in re.split(r'[._-]', tg_slug) if p]
        if any(p in TELEGRAM_PLACEHOLDER_SLUGS for p in tg_parts):
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
    digits = re.sub(r'\D', '', e164)
    if not digits:
        return True
    if re.search(r'(?:1234567|123456|1111111|0000000|9999999|123456789)$', digits):
        return True
    if len(set(digits[-7:])) <= 2 and len(digits) >= 9:
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
    preferred_prefix = REGION_DIALING_PREFIX_MAP.get(default_region.upper(), '')

    for raw_tel, context in raw_tel_candidates:
        try:
            parsed = phonenumbers.parse(raw_tel, default_region)
            if phonenumbers.is_valid_number(parsed):
                e164_chk = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                if is_junk_phone(e164_chk):
                    continue
                formatted = phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                )
                region_bonus = 35 if (preferred_prefix and e164_chk.startswith(preferred_prefix)) else 0
                ctx_score = 15 + region_bonus + score_phone_context(context)
                if formatted not in phone_scores or ctx_score > phone_scores[formatted]:
                    phone_scores[formatted] = ctx_score
                if formatted not in phone_order:
                    phone_order[formatted] = order_counter
                    order_counter += 1
        except phonenumbers.NumberParseException:
            continue

    for match in phonenumbers.PhoneNumberMatcher(text, default_region):
        if phonenumbers.is_valid_number(match.number):
            e164_chk = phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164)
            if is_junk_phone(e164_chk):
                continue
            formatted = phonenumbers.format_number(
                match.number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            start_idx = max(0, match.start - 90)
            end_idx = min(len(text), match.end + 90)
            context = text[start_idx:end_idx]
            region_bonus = 35 if (preferred_prefix and e164_chk.startswith(preferred_prefix)) else 0
            ctx_score = region_bonus + score_phone_context(context)

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


def classify_dm_source_type(dm_source_url: str | None) -> str | None:
    if not dm_source_url:
        return None
    path_low = urlparse(dm_source_url).path.lower()
    if IMPRESSUM_CANONICAL_PATH_REGEX.search(path_low):
        return 'impressum_page'
    if DM_LEGAL_SOURCE_FLAG.search(path_low):
        return 'legal_or_offer_page'
    if any(k in path_low for k in ('/team', '/komanda', '/leadership', '/management', '/founders', '/zespol', '/equipe')):
        return 'team_page'
    if any(k in path_low for k in (
        '/about', '/pro-nas', '/o-nas', '/company', '/our-story',
        '/uber-uns', '/ueber-uns', '/qui-sommes-nous', '/a-propos',
        '/quienes-somos', '/chi-siamo', '/over-ons', '/o-firmie', '/om-oss'
    )):
        return 'about_page'
    if any(k in path_low for k in ('/blog', '/news', '/article', '/post', '/media', '/press')):
        return 'blog_or_press_page'
    if path_low in ('', '/', '/ua/', '/uk/', '/en/', '/uk-ua/', '/de/', '/fr/', '/pl/', '/es/', '/it/', '/nl/'):
        return 'homepage'
    return 'product_or_service_page'


def strip_role_tokens_from_name(candidate: str) -> str:
    words = [w.strip('.,;:()[]"\'') for w in candidate.strip().split() if w.strip('.,;:()[]"\'')]
    words = [w.rstrip('-').lstrip('-') for w in words if w.rstrip('-').lstrip('-')]
    while words and (
        words[0].lower() in ROLE_TOKEN_BLACKLIST
        or words[0].lower() in DEPARTMENT_PREFIX_BLACKLIST
        or words[0].lower() in CITY_NAMES_BLACKLIST
        or words[0].lower() in CORPORATE_ENTITY_TOKENS
        or words[0].isupper()
        or re.fullmatch(ROLES_REGEX_PART, words[0], re.IGNORECASE)
    ):
        words.pop(0)
    while words and (
        words[-1].lower() in ROLE_TOKEN_BLACKLIST
        or words[-1].lower() in DEPARTMENT_PREFIX_BLACKLIST
        or words[-1].lower() in CITY_NAMES_BLACKLIST
        or words[-1].lower() in CORPORATE_ENTITY_TOKENS
        or words[-1].isupper()
        or re.fullmatch(ROLES_REGEX_PART, words[-1], re.IGNORECASE)
    ):
        words.pop(-1)
    has_cyrillic = any(re.search(r'[а-яіїєґА-ЯІЇЄҐ]', w) for w in words)
    if has_cyrillic:
        while words and re.fullmatch(r'[A-Za-z\'-]+', words[0]):
            words.pop(0)
    if len(words) == 3 and ('-' in words[1] or '-' in words[0]):
        words = words[:2]
    return ' '.join(words)


def is_valid_person_name(candidate: str, brand_root: str = '') -> bool:
    """
    P0 #2 Fix: Відсікає корпоративні сутності (BPO Capital, GFH Gesellschaft, YOU Verwaltungs)
    та будь-які токени з капс-абревіатурами або суфіксами юросіб.
    """
    words = [w.strip('.,;:()[]"\'') for w in candidate.strip().split() if w.strip('.,;:()[]"\'')]
    if len(words) not in (2, 3):
        return False
    if not all(w and w[0].isupper() and len(w) >= 2 for w in words):
        return False
    # Якщо будь-яке слово повністю у верхньому регістрі (BPO, GFH, YOU, AG, SE) — це юрособа/абревіатура, не людина
    if any(w.isupper() for w in words):
        return False
    words_low = [w.lower() for w in words]
    if any(
        wl in _STOP_NAME_WORDS_LOWER
        or wl in ROLE_TOKEN_BLACKLIST
        or wl in DEPARTMENT_PREFIX_BLACKLIST
        or wl in CITY_NAMES_BLACKLIST
        or wl in CORPORATE_ENTITY_TOKENS
        for wl in words_low
    ):
        return False
    # Перевірка на типові німецькі корпоративні закінчення (-gesellschaft, -verwaltung, -beteiligung, -stiftung)
    if any(wl.endswith(('gesellschaft', 'verwaltung', 'verwaltungs', 'beteiligung', 'stiftung', 'holding', 'konzern')) for wl in words_low):
        return False
    if any(re.fullmatch(ROLES_REGEX_PART, w, re.IGNORECASE) for w in words):
        return False
    if brand_root:
        b_low = brand_root.lower()
        joined_low = ''.join(words_low)
        if joined_low == b_low or b_low in words_low:
            return False
    return True


def normalize_executive_role(raw_role: str | None) -> str | None:
    if not raw_role:
        return None
    clean = raw_role.strip(' .,;:|-–—')
    return ROLE_NORMALIZATION_MAP.get(clean.lower(), clean)


def strip_testimonial_elements_and_get_clean_text(soup: BeautifulSoup) -> str:
    for tag in soup.find_all(['blockquote', 'cite', 'q']):
        tag.decompose()
    return soup.get_text(' ', strip=True)


def is_text_match_in_testimonial_window(text: str, match_start: int, match_end: int, cand_name: str = '') -> bool:
    if cand_name.strip().lower() in FOREIGN_TESTIMONIAL_NAMES_BLACKLIST:
        return True
    win_start = max(0, match_start - 200)
    win_end = min(len(text), match_end + 140)
    window = text[win_start:win_end]
    win_low = window.lower()
    if any(m in win_low for m in TESTIMONIAL_TEXT_MARKERS):
        return True
    before_slice = text[max(0, match_start - 80):match_start]
    if any(q in before_slice for q in ('«', '»', '“', '”', '„')):
        return True
    return False


def is_low_trust_legal_offer_page(path: str) -> bool:
    if IMPRESSUM_CANONICAL_PATH_REGEX.search(path):
        return False
    return bool(DM_LEGAL_SOURCE_FLAG.search(path))


def build_decision_makers_json_from_summary(
    dms_summary_str: str | None,
    primary_li_url: str | None = None
) -> str | None:
    """
    Конвертує semicolon-рядок decision_makers_found (або кешований запис) у валідний JSON-масив,
    відфільтровуючи будь-які застарілі корпоративні сутності (BPO Capital, GFH Gesellschaft, YOU Verwaltungs).
    """
    if not dms_summary_str:
        return None
    items = []
    seen = set()
    for part in dms_summary_str.split(';'):
        part = part.strip()
        if not part:
            continue
        m = re.match(r'^(.+?)\s*\((.+?)\)\s*\[(.+?)\]$', part)
        if not m:
            continue
        raw_name, raw_role, src_url = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        clean_name = strip_role_tokens_from_name(raw_name)
        if not is_valid_person_name(clean_name):
            continue
        if clean_name.lower() in seen:
            continue
        seen.add(clean_name.lower())
        norm_role = normalize_executive_role(raw_role) or raw_role
        src_type = classify_dm_source_type(src_url)
        matched_li = primary_li_url if (primary_li_url and verify_person_linkedin_match(clean_name, primary_li_url)) else None
        conf = 'high' if (matched_li or src_type in ('impressum_page', 'team_page', 'about_page')) else 'medium'
        items.append({
            'name': clean_name,
            'role': norm_role,
            'linkedin_url': matched_li,
            'source_url': src_url,
            'source_type': src_type,
            'confidence': conf,
            'is_verified_person': True
        })
    return json.dumps(items, ensure_ascii=False) if items else None


def extract_decision_maker_deep(
    pages_with_urls: list[tuple[str, str, str]]
) -> tuple[str | None, str | None, str | None, str | None, bool, str | None, str | None, str | None]:
    """
    Повертає 8 значень:
    (dm_name, dm_role, dm_linkedin_url, dm_source_url, dm_source_is_legal, dm_source_type, dms_summary_str, dms_json_str)
    """
    candidate_li_urls: list[str] = []
    found_dms_by_name: dict[str, dict] = {}

    brand_root = ''
    if pages_with_urls:
        first_host = urlparse(pages_with_urls[0][0]).netloc.lower().replace('www.', '')
        brand_root = first_host.split('.')[0] if first_host else ''

    for page_url, html, _ in pages_with_urls:
        url_path = urlparse(page_url).path
        if DM_SOURCE_BLACKLIST.search(url_path):
            continue
        soup = BeautifulSoup(html, 'lxml')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            if 'linkedin.com/in/' in href.lower():
                parsed = urlparse(href)
                if parsed.scheme in ('http', 'https'):
                    clean_li = f"https://www.linkedin.com{parsed.path.rstrip('/')}"
                    if clean_li not in candidate_li_urls:
                        candidate_li_urls.append(clean_li)

    def add_dm_candidate(name: str, role: str | None, page_url: str, is_leg: bool, base_priority: int):
        norm_name = strip_role_tokens_from_name(name)
        if not is_valid_person_name(norm_name, brand_root):
            return
        name_key = norm_name.lower()
        if name_key in FOREIGN_TESTIMONIAL_NAMES_BLACKLIST:
            return
        clean_src = clean_url_port(page_url) or page_url
        src_type = classify_dm_source_type(clean_src)
        matched_li = next((u for u in candidate_li_urls if verify_person_linkedin_match(norm_name, u)), None)
        norm_role = normalize_executive_role(role) or 'Executive'

        type_bonus = {
            'impressum_page': 32,
            'team_page': 30,
            'about_page': 25,
            'homepage': 15,
            'product_or_service_page': 10,
            'blog_or_press_page': 5,
            'legal_or_offer_page': 8
        }.get(src_type or '', 5)

        role_low = norm_role.lower()
        if 'supervisory' in role_low or 'aufsichtsrat' in role_low:
            role_bonus = -30
        elif src_type == 'product_or_service_page' and 'ceo' in role_low and 'founder' not in role_low:
            role_bonus = -10
        elif any(k in role_low for k in ('marketing', 'cmo', 'e-commerce', 'growth', 'digital')):
            role_bonus = 22
        elif any(k in role_low for k in ('ceo', 'founder', 'co-founder', 'owner', 'managing director')):
            role_bonus = 18
        else:
            role_bonus = 5

        li_bonus = 60 if matched_li else 0
        total_score = base_priority + type_bonus + role_bonus + li_bonus
        conf = 'high' if (matched_li or src_type in ('impressum_page', 'team_page', 'about_page')) else 'medium'

        existing = found_dms_by_name.get(name_key)
        if existing is None or total_score > existing['score']:
            found_dms_by_name[name_key] = {
                'name': norm_name,
                'role': norm_role,
                'li_url': matched_li or (existing['li_url'] if existing else None),
                'source_url': clean_src,
                'source_type': src_type,
                'confidence': conf,
                'is_legal': is_leg,
                'score': total_score
            }
        elif matched_li and not existing.get('li_url'):
            existing['li_url'] = matched_li
            existing['score'] += 60
            existing['confidence'] = 'high'

    for page_url, html, _ in pages_with_urls:
        url_path = urlparse(page_url).path
        if DM_SOURCE_BLACKLIST.search(url_path):
            continue

        soup = BeautifulSoup(html, 'lxml')
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
                    if str(item.get('@type', '')).lower() in ('review', 'claimreview', 'quotation'):
                        continue
                    for key, default_role in (('founder', 'Founder'), ('founders', 'Founder'), ('employee', 'Executive')):
                        val = item.get(key)
                        if isinstance(val, dict) and val.get('name'):
                            cand = strip_role_tokens_from_name(str(val['name']))
                            role = normalize_executive_role(str(val.get('jobTitle') or default_role))
                            if is_valid_person_name(cand, brand_root):
                                is_leg = is_low_trust_legal_offer_page(url_path)
                                add_dm_candidate(cand, role, page_url, is_leg, 40)
                        elif isinstance(val, list):
                            for sub in val:
                                if isinstance(sub, dict) and sub.get('name'):
                                    cand = strip_role_tokens_from_name(str(sub['name']))
                                    role = normalize_executive_role(str(sub.get('jobTitle') or default_role))
                                    if is_valid_person_name(cand, brand_root):
                                        is_leg = is_low_trust_legal_offer_page(url_path)
                                        add_dm_candidate(cand, role, page_url, is_leg, 40)
            except Exception:
                continue

    for page_url, html, _ in pages_with_urls:
        url_path = urlparse(page_url).path
        if DM_SOURCE_BLACKLIST.search(url_path):
            continue
        is_leg = is_low_trust_legal_offer_page(url_path)

        clean_soup = BeautifulSoup(html, 'lxml')
        dm_clean_text = strip_testimonial_elements_and_get_clean_text(clean_soup)

        for vm in VERTRETEN_DURCH_PATTERN.finditer(dm_clean_text):
            cand_name = strip_role_tokens_from_name(vm.group(1))
            if is_valid_person_name(cand_name, brand_root):
                add_dm_candidate(cand_name, 'Chief Executive Officer (CEO)', page_url, is_leg, 45)

        for m in NAME_BEFORE_ROLE_PATTERN.finditer(dm_clean_text):
            cand_name = strip_role_tokens_from_name(m.group(1))
            if is_text_match_in_testimonial_window(dm_clean_text, m.start(), m.end(), cand_name):
                continue
            cand_role = normalize_executive_role(m.group(2))
            ctx_slice = dm_clean_text[max(0, m.start() - 55):min(len(dm_clean_text), m.end() + 55)].lower()
            if 'aufsichtsrat' in ctx_slice:
                continue
            if is_valid_person_name(cand_name, brand_root):
                add_dm_candidate(cand_name, cand_role, page_url, is_leg, 25)

        for m in ROLE_BEFORE_NAME_PATTERN.finditer(dm_clean_text):
            cand_name = strip_role_tokens_from_name(m.group(2))
            if is_text_match_in_testimonial_window(dm_clean_text, m.start(), m.end(), cand_name):
                continue
            cand_role = normalize_executive_role(m.group(1))
            ctx_slice = dm_clean_text[max(0, m.start() - 55):min(len(dm_clean_text), m.end() + 55)].lower()
            if 'aufsichtsrat' in ctx_slice:
                continue
            if is_valid_person_name(cand_name, brand_root):
                add_dm_candidate(cand_name, cand_role, page_url, is_leg, 25)

    for page_url, _, page_text in pages_with_urls:
        url_path = urlparse(page_url).path
        if DM_SOURCE_BLACKLIST.search(url_path):
            continue
        is_leg = is_low_trust_legal_offer_page(url_path)
        for m in FOP_OWNER_PATTERN.finditer(page_text):
            cand_name = strip_role_tokens_from_name(m.group(1))
            if is_valid_person_name(cand_name, brand_root):
                add_dm_candidate(cand_name, 'Registered Business Owner / ФОП', page_url, is_leg, 10)

    if not found_dms_by_name:
        return None, None, None, None, False, None, None, None

    found_dms = sorted(found_dms_by_name.values(), key=lambda d: (-d['score'], d['name']))
    primary = found_dms[0]
    top_dms = found_dms[:5]
    dms_summary_str = '; '.join(
        f"{d['name']} ({d['role']}) [{d['source_url']}]" for d in top_dms
    )
    dms_json_list = [
        {
            'name': d['name'],
            'role': d['role'],
            'linkedin_url': d['li_url'],
            'source_url': d['source_url'],
            'source_type': d['source_type'],
            'confidence': d['confidence'],
            'is_verified_person': True
        }
        for d in top_dms
    ]
    dms_json_str = json.dumps(dms_json_list, ensure_ascii=False)
    return (
        primary['name'],
        primary['role'],
        primary['li_url'],
        primary['source_url'],
        primary['is_legal'],
        primary['source_type'],
        dms_summary_str,
        dms_json_str
    )
