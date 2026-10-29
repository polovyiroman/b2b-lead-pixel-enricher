import asyncio
import json
import os
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

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
    UI_ACTION_WORDS_BLACKLIST,
    VERTRETEN_DURCH_PATTERN,
    WHOLESALE_MERCH_PREFIXES,
    clean_url_port,
)

_DNS_MX_CACHE: dict[str, str] = {}
_DNS_DOMAIN_LOCKS: dict[str, asyncio.Lock] = {}


def decode_cf_email(cf_hex: str) -> str | None:
    try:
        r = int(cf_hex[:2], 16)
        return ''.join(
            chr(int(cf_hex[i:i + 2], 16) ^ r)
            for i in range(2, len(cf_hex), 2)
        )
    except Exception:
        return None


def transliterate_ua_to_latin(text: str) -> str:
    return ''.join(UA_TO_LATIN.get(ch, ch) for ch in text.lower())


def normalize_executive_role(raw_role: str | None) -> str | None:
    if not raw_role:
        return None
    clean = ' '.join(str(raw_role).split()).strip(' ,—–-:|()•')
    low = clean.lower()
    if low in ROLE_NORMALIZATION_MAP:
        return ROLE_NORMALIZATION_MAP[low]
    for k, v in ROLE_NORMALIZATION_MAP.items():
        if re.search(rf'\b{re.escape(k)}\b', low):
            return v
    return clean


def strip_role_tokens_from_name(raw_name: str) -> str:
    if not raw_name:
        return ''
    cleaned = re.sub(r'^(?:Dr\.|Prof\.|Mag\.|Dipl\.-Ing\.|Ing\.|Mr\.|Mrs\.|Ms\.)\s+', '', raw_name.strip(), flags=re.I)
    tokens = [t.strip(' ,—–-:|()•.') for t in cleaned.split() if t.strip(' ,—–-:|()•.')]
    kept: list[str] = []
    for tok in tokens:
        t_low = tok.lower()
        if t_low in ROLE_TOKEN_BLACKLIST or t_low in STOP_NAME_WORDS or tok in STOP_NAME_WORDS:
            continue
        if t_low in CITY_NAMES_BLACKLIST or t_low in CORPORATE_ENTITY_TOKENS:
            continue
        kept.append(tok)
    return ' '.join(kept[:3])


def is_valid_person_name(candidate: str | None, brand_root: str = '') -> bool:
    if not candidate:
        return False
    clean = ' '.join(candidate.split()).strip()
    if len(clean) < 5 or len(clean) > 48:
        return False
    low = clean.lower()
    if low in FOREIGN_TESTIMONIAL_NAMES_BLACKLIST:
        return False
    if any(ch.isdigit() for ch in clean):
        return False
    parts = clean.split()
    if len(parts) < 2 or len(parts) > 3:
        return False
    b_low = (brand_root or '').lower().strip()
    for p in parts:
        p_clean = p.strip('.,-’\'')
        p_low = p_clean.lower()
        if len(p_clean) < 2:
            return False
        if not p_clean[0].isupper():
            return False
        if p_clean in STOP_NAME_WORDS or p_low in ROLE_TOKEN_BLACKLIST:
            return False
        if p_low in CITY_NAMES_BLACKLIST or p_low in CORPORATE_ENTITY_TOKENS:
            return False
        if p_low in DEPARTMENT_PREFIX_BLACKLIST or p_low in UI_ACTION_WORDS_BLACKLIST:
            return False
        if b_low and len(b_low) >= 4 and p_low == b_low and p_low not in ('otto',):
            return False
        for sub_part in p_clean.split('-'):
            if not sub_part or len(sub_part) < 2:
                return False
            if sub_part.lower() in CORPORATE_ENTITY_TOKENS or sub_part.lower() in CITY_NAMES_BLACKLIST:
                return False
    return True


def verify_person_email_match(dm_name: str | None, email: str | None) -> bool:
    if not dm_name or not email or '@' not in email:
        return False
    local = email.split('@', 1)[0].lower()
    if local in NON_PERSON_TOKENS:
        return False
    parts = [transliterate_ua_to_latin(p) for p in dm_name.split() if len(p) >= 2]
    if len(parts) < 2:
        return False
    first_n, last_n = re.sub(r'[^a-z]', '', parts[0]), re.sub(r'[^a-z]', '', parts[-1])
    norm_local = re.sub(r'[^a-z]', '', local)
    if len(first_n) >= 3 and len(last_n) >= 3:
        if first_n in norm_local and last_n in norm_local:
            return True
        if norm_local == f'{first_n[0]}{last_n}' or norm_local == f'{last_n}{first_n[0]}':
            return True
    return False


def verify_person_linkedin_match(dm_name: str | None, linkedin_url: str | None) -> bool:
    if not dm_name or not linkedin_url or 'linkedin.com/in/' not in linkedin_url.lower():
        return False
    slug = linkedin_url.lower().split('linkedin.com/in/', 1)[1].split('/')[0].split('?')[0]
    slug_clean = re.sub(r'[^a-z]', '', slug)
    parts = [ re.sub(r'[^a-z]', '', transliterate_ua_to_latin(p)) for p in dm_name.split() if len(p) >= 2 ]
    parts = [p for p in parts if len(p) >= 3]
    if len(parts) < 2:
        return False
    return parts[0] in slug_clean and parts[-1] in slug_clean


def _matches_prefix_safely(local_part: str, tokens: list[str], prefix_tuple: tuple[str, ...]) -> bool:
    if local_part in prefix_tuple:
        return True
    for t in tokens:
        if t in prefix_tuple:
            return True
    for pref in prefix_tuple:
        if len(pref) >= 4 and (local_part.startswith(pref) or local_part.endswith(pref)):
            return True
    return False


def classify_email_type(email: str | None, brand_root: str = '') -> str | None:
    if not email or '@' not in email:
        return None
    local, dom = email.lower().strip().split('@', 1)
    tokens = [t for t in re.split(r'[._+\-]+', local) if t]
    norm_local = re.sub(r'[._+\-]', '', local)
    b_low = (brand_root or '').lower().strip()

    if dom in PUBLIC_WEBMAIL_DOMAINS:
        if any(s in tokens or s in norm_local for s in ('support', 'help', 'service', 'order', 'orders', 'shop')):
            return 'brand_webmail_support_inbox'
        if b_low and len(b_low) >= 3 and b_low in norm_local:
            return 'brand_webmail_general_inbox'
        return 'brand_webmail_general_inbox'

    if _matches_prefix_safely(local, tokens, LOW_PRIORITY_PREFIXES):
        return 'legal_or_hr_inbox'
    if _matches_prefix_safely(local, tokens, INFLUENCER_PREFIXES):
        return 'influencer_gifting_inbox'
    if _matches_prefix_safely(local, tokens, MARKETING_EXEC_PREFIXES):
        return 'marketing_or_exec_role'
    if _matches_prefix_safely(local, tokens, B2B_PARTNERSHIP_PREFIXES):
        return 'b2b_partnerships'
    if _matches_prefix_safely(local, tokens, WHOLESALE_MERCH_PREFIXES):
        return 'wholesale_or_sales_inbox'
    if _matches_prefix_safely(local, tokens, PR_MEDIA_PREFIXES):
        return 'pr_and_media_inbox'
    if _matches_prefix_safely(local, tokens, SUPPORT_PREFIXES):
        return 'customer_support_inbox'
    if _matches_prefix_safely(local, tokens, DEPARTMENT_OR_ADMISSIONS_PREFIXES):
        return 'admissions_or_department_inbox'
    if local in REGIONAL_BRANCH_LOCALS or any(t in REGIONAL_BRANCH_LOCALS for t in tokens):
        return 'regional_branch_inbox'
    if _matches_prefix_safely(local, tokens, GENERAL_OFFICE_PREFIXES):
        return 'general_office_inbox'

    if len(tokens) == 2 and all(len(t) >= 2 and t.isalpha() and t not in NON_PERSON_TOKENS for t in tokens):
        return 'personal_or_named_inbox'
    if len(tokens) == 1 and local.isalpha() and 3 <= len(local) <= 12 and local not in NON_PERSON_TOKENS:
        if b_low and local == b_low:
            return 'general_office_inbox'
        return 'personal_or_named_inbox'

    return 'department_or_general_inbox'


def is_valid_Scraped_email(email: str, canonical_domain: str) -> tuple[bool, bool]:
    if not email or '@' not in email or len(email) > 90:
        return False, False
    em_low = email.lower().strip().strip('.,;:/|()[]<>\"\'')
    if any(em_low.endswith(ext) for ext in JUNK_EXTENSIONS):
        return False, False
    local, dom = em_low.split('@', 1)
    if not local or not dom or '.' not in dom:
        return False, False
    tld = dom.rsplit('.', 1)[-1]
    if tld in INVALID_EMAIL_TLDS or not tld.isalpha() or len(tld) < 2:
        return False, False
    if local in JUNK_EMAIL_LOCALS or HEX_HASH_LOCAL_REGEX.match(local):
        return False, False
    if any(j in dom for j in JUNK_EMAIL_DOMAINS):
        return False, False

    c_low = (canonical_domain or '').lower().replace('www.', '')
    brand_root = c_low.split('.')[0] if c_low else ''
    if dom == c_low or dom.endswith(f'.{c_low}'):
        return True, False
    if dom in PUBLIC_WEBMAIL_DOMAINS:
        norm_l = re.sub(r'[._+\-]', '', local)
        if brand_root and len(brand_root) >= 3 and brand_root in norm_l:
            return True, False
        return False, False

    dom_root = dom.split('.')[0]
    if brand_root and len(brand_root) >= 4 and (dom_root == brand_root or brand_root in dom_root):
        return True, False

    return False, True


def rank_and_clean_emails(
    email_sources: dict[str, str],
    canonical_domain: str
) -> tuple[list[tuple[str, str]], bool]:
    brand_root = canonical_domain.split('.')[0].lower() if canonical_domain else ''
    type_weights = {
        'marketing_or_exec_role': 100,
        'personal_or_named_inbox': 92,
        'b2b_partnerships': 85,
        'wholesale_or_sales_inbox': 75,
        'general_office_inbox': 60,
        'brand_webmail_general_inbox': 50,
        'brand_webmail_support_inbox': 42,
        'regional_branch_inbox': 35,
        'admissions_or_department_inbox': 28,
        'department_or_general_inbox': 15,
        'pr_and_media_inbox': 12,
        'influencer_gifting_inbox': 10,
        'customer_support_inbox': 8,
        'legal_or_hr_inbox': 2,
    }

    cleaned: dict[str, tuple[int, str]] = {}
    had_external_pollution = False

    for raw_em, src_url in email_sources.items():
        em = raw_em.strip().strip('.,;:/|()[]<>\"\'').lower()
        is_val, is_ext = is_valid_Scraped_email(em, canonical_domain)
        if not is_val:
            if is_ext:
                had_external_pollution = True
            continue
        em_type = classify_email_type(em, brand_root) or 'department_or_general_inbox'
        score = type_weights.get(em_type, 10)
        if em not in cleaned or score > cleaned[em][0]:
            cleaned[em] = (score, src_url)

    ranked = sorted(cleaned.items(), key=lambda x: (-x[1][0], x[0]))
    return [(em, info[1]) for em, info in ranked], had_external_pollution


def classify_email_source_type_and_note(
    best_email: str | None,
    best_email_type: str | None,
    email_source_url: str | None,
    pages_with_urls: list[tuple[str, str, str]]
) -> tuple[str | None, str | None]:
    if not best_email:
        return None, None
    path = urlparse(email_source_url or '').path.lower()
    if any(k in path for k in ('impressum', 'mentions-legales', 'aviso-legal')):
        src_type = 'impressum_or_legal_page'
    elif any(k in path for k in ('contact', 'kontakt', 'kontakty', 'contatti', 'contacto')):
        src_type = 'contact_page'
    elif any(k in path for k in ('about', 'team', 'komanda', 'ueber-uns', 'uber-uns', 'pro-nas')):
        src_type = 'about_or_team_page'
    else:
        src_type = 'homepage_or_footer'

    note = f'Extracted {best_email_type} from {src_type}'
    return src_type, note


def extract_named_email_owner_hint(
    best_email: str | None,
    best_email_type: str | None,
    pages_with_urls: list[tuple[str, str, str]]
) -> str | None:
    if not best_email or best_email_type != 'personal_or_named_inbox':
        return None
    for _, _, text in pages_with_urls:
        idx = text.lower().find(best_email.lower())
        if idx != -1:
            window = text[max(0, idx - 90):min(len(text), idx + 90)]
            for rw in ROLE_WORDS_IN_CONTEXT:
                if rw in window.lower():
                    return f'Context near {best_email}: "{window.strip()[:100]}"'
    return None


async def verify_email_deliverability_deep(
    client: AsyncSession,
    email: str | None,
    source_url: str | None = None
) -> str | None:
    if not email or '@' not in email:
        return None
    dom = email.split('@', 1)[1].lower().strip()
    if dom in PUBLIC_WEBMAIL_DOMAINS:
        return f'public_webmail_provider ({dom}; MX_assumed_valid)'

    if dom in _DNS_MX_CACHE:
        return _DNS_MX_CACHE[dom]

    lock = _DNS_DOMAIN_LOCKS.setdefault(dom, asyncio.Lock())
    async with lock:
        if dom in _DNS_MX_CACHE:
            return _DNS_MX_CACHE[dom]

        doh_endpoints = (
            f'https://dns.google/resolve?name={dom}&type=MX',
            f'https://cloudflare-dns.com/dns-query?name={dom}&type=MX',
        )
        mx_answers = []
        dns_ok = False
        for ep in doh_endpoints:
            try:
                resp = await client.get(ep, headers={'Accept': 'application/dns-json'}, timeout=4.0)
                if resp.status_code == 200:
                    data = resp.json()
                    dns_ok = True
                    mx_answers = data.get('Answer') or []
                    if mx_answers:
                        break
            except Exception:
                continue

        if not dns_ok:
            res = 'dns_lookup_timeout_or_error (verify_manually)'
            _DNS_MX_CACHE[dom] = res
            return res

        if not mx_answers:
            res = 'invalid_no_mx_records_found'
            _DNS_MX_CACHE[dom] = res
            return res

        mx_hosts = ' '.join(str(a.get('data', '')).lower() for a in mx_answers)
        if 'google.com' in mx_hosts or 'googlemail.com' in mx_hosts:
            provider = 'Google Workspace'
        elif 'outlook.com' in mx_hosts or 'protection.outlook.com' in mx_hosts:
            provider = 'Microsoft 365'
        elif 'pphosted.com' in mx_hosts or 'mimecast.com' in mx_hosts:
            provider = 'Enterprise Gateway (Proofpoint/Mimecast)'
        elif 'zoho.' in mx_hosts:
            provider = 'Zoho Mail'
        else:
            provider = 'Custom MX'

        spf_present = False
        try:
            txt_resp = await client.get(
                f'https://dns.google/resolve?name={dom}&type=TXT',
                headers={'Accept': 'application/dns-json'},
                timeout=3.5
            )
            if txt_resp.status_code == 200:
                txt_ans = txt_resp.json().get('Answer') or []
                spf_present = any('v=spf1' in str(a.get('data', '')).lower() for a in txt_ans)
        except Exception:
            pass

        spf_tag = 'SPF_present' if spf_present else 'SPF_unverified'
        res = f'domain_accepts_email ({provider}; MX_found; {spf_tag})'
        _DNS_MX_CACHE[dom] = res
        return res


def extract_valid_phones(
    text: str,
    raw_tel_links: list[tuple[str, str]],
    default_region: str = 'US'
) -> list[tuple[str, int]]:
    dial_pref = REGION_DIALING_PREFIX_MAP.get(default_region.upper(), '+1')
    candidates: dict[str, int] = {}

    def _score_phone(raw_p: str, ctx: str, is_href: bool) -> None:
        cleaned = re.sub(r'[^\d+]', '', raw_p)
        if cleaned.startswith('00'):
            cleaned = '+' + cleaned[2:]
        digits_only = re.sub(r'\D', '', cleaned)
        if len(digits_only) < 9 or len(digits_only) > 15:
            return
        if re.search(r'(\d)\1{6,}', digits_only):
            return
        if digits_only.startswith(('199', '200', '201', '202')) and len(digits_only) == 8:
            return

        if not cleaned.startswith('+'):
            if default_region == 'UA' and digits_only.startswith('0') and len(digits_only) == 10:
                cleaned = '+38' + digits_only
            elif default_region == 'DE' and digits_only.startswith('0') and 10 <= len(digits_only) <= 12:
                cleaned = '+49' + digits_only[1:]
            elif len(digits_only) >= 10:
                cleaned = f'{dial_pref}{digits_only[-10:]}' if dial_pref == '+1' else f'+{digits_only}'
            else:
                return

        score = 50 if is_href else 25
        ctx_low = (ctx or '').lower()
        if any(k in ctx_low for k in B2B_PHONE_KEYWORDS):
            score += 30
        elif any(k in ctx_low for k in RETAIL_PHONE_KEYWORDS):
            score -= 10
        if cleaned not in candidates or score > candidates[cleaned]:
            candidates[cleaned] = score

    for tel_str, ctx in raw_tel_links:
        _score_phone(tel_str, ctx, True)

    for m in re.finditer(r'(?:\+\d{1,3}[\s\-()]*)?(?:\(\d{2,4}\)[\s\-]*|\d{2,4}[\s\-]+)\d{2,4}[\s\-]+\d{2,4}(?:[\s\-]+\d{2,4})?', text):
        val = m.group(0)
        start = max(0, m.start() - 50)
        end = min(len(text), m.end() + 50)
        _score_phone(val, text[start:end], False)

    ranked = sorted(candidates.items(), key=lambda x: (-x[1], x[0]))
    return ranked[:3]


def clean_and_validate_social_url(platform: str, url: str) -> str | None:
    if not url:
        return None
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ('http', 'https'):
            return None
        path_segments = [s for s in parsed.path.split('/') if s]
        if not path_segments:
            return None
        first_seg = path_segments[0].lower()
        if first_seg in SOCIAL_BAD_SEGMENTS:
            return None

        if platform == 'linkedin':
            if first_seg not in ('company', 'in', 'school', 'showcase'):
                return None
            if len(path_segments) < 2:
                return None
            slug = path_segments[1]
            return f'https://www.linkedin.com/{first_seg}/{slug}'

        if platform == 'telegram':
            if first_seg in TELEGRAM_PLACEHOLDER_SLUGS or first_seg == 'share':
                return None
            return f'https://t.me/{path_segments[0]}'

        if platform == 'tiktok':
            if not first_seg.startswith('@'):
                return None
            return f'https://www.tiktok.com/{path_segments[0]}'

        clean_path = '/'.join(path_segments[:2])
        host = parsed.netloc.lower()
        if not host.startswith('www.') and platform in ('instagram', 'facebook', 'youtube'):
            host = 'www.' + host
        return f'https://{host}/{clean_path}'
    except Exception:
        return None


def pick_best_social_candidate(
    candidates: list[tuple[str, str]],
    brand_root: str = ''
) -> tuple[str | None, str | None]:
    if not candidates:
        return None, None
    b_low = (brand_root or '').lower()
    best_url, best_src, best_score = None, None, -100
    for u, src in candidates:
        sc = 10
        u_low = u.lower()
        if '/company/' in u_low:
            sc += 30
        elif '/in/' in u_low:
            sc -= 5
        if b_low and len(b_low) >= 3 and b_low in u_low:
            sc += 25
        if sc > best_score:
            best_score = sc
            best_url, best_src = u, src
    return best_url, best_src


def classify_dm_source_type(source_url: str | None) -> str | None:
    if not source_url:
        return None
    u_low = source_url.lower()
    if 'linkedin.com/in/' in u_low:
        return 'serp_linkedin_xray'
    path = urlparse(source_url).path.lower()
    if any(k in path for k in ('impressum', 'mentions-legales', 'aviso-legal')):
        return 'impressum_page'
    if any(k in path for k in ('team', 'komanda', 'leadership', 'management', 'founders', 'board', 'vorstand')):
        return 'team_or_leadership_page'
    if any(k in path for k in ('about', 'ueber-uns', 'uber-uns', 'pro-nas', 'o-nas', 'company', 'qui-sommes-nous')):
        return 'about_page'
    if any(k in path for k in ('contact', 'kontakt', 'kontakty', 'contatti', 'contacto')):
        return 'contact_page'
    if DM_LEGAL_SOURCE_FLAG.search(path):
        return 'legal_or_terms_page'
    if any(k in path for k in ('blog', 'news', 'press', 'media', 'article', 'post', 'newsroom')):
        return 'blog_or_press_page'
    if not path or path == '/':
        return 'homepage'
    return 'product_or_service_page'


def _dm_role_priority_weight(role_str: str | None) -> int:
    r_low = (role_str or '').lower()
    if 'supervisory' in r_low or 'aufsichtsrat' in r_low:
        return -30
    if any(k in r_low for k in ('cmo', 'marketing', 'e-commerce', 'growth', 'digital')):
        return 24
    if any(k in r_low for k in ('ceo', 'chief executive', 'managing director', 'general manager', 'vorstand', 'president', 'geschäftsführer')):
        return 20
    if any(k in r_low for k in ('founder', 'co-founder')):
        return 18
    if 'owner' in r_low:
        return 16
    return 10


def build_decision_makers_json_from_summary(
    dms_found_str: str | None,
    primary_linkedin_url: str | None = None
) -> str | None:
    if not dms_found_str:
        return None
    items = []
    for idx, chunk in enumerate(dms_found_str.split(';')):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r'^(.+?)\s*\((.+?)\)\s*\[(.+?)\]$', chunk)
        if not m:
            continue
        name, role, src_url = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        li_match = None
        if primary_linkedin_url and (idx == 0 or verify_person_linkedin_match(name, primary_linkedin_url)):
            li_match = primary_linkedin_url
        elif 'linkedin.com/in/' in src_url.lower():
            li_match = src_url
        items.append({
            'name': name,
            'role': role,
            'source_url': src_url,
            'source_type': classify_dm_source_type(src_url),
            'linkedin_url': li_match,
        })
    return json.dumps(items, ensure_ascii=False) if items else None


def extract_decision_maker_deep(
    pages_with_urls: list[tuple[str, str, str]]
) -> tuple[str | None, str | None, str | None, str | None, bool, str | None, str | None, str | None]:
    if not pages_with_urls:
        return None, None, None, None, False, None, None, None

    first_url = pages_with_urls[0][0]
    parsed_host = urlparse(first_url).netloc.lower().replace('www.', '')
    brand_root = parsed_host.split('.')[0] if parsed_host else ''

    candidates: dict[str, dict] = {}
    personal_linkedin_urls: list[str] = []

    for page_url, raw_html, page_text in pages_with_urls:
        u_path = urlparse(page_url).path.lower()
        if DM_SOURCE_BLACKLIST.search(u_path):
            continue

        is_legal_doc = bool(DM_LEGAL_SOURCE_FLAG.search(u_path)) and not any(
            imp in u_path for imp in ('impressum', 'mentions-legales', 'aviso-legal')
        )
        src_type = classify_dm_source_type(page_url)
        page_bonus = 15 if src_type in ('impressum_page', 'team_or_leadership_page', 'about_page') else 0

        if raw_html:
            soup = BeautifulSoup(raw_html, 'lxml')
            for a_el in soup.find_all('a', href=True):
                href = a_el['href'].strip()
                if 'linkedin.com/in/' in href.lower():
                    clean_li = clean_and_validate_social_url('linkedin', href)
                    if clean_li and clean_li not in personal_linkedin_urls:
                        personal_linkedin_urls.append(clean_li)

            for ld_script in soup.find_all('script', type=re.compile(r'ld\+json', re.I)):
                try:
                    data = json.loads(ld_script.string or '')
                    objs = data if isinstance(data, list) else [data]
                    for obj in objs:
                        if not isinstance(obj, dict):
                            continue
                        graph = obj.get('@graph', [obj])
                        for node in (graph if isinstance(graph, list) else [obj]):
                            if not isinstance(node, dict):
                                continue
                            for key_role in ('founder', 'founders', 'employee', 'employees', 'member', 'members', 'author'):
                                val = node.get(key_role)
                                p_list = val if isinstance(val, list) else ([val] if isinstance(val, dict) else [])
                                for person in p_list:
                                    if not isinstance(person, dict):
                                        continue
                                    p_name = strip_role_tokens_from_name(str(person.get('name', '')))
                                    p_job = str(person.get('jobTitle') or key_role)
                                    if is_valid_person_name(p_name, brand_root):
                                        norm_r = normalize_executive_role(p_job) or 'Founder'
                                        sc = _dm_role_priority_weight(norm_r) + page_bonus + 10
                                        k_low = p_name.lower()
                                        if k_low not in candidates or sc > candidates[k_low]['score']:
                                            candidates[k_low] = {
                                                'name': p_name,
                                                'role': norm_r,
                                                'url': page_url,
                                                'is_legal': is_legal_doc,
                                                'src_type': src_type,
                                                'score': sc,
                                            }
                except Exception:
                    pass

        for m in VERTRETEN_DURCH_PATTERN.finditer(page_text):
            raw_n = m.group(1)
            full_match_low = m.group(0).lower()
            cand_name = strip_role_tokens_from_name(raw_n)
            if not is_valid_person_name(cand_name, brand_root):
                continue
            if 'aufsichtsrat' in full_match_low:
                role_label = 'Chairman of the Supervisory Board'
            elif 'vorstand' in full_match_low:
                role_label = 'Executive Board / CEO (Vorstand)'
            else:
                role_label = 'Managing Director / CEO (Geschäftsführer)'
            sc = _dm_role_priority_weight(role_label) + page_bonus + 12
            k_low = cand_name.lower()
            if k_low not in candidates or sc > candidates[k_low]['score']:
                candidates[k_low] = {
                    'name': cand_name,
                    'role': role_label,
                    'url': page_url,
                    'is_legal': is_legal_doc,
                    'src_type': src_type,
                    'score': sc,
                }

        for pattern, name_grp, role_grp in (
            (NAME_BEFORE_ROLE_PATTERN, 1, 2),
            (ROLE_BEFORE_NAME_PATTERN, 2, 1),
        ):
            for m in pattern.finditer(page_text):
                start_w = max(0, m.start() - 120)
                end_w = min(len(page_text), m.end() + 120)
                ctx_window = page_text[start_w:end_w].lower()
                if any(tm in ctx_window for tm in TESTIMONIAL_TEXT_MARKERS):
                    continue
                raw_n = m.group(name_grp)
                raw_r = m.group(role_grp)
                cand_name = strip_role_tokens_from_name(raw_n)
                if not is_valid_person_name(cand_name, brand_root):
                    continue
                norm_r = normalize_executive_role(raw_r) or raw_r
                sc = _dm_role_priority_weight(norm_r) + page_bonus
                k_low = cand_name.lower()
                if k_low not in candidates or sc > candidates[k_low]['score']:
                    candidates[k_low] = {
                        'name': cand_name,
                        'role': norm_r,
                        'url': page_url,
                        'is_legal': is_legal_doc,
                        'src_type': src_type,
                        'score': sc,
                    }

        for m in FOP_OWNER_PATTERN.finditer(page_text):
            cand_name = strip_role_tokens_from_name(m.group(1))
            if is_valid_person_name(cand_name, brand_root):
                norm_r = 'Owner'
                sc = _dm_role_priority_weight(norm_r) + page_bonus
                k_low = cand_name.lower()
                if k_low not in candidates or sc > candidates[k_low]['score']:
                    candidates[k_low] = {
                        'name': cand_name,
                        'role': norm_r,
                        'url': page_url,
                        'is_legal': is_legal_doc,
                        'src_type': src_type,
                        'score': sc,
                    }

    if not candidates:
        return None, None, None, None, False, None, None, None

    for c_info in candidates.values():
        c_info['li_url'] = None
        for li_u in personal_linkedin_urls:
            if verify_person_linkedin_match(c_info['name'], li_u):
                c_info['li_url'] = li_u
                c_info['score'] += 35
                break

    sorted_cands = sorted(
        candidates.values(),
        key=lambda item: (-1 if item['li_url'] else 0, -item['score'], item['name'])
    )

    best = sorted_cands[0]
    dms_found_str = '; '.join(
        f"{c['name']} ({c['role']}) [{c['url']}]" for c in sorted_cands[:5]
    )
    dms_json_str = build_decision_makers_json_from_summary(dms_found_str, best['li_url'])

    return (
        best['name'],
        best['role'],
        best['li_url'],
        best['url'],
        best['is_legal'],
        best['src_type'],
        dms_found_str,
        dms_json_str,
    )


async def fetch_dm_via_serp_fallback(
    client: AsyncSession,
    search_query: str | None,
    brand_root: str = '',
    serper_api_key: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Крок 1 (Автоматичний пошук ЛПР через Google SERP / Serper.dev):
    Коли сайт не публікує імена CMO/CEO (як більшість великих інтернет-магазинів),
    робить 1 легкий запит до Serper.dev із нашим decision_maker_search_query
    і розбирає заголовки LinkedIn ('Ім'я Прізвище - Посада - Компанія | LinkedIn')
    за допомогою наших детермінованих функцій strip_role_tokens_from_name та verify_person_linkedin_match.
    """
    api_key = (serper_api_key or os.environ.get('SERPER_API_KEY') or '').strip()
    if not api_key or not search_query:
        return None, None, None, None

    try:
        resp = await client.post(
            'https://google.serper.dev/search',
            headers={
                'X-API-KEY': api_key,
                'Content-Type': 'application/json',
            },
            json={'q': search_query, 'num': 5},
            timeout=6.0,
        )
        if resp.status_code != 200:
            return None, None, None, None
        data = resp.json()
        organic = data.get('organic') or []
        role_re = re.compile(rf'\b({ROLES_REGEX_PART})\b', re.I | re.U)

        for item in organic:
            link = str(item.get('link') or '').strip()
            title = str(item.get('title') or '').strip()
            snippet = str(item.get('snippet') or '').strip()
            if 'linkedin.com/in/' not in link.lower() or not title:
                continue

            clean_li = clean_and_validate_social_url('linkedin', link)
            if not clean_li:
                continue

            # Типовий заголовок LinkedIn: "Іван Петренко - Chief Marketing Officer - Comfy | LinkedIn"
            title_no_suffix = re.sub(r'\s*[\|\-–—]\s*LinkedIn.*$', '', title, flags=re.I)
            segments = [s.strip() for s in re.split(r'\s+[\-–—|•]\s+', title_no_suffix) if s.strip()]
            if not segments:
                continue

            cand_name = strip_role_tokens_from_name(segments[0])
            if not is_valid_person_name(cand_name, brand_root):
                continue
            if not verify_person_linkedin_match(cand_name, clean_li):
                continue

            combined_role_ctx = ' '.join(segments[1:]) + ' ' + snippet
            r_match = role_re.search(combined_role_ctx)
            raw_role = r_match.group(1) if r_match else (segments[1] if len(segments) > 1 else 'Marketing / Executive Lead')
            norm_role = normalize_executive_role(raw_role) or 'Marketing / Executive Lead'
            dms_str = f'{cand_name} ({norm_role}) [{clean_li}]'
            return cand_name, norm_role, clean_li, dms_str
    except Exception:
        pass

    return None, None, None, None
