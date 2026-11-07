import asyncio
import hashlib
import json
import os
import re
import secrets
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

try:
    import phonenumbers
    from phonenumbers import PhoneNumberType
    _PHONENUMBERS_AVAILABLE = True
except ImportError:
    _PHONENUMBERS_AVAILABLE = False

from .config import (
    ATS_CNAME_SIGNATURES,
    B2B_PARTNERSHIP_PREFIXES,
    B2B_PHONE_KEYWORDS,
    CITY_NAMES_BLACKLIST,
    CORPORATE_ENTITY_TOKENS,
    DEPARTMENT_OR_ADMISSIONS_PREFIXES,
    DEPARTMENT_PREFIX_BLACKLIST,
    DKIM_ESP_SELECTORS,
    DM_LEGAL_SOURCE_FLAG,
    DM_SOURCE_BLACKLIST,
    DNS_TXT_TECH_SIGNATURES,
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
    MX_SEG_FIREWALL_SIGNATURES,
    NAME_BEFORE_ROLE_PATTERN,
    NAME_REGEX_PART,
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
    TOXIC_COMPLIANCE_LOCAL_PARTS,
    UA_POPULAR_NAME_ALIASES,
    UA_TO_LATIN,
    UI_ACTION_WORDS_BLACKLIST,
    VERTRETEN_DURCH_PATTERN,
    WHOLESALE_MERCH_PREFIXES,
)

_DNS_MX_CACHE: dict[str, str] = {}
_DNS_DOMAIN_LOCKS: dict[str, asyncio.Lock] = {}

_STANDALONE_NAME_FINDER = re.compile(rf'\b{NAME_REGEX_PART}\b', re.UNICODE)

WIKIDATA_SEMAPHORE = asyncio.Semaphore(4)
WP_AVATAR_HASH_RE = re.compile(r"/avatar/([a-f0-9]{64}|[a-f0-9]{32})\b", re.IGNORECASE)

ACADEMIC_PREFIX_TITLES_RE = re.compile(
    r"^(?:(?:prof|dr|mag|dipl\s*-\s*(?:ing|kfm|vw|inf|jur)|ing|mba|ll\.?\s*m|ph\.?\s*d|"
    r"(?:rer\.?\s*(?:nat|pol|soc|oec)|med|iur|jur|h\.?\s*c|mult|univ)\.|"
    r"fh|пан|пані|mr|mrs|ms|mx)[\.\s,()/-]+)+",
    re.IGNORECASE
)
ACADEMIC_SUFFIX_TITLES_RE = re.compile(
    r"[\s,/()-]+(?:mba|ph\.?\s*d|ll\.?\s*m|m\.?\s*sc|b\.?\s*sc|m\.?\s*a|b\.?\s*a|"
    r"cfa|cpa|esq|jr\.?|sr\.?|ii|iii|iv|\(fh\))$",
    re.IGNORECASE
)

FAX_CONTEXT_RE = re.compile(
    r"(?:telefax|fax|факс|faks|télécopie)\s*[:.\-/]?\s*[\+\d\s()/.-]{6,22}",
    re.IGNORECASE
)

GENERIC_DNS_HOSTMASTERS = (
    "cloudflare.com", "awsdns", "googledomains.com", "google.com",
    "registrar-servers.com", "ovh.net", "hetzner.com", "godaddy.com",
    "domaincontrol.com", "namecheap.com", "azure-dns"
)

GENERIC_SINGLE_WORD_LOCALS = {
    'ask', 'dclub', 'return', 'returns', 'club', 'bonus', 'loyalty', 'card',
    'cards', 'gift', 'gifts', 'promo', 'action', 'actions', 'subscribe',
    'sub', 'news', 'app', 'apps', 'mobile', 'web', 'site', 'portal', 'b2c',
    'retail', 'opt', 'pay', 'payment', 'payments', 'delivery', 'shipping',
    'track', 'tracking', 'status', 'order', 'orders', 'claim', 'claims',
    'warranty', 'repair', 'service', 'services', 'feedback', 'review',
    'reviews', 'rating', 'career', 'work', 'talent', 'people', 'culture',
    'events', 'event', 'webinar', 'demo', 'trial', 'free', 'start', 'join',
    'hello', 'hi', 'hey', 'info', 'mail', 'email', 'contact', 'contacts',
    'office', 'team', 'support', 'help', 'care', 'sales', 'partner',
    'partners', 'b2b', 'press', 'media', 'pr', 'legal', 'privacy', 'gdpr',
    'dpo', 'compliance', 'security', 'abuse', 'post', 'inbox', 'general',
    'external', 'internal', 'ip', 'it', 'dev', 'tech', 'api', 'sdk', 'bot',
    'system', 'notifications', 'notify', 'alert', 'alerts', 'billing',
}

NON_EXECUTIVE_ROLE_REJECT_SET = {
    'author', 'authors', 'member', 'members', 'employee', 'employees',
    'contributor', 'writer', 'editor', 'copywriter', 'journalist',
    'blogger', 'reviewer', 'pharmacist', 'doctor', 'consultant',
    'specialist', 'intern', 'assistant', 'support', 'moderator',
    'автор', 'авторка', 'редактор', 'журналіст', 'фармацевт', 'провізор',
    'спеціаліст', 'консультант', 'співробітник',
}


# ==============================================================================
# v23.1 Complete: OSINT Керівників, WP 6.8+ Кракер та Порт-443 Каскад (Фаза 2)
# ==============================================================================

def split_clean_executive_name(raw_full_name: str) -> Dict[str, str]:
    if not raw_full_name:
        return {"dm_clean_full_name": "", "dm_first_name": "", "dm_last_name": ""}
    clean = raw_full_name.strip()
    for _ in range(3):
        clean = ACADEMIC_PREFIX_TITLES_RE.sub("", clean).strip()
        clean = ACADEMIC_SUFFIX_TITLES_RE.sub("", clean).strip()

    if "," in clean:
        parts_comma = [p.strip() for p in clean.split(",", 1) if p.strip()]
        if len(parts_comma) == 2 and " " not in parts_comma[0]:
            clean = f"{parts_comma[1]} {parts_comma[0]}"

    tokens = [t for t in clean.split() if t]
    if not tokens:
        return {"dm_clean_full_name": "", "dm_first_name": "", "dm_last_name": ""}
    if len(tokens) == 1:
        return {"dm_clean_full_name": tokens[0], "dm_first_name": tokens[0], "dm_last_name": ""}
    return {
        "dm_clean_full_name": " ".join(tokens),
        "dm_first_name": tokens[0],
        "dm_last_name": " ".join(tokens[1:]),
    }


def parse_schema_org_employees_v23(emp_node: Any) -> Optional[int]:
    if emp_node is None:
        return None
    if isinstance(emp_node, (int, float)) and emp_node > 0:
        return int(emp_node)
    if isinstance(emp_node, str):
        clean_num = re.sub(r"['’`,\u00a0\u202f\s]", "", emp_node)
        clean_num = re.sub(r"(?<=\d)\.(?=\d{3}(?:\b|\.))", "", clean_num)
        nums = [int(n) for n in re.findall(r"\d+", clean_num) if int(n) > 0]
        return nums[0] if nums else None
    if isinstance(emp_node, dict):
        val = emp_node.get("value")
        if val is not None:
            parsed = parse_schema_org_employees_v23(val)
            if parsed:
                return parsed
        min_v = parse_schema_org_employees_v23(emp_node.get("minValue"))
        max_v = parse_schema_org_employees_v23(emp_node.get("maxValue"))
        return min_v or max_v
    return None


def build_wikidata_holding_sparql_v23_1(domain: str, extra_san_domains: List[str] | None = None) -> str:
    """
    Використовує B-Tree індекс VALUES ?website, піднімається по wdt:P749 (без інвестфондів P127)
    і коректно прив'язує ?org до ?parentOrg через IF(!BOUND(?itemCeo) && BOUND(?parentCeo), ...).
    """
    domains_to_check = [domain] + (extra_san_domains[:2] if extra_san_domains else [])
    uri_literals = []
    for d in dict.fromkeys(domains_to_check):
        clean = d.lower().strip("/").removeprefix("www.")
        for proto in ("https://", "http://"):
            for prefix in ("", "www."):
                for suffix in ("", "/"):
                    uri_literals.append(f"<{proto}{prefix}{clean}{suffix}>")

    values_clause = " ".join(uri_literals)
    return f"""
    SELECT ?org ?orgLabel ?ceo ?ceoLabel ?execScope ?founder ?founderLabel ?lei ?euVat ?employees WHERE {{
      VALUES ?website {{ {values_clause} }}
      ?item wdt:P856 ?website .
      OPTIONAL {{
        ?item p:P169 ?itemCeoStmt .
        ?itemCeoStmt ps:P169 ?itemCeo .
        FILTER NOT EXISTS {{ ?itemCeoStmt pq:P582 ?endTime1 . }}
      }}
      OPTIONAL {{
        ?item wdt:P749 ?parentOrg .
        OPTIONAL {{
          ?parentOrg p:P169 ?parentCeoStmt .
          ?parentCeoStmt ps:P169 ?parentCeo .
          FILTER NOT EXISTS {{ ?parentCeoStmt pq:P582 ?endTime2 . }}
        }}
        OPTIONAL {{ ?parentOrg wdt:P1278 ?parentLei . }}
        OPTIONAL {{ ?parentOrg wdt:P3608 ?parentVat . }}
        OPTIONAL {{ ?parentOrg wdt:P1128 ?parentEmp . }}
        OPTIONAL {{ ?parentOrg wdt:P112 ?parentFounder . }}
      }}
      OPTIONAL {{ ?item wdt:P1278 ?itemLei . }}
      OPTIONAL {{ ?item wdt:P3608 ?itemVat . }}
      OPTIONAL {{ ?item wdt:P1128 ?itemEmp . }}
      OPTIONAL {{ ?item wdt:P112 ?itemFounder . }}
      BIND(COALESCE(?itemCeo, ?parentCeo) AS ?ceo)
      BIND(IF(BOUND(?itemCeo), "target_entity", IF(BOUND(?parentCeo), "parent_holding", "none")) AS ?execScope)
      BIND(COALESCE(?itemFounder, ?parentFounder) AS ?founder)
      BIND(COALESCE(?itemLei, ?parentLei) AS ?lei)
      BIND(COALESCE(?itemVat, ?parentVat) AS ?euVat)
      BIND(COALESCE(?itemEmp, ?parentEmp) AS ?employees)
      BIND(IF(!BOUND(?itemCeo) && BOUND(?parentCeo), ?parentOrg, ?item) AS ?org)
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en,de,uk,pl,fr,nl". }}
    }}
    LIMIT 5
    """


async def query_wikidata_holding_and_ceo(
    http_client: Any,
    domain: str,
    extra_san_domains: List[str] | None = None
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "wikidata_current_ceo": None,
        "decision_maker_scope": "none",
        "wikidata_founders": [],
        "wikidata_org_label": None,
        "wikidata_lei": None,
        "wikidata_eu_vat": None,
        "wikidata_employees": None,
    }
    sparql = build_wikidata_holding_sparql_v23_1(domain, extra_san_domains)
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "ApifyB2BLeadEnricherBot/23.1 (https://apify.com; support@apify.com)",
    }
    async with WIKIDATA_SEMAPHORE:
        try:
            resp = await http_client.get(
                "https://query.wikidata.org/sparql",
                params={"query": sparql, "format": "json"},
                headers=headers,
                timeout=2.2
            )
            if resp.status_code == 200:
                bindings = (resp.json().get("results") or {}).get("bindings") or []
                founders_set: Set[str] = set()
                for b in bindings:
                    if not out["wikidata_current_ceo"] and b.get("ceoLabel", {}).get("value"):
                        val = b["ceoLabel"]["value"]
                        if not re.match(r"^Q\d+$", val):
                            out["wikidata_current_ceo"] = val
                            out["decision_maker_scope"] = b.get("execScope", {}).get("value", "target_entity")
                    f_val = b.get("founderLabel", {}).get("value")
                    if f_val and not re.match(r"^Q\d+$", f_val):
                        founders_set.add(f_val)
                    if not out["wikidata_org_label"] and b.get("orgLabel", {}).get("value"):
                        out["wikidata_org_label"] = b["orgLabel"]["value"]
                    if not out["wikidata_lei"] and b.get("lei", {}).get("value"):
                        out["wikidata_lei"] = b["lei"]["value"]
                    if not out["wikidata_eu_vat"] and b.get("euVat", {}).get("value"):
                        out["wikidata_eu_vat"] = b["euVat"]["value"]
                    if not out["wikidata_employees"] and b.get("employees", {}).get("value"):
                        out["wikidata_employees"] = parse_schema_org_employees_v23(b["employees"]["value"])
                out["wikidata_founders"] = sorted(founders_set)[:4]
                if not out["wikidata_current_ceo"] and out["wikidata_founders"]:
                    out["wikidata_current_ceo"] = out["wikidata_founders"][0]
                    out["decision_maker_scope"] = "founder_fallback"
        except Exception:
            pass
    return out


def generate_phonetic_token_variants_v23(
    raw_token: str,
    translit_func: Optional[Callable[[str], str]] = None
) -> List[str]:
    """
    Виправлено (v23.1): active_translit викликається на кожній із 3 гілок (t, ascii_pre, din_pre),
    щоб комбіновані імена з умлаутами та слов'янською діакритикою/кирилицею ніколи не втрачали символи.
    """
    if not raw_token:
        return []
    t = raw_token.strip().lower()
    ascii_pre = (
        t.replace("ä", "a").replace("ö", "o").replace("ü", "u").replace("ß", "ss")
        .replace("ł", "l").replace("ń", "n").replace("ś", "s").replace("ź", "z")
        .replace("ż", "z").replace("ć", "c").replace("ą", "a").replace("ę", "e")
    )
    din_pre = (
        t.replace("ä", "ae").replace("ö", "oe").replace("ü", "ue").replace("ß", "ss").replace("ł", "l")
    )
    active_translit = translit_func or transliterate_ua_to_latin
    variants: Set[str] = set()
    for branch in (t, ascii_pre, din_pre):
        lat = active_translit(branch).lower()
        clean_v = re.sub(r"[^a-z0-9]", "", lat)
        if clean_v:
            variants.add(clean_v)
            if clean_v in UA_POPULAR_NAME_ALIASES:
                variants.update(UA_POPULAR_NAME_ALIASES[clean_v])
    return sorted(variants)


def crack_wp_user_email_dual_hash_v23_1(
    full_name: str,
    slug: str,
    domain: str,
    avatar_urls: Dict[str, str],
    translit_func: Optional[Callable[[str], str]] = None
) -> Optional[str]:
    """
    Двохешевий дешифратор (MD5 32 символи + SHA-256 64 символи для WordPress 6.8+).
    Використовується для математичного визначення корпоративного шаблону пошт домену.
    """
    if not domain or not avatar_urls:
        return None
    target_hash = None
    for url in avatar_urls.values():
        m = WP_AVATAR_HASH_RE.search(str(url))
        if m:
            target_hash = m.group(1).lower()
            break
    if not target_hash:
        return None

    hash_func = hashlib.sha256 if len(target_hash) == 64 else hashlib.md5
    clean_dom = domain.lower().strip().removeprefix("www.")
    candidates: List[str] = []
    if slug:
        s_clean = re.sub(r"[^a-z0-9._-]", "", slug.lower())
        if s_clean:
            candidates.append(f"{s_clean}@{clean_dom}")

    raw_parts = [p for p in (full_name or "").strip().split() if p]
    if len(raw_parts) >= 2:
        first_vars = generate_phonetic_token_variants_v23(raw_parts[0], translit_func)
        last_vars = generate_phonetic_token_variants_v23(raw_parts[-1], translit_func)
        for f in first_vars:
            candidates.append(f"{f}@{clean_dom}")
            for l in last_vars:
                candidates.extend([
                    f"{f}.{l}@{clean_dom}",
                    f"{f[0]}.{l}@{clean_dom}",
                    f"{f[0]}{l}@{clean_dom}",
                    f"{f}_{l}@{clean_dom}",
                    f"{f}-{l}@{clean_dom}",
                    f"{l}.{f}@{clean_dom}",
                    f"{l}@{clean_dom}",
                ])
    elif len(raw_parts) == 1:
        for f in generate_phonetic_token_variants_v23(raw_parts[0], translit_func):
            candidates.append(f"{f}@{clean_dom}")

    for cand in dict.fromkeys(candidates):
        if hash_func(cand.encode("utf-8")).hexdigest() == target_hash:
            return cand
    return None


async def verify_m365_candidates_safe(
    http_session: Any,
    domain: str,
    candidate_emails: List[str]
) -> Dict[str, Any]:
    endpoint = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
    out: Dict[str, Any] = {
        "verified_email": None,
        "verification_status": "not_checked",
        "tenant_type": None,
        "detected_federated_idp": None,
    }

    async def _probe(email_addr: str) -> Optional[Dict[str, Any]]:
        payload = {
            "Username": email_addr,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "originalRequest": "",
            "flowToken": ""
        }
        try:
            resp = await http_session.post(endpoint, json=payload, timeout=2.5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            return None
        return None

    canary_data = await _probe(f"canary_probe_{secrets.token_hex(5)}@{domain}")
    if not canary_data:
        out["verification_status"] = "m365_unreachable"
        return out

    ests_props = canary_data.get("EstsProperties") or {}
    domain_type = ests_props.get("DomainType")
    throttle_status = canary_data.get("ThrottleStatus", 0)
    canary_exists = canary_data.get("IfExistsResult", -1)
    out["tenant_type"] = domain_type

    if domain_type == 4:
        fed_url = (canary_data.get("Credentials") or {}).get("FederationRedirectUrl") or ""
        if "okta.com" in fed_url:
            out["detected_federated_idp"] = "Okta SSO"
        elif "pingidentity" in fed_url:
            out["detected_federated_idp"] = "PingIdentity"
        elif "duosecurity" in fed_url:
            out["detected_federated_idp"] = "Cisco Duo"
        else:
            out["detected_federated_idp"] = "Enterprise Federated ADFS/IdP"
        out["verification_status"] = "skipped_federated_idp"
        return out

    if domain_type != 3 or throttle_status != 0 or canary_exists != 1:
        out["verification_status"] = "skipped_catch_all_or_non_managed"
        return out

    for candidate in candidate_emails[:4]:
        res = await _probe(candidate)
        if not res:
            continue
        if res.get("ThrottleStatus", 0) != 0:
            out["verification_status"] = "aborted_m365_throttled"
            break
        if res.get("IfExistsResult") in (0, 5, 6):
            out["verified_email"] = candidate
            out["verification_status"] = "m365_matched"
            return out

    out["verification_status"] = "no_candidate_matched_m365"
    return out


async def verify_candidates_via_gravatar_two_step(
    http_session: Any,
    candidate_emails: List[str]
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "verified_email": None,
        "verification_status": "no_gravatar_match",
        "profile_display_name": None,
    }
    for email in candidate_emails[:4]:
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email:
            continue
        md5_hash = hashlib.md5(clean_email.encode("utf-8")).hexdigest()
        try:
            head_resp = await http_session.head(f"https://www.gravatar.com/avatar/{md5_hash}?d=404", timeout=1.8)
            if head_resp.status_code == 200:
                result["verified_email"] = clean_email
                result["verification_status"] = "identity_verified_gravatar_profile"
                try:
                    j_resp = await http_session.get(f"https://en.gravatar.com/{md5_hash}.json", timeout=1.8)
                    if j_resp.status_code == 200:
                        entries = j_resp.json().get("entry") or []
                        if entries and isinstance(entries[0], dict):
                            result["profile_display_name"] = entries[0].get("displayName")
                except Exception:
                    pass
                return result
        except Exception:
            continue
    return result


async def verify_ceo_email_cascade_port443_v23_1(
    http_client: Any,
    domain: str,
    candidate_emails: List[str],
    mx_records_str: str,
    has_seg_gateway: bool = False
) -> Dict[str, Any]:
    if not candidate_emails:
        return {
            "verified_email": None,
            "verification_status": "no_candidates",
            "email_verification_confidence": "NONE",
            "detected_federated_idp": None,
        }

    mx_low = (mx_records_str or "").lower()
    is_m365_mx = "outlook.com" in mx_low or "microsoft" in mx_low or has_seg_gateway
    is_google_mx = "google.com" in mx_low or "googlemail.com" in mx_low
    fed_idp = None

    if not is_google_mx:
        m365_res = await verify_m365_candidates_safe(http_client, domain, candidate_emails)
        fed_idp = m365_res.get("detected_federated_idp")
        if m365_res.get("verified_email"):
            if is_m365_mx:
                return {
                    "verified_email": m365_res["verified_email"],
                    "verification_status": "mailbox_verified_m365_active_directory",
                    "email_verification_confidence": "HIGH_IDENTITY_AND_MX",
                    "detected_federated_idp": fed_idp,
                }
            return {
                "verified_email": m365_res["verified_email"],
                "verification_status": "identity_verified_m365_external_mx",
                "email_verification_confidence": "MEDIUM_PUBLIC_IDENTITY",
                "detected_federated_idp": fed_idp,
            }

    grav_res = await verify_candidates_via_gravatar_two_step(http_client, candidate_emails)
    if grav_res.get("verified_email"):
        return {
            "verified_email": grav_res["verified_email"],
            "verification_status": "identity_verified_gravatar_profile",
            "email_verification_confidence": "MEDIUM_PUBLIC_IDENTITY",
            "detected_federated_idp": fed_idp,
        }

    for cand in candidate_emails[:2]:
        try:
            pgp_url = f"https://keys.openpgp.org/vks/v1/by-email/{quote(cand.strip().lower())}"
            resp = await http_client.get(pgp_url, timeout=1.8)
            if resp.status_code == 200:
                return {
                    "verified_email": cand.strip().lower(),
                    "verification_status": "identity_verified_openpgp_key",
                    "email_verification_confidence": "MEDIUM_PUBLIC_IDENTITY",
                    "detected_federated_idp": fed_idp,
                }
        except Exception:
            continue

    return {
        "verified_email": None,
        "verification_status": "mailbox_unverified",
        "email_verification_confidence": "PATTERN_ESTIMATED",
        "detected_federated_idp": fed_idp,
    }


def _clean_doh_strings(doh_tuple: Any) -> List[str]:
    if not isinstance(doh_tuple, (tuple, list)) or len(doh_tuple) < 2:
        return []
    ok, records = doh_tuple[0], doh_tuple[1]
    if not ok or not isinstance(records, list):
        return []
    cleaned: List[str] = []
    for rec in records:
        if isinstance(rec, dict):
            raw = str(rec.get("data") or "")
            norm = re.sub(r'"\s*"', "", raw).strip('"').strip().rstrip(".")
            if norm:
                cleaned.append(norm)
    return cleaned


def resolve_soa_rname_safe(
    rname_raw: str,
    etld_func: Callable[[str], tuple[str, str]]
) -> Optional[str]:
    if not rname_raw:
        return None
    clean = rname_raw.strip().rstrip(".").lower()
    if not clean or "." not in clean or any(g in clean for g in GENERIC_DNS_HOSTMASTERS):
        return None

    if r"\." in clean:
        parts = re.split(r"(?<!\\)\.", clean, maxsplit=1)
        if len(parts) == 2:
            local = parts[0].replace(r"\.", ".")
            host_reg, _ = etld_func(parts[1])
            return f"{local}@{host_reg or parts[1]}"

    reg_dom, _ = etld_func(clean)
    if not reg_dom or not clean.endswith(reg_dom) or clean == reg_dom:
        return None
    prefix = clean[: -(len(reg_dom) + 1)].strip(".")
    if not prefix:
        return None

    standard_roles = {
        "hostmaster", "postmaster", "dns", "dnsadmin", "dns-admin",
        "noc", "domains", "domainadmin", "admin", "root", "tech", "abuse"
    }
    first_label = prefix.split(".")[0]
    if first_label in standard_roles:
        return f"{first_label}@{reg_dom}"
    return f"{prefix}@{reg_dom}"


async def run_unified_dns_intelligence_v23(
    http_client: Any,
    domain: str,
    query_doh_func: Callable[[Any, str, str], Any],
    etld_func: Callable[[str], tuple[str, str]],
    probe_dkim: bool = True
) -> Dict[str, Any]:
    tasks: Dict[str, Any] = {
        "txt": query_doh_func(http_client, domain, "TXT"),
        "mx": query_doh_func(http_client, domain, "MX"),
        "dmarc": query_doh_func(http_client, f"_dmarc.{domain}", "TXT"),
        "bimi": query_doh_func(http_client, f"default._bimi.{domain}", "TXT"),
        "soa": query_doh_func(http_client, domain, "SOA"),
        "jobs_cname": query_doh_func(http_client, f"jobs.{domain}", "CNAME"),
        "careers_cname": query_doh_func(http_client, f"careers.{domain}", "CNAME"),
    }
    if probe_dkim:
        for sel in DKIM_ESP_SELECTORS:
            tasks[sel] = query_doh_func(http_client, f"{sel}.{domain}", "CNAME")

    keys = list(tasks.keys())
    raw_results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    res_map = dict(zip(keys, raw_results))

    shadow_tech: Set[str] = set()
    txt_joined = " ".join(_clean_doh_strings(res_map.get("txt"))).lower()
    mx_joined = " ".join(_clean_doh_strings(res_map.get("mx"))).lower()

    for sig, tech_name in DNS_TXT_TECH_SIGNATURES.items():
        if sig in txt_joined:
            shadow_tech.add(tech_name)
    for sel, (marker, esp_name) in DKIM_ESP_SELECTORS.items():
        for cname_val in _clean_doh_strings(res_map.get(sel)):
            if marker in cname_val.lower():
                shadow_tech.add(esp_name)

    seg_gateway = None
    combined_mail = f"{mx_joined} {txt_joined}"
    for seg_sig, seg_name in MX_SEG_FIREWALL_SIGNATURES.items():
        if seg_sig in combined_mail:
            seg_gateway = seg_name
            break

    dmarc_policy = "none_or_missing"
    dmarc_rua_domains: Set[str] = set()
    curr_reg, _ = etld_func(domain)
    for dm_str in _clean_doh_strings(res_map.get("dmarc")):
        dm_low = dm_str.lower()
        if "v=dmarc1" in dm_low:
            m_pol = re.search(r"\bp\s*=\s*(reject|quarantine|none)\b", dm_low)
            if m_pol:
                dmarc_policy = m_pol.group(1)
            for mail_match in re.findall(r"mailto:[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})", dm_low):
                rua_reg, _ = etld_func(mail_match)
                if rua_reg and rua_reg != curr_reg:
                    dmarc_rua_domains.add(rua_reg)

    detected_ats = None
    ats_cname_target = None
    for ck in ("jobs_cname", "careers_cname"):
        for c_val in _clean_doh_strings(res_map.get(ck)):
            c_low = c_val.lower()
            for ats_sig, ats_name in ATS_CNAME_SIGNATURES.items():
                if ats_sig in c_low:
                    detected_ats = ats_name
                    ats_cname_target = c_low
                    shadow_tech.add(ats_name)
                    break

    bimi_logo = None
    bimi_vmc = None
    for b_str in _clean_doh_strings(res_map.get("bimi")):
        if "v=bimi1" in b_str.lower():
            for part in b_str.split(";"):
                p = part.strip()
                if p.lower().startswith("l="):
                    bimi_logo = p[2:].strip()
                elif p.lower().startswith("a="):
                    bimi_vmc = p[2:].strip()

    soa_email = None
    last_dns_change = None
    for soa_str in _clean_doh_strings(res_map.get("soa")):
        parts = soa_str.split()
        if len(parts) >= 3:
            soa_email = resolve_soa_rname_safe(parts[1], etld_func)
            serial = parts[2].strip()
            if len(serial) == 10 and serial.isdigit() and serial.startswith(("202", "201")):
                y, m, d = serial[:4], serial[4:6], serial[6:8]
                if 1 <= int(m) <= 12 and 1 <= int(d) <= 31:
                    last_dns_change = f"{y}-{m}-{d}"
            break

    return {
        "dns_shadow_tech": sorted(shadow_tech),
        "mx_records_raw": mx_joined,
        "email_security_gateway": seg_gateway,
        "plain_text_outreach_required": bool(seg_gateway),
        "dmarc_policy": dmarc_policy,
        "dmarc_parent_or_vendor_domains": sorted(dmarc_rua_domains)[:5],
        "detected_ats_provider": detected_ats,
        "ats_cname_target": ats_cname_target,
        "bimi_logo_url": bimi_logo,
        "has_enterprise_vmc_seal": bool(bimi_vmc and bimi_vmc.lower().endswith(".pem")),
        "soa_admin_email": soa_email,
        "last_dns_change_date": last_dns_change,
    }


def filter_poisoned_and_compliance_emails(
    candidate_emails: List[str],
    poisoned_honeypot_set: Set[str]
) -> Tuple[List[str], Optional[str]]:
    safe_emails: List[str] = []
    dpo_email: Optional[str] = None
    for email in (candidate_emails or []):
        e_low = email.strip().lower()
        if "@" not in e_low or e_low in poisoned_honeypot_set:
            continue
        local_part = e_low.split("@", 1)[0]
        if local_part in TOXIC_COMPLIANCE_LOCAL_PARTS or any(
            local_part.startswith(f"{t}.") or local_part.startswith(f"{t}-") or local_part.startswith(f"{t}_")
            for t in ("datenschutz", "dpo", "privacy", "widerruf", "gdpr", "abuse")
        ):
            if not dpo_email:
                dpo_email = e_low
            continue
        safe_emails.append(email)
    return safe_emails, dpo_email


def normalize_whatsapp_number_safe(raw_digits: str, default_region: str = "UA") -> Optional[str]:
    if not raw_digits:
        return None
    clean_digits = re.sub(r"\D", "", raw_digits)
    if len(clean_digits) < 8 or len(clean_digits) > 15:
        return None
    if _PHONENUMBERS_AVAILABLE:
        if not clean_digits.startswith("0"):
            try:
                parsed = phonenumbers.parse(f"+{clean_digits}", None)
                if phonenumbers.is_valid_number(parsed):
                    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            except Exception:
                pass
        if default_region:
            try:
                parsed_loc = phonenumbers.parse(clean_digits, default_region.upper())
                if phonenumbers.is_valid_number(parsed_loc):
                    return phonenumbers.format_number(parsed_loc, phonenumbers.PhoneNumberFormat.E164)
            except Exception:
                pass
    return None


# ==============================================================================
# Core Contact Classification & Extraction Functions
# ==============================================================================

def clean_escaped_email_prefix(raw_email: str | None) -> str:
    if not raw_email:
        return ''
    em = raw_email.strip().strip('.,;:/|()[]<>\"\'')
    em = re.sub(r'^(?:\\?u00[0-9a-f]{2}|%[0-9a-f]{2}|3a|2f|20)+', '', em, flags=re.I)
    return em.strip().strip('.,;:/|()[]<>\"\'').lower()


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
    clean = re.sub(r'\s*\((?:source|джерело|from|http)[^)]*\)?.*$', '', str(raw_role), flags=re.I)
    clean = re.sub(r'https?://\S+', '', clean, flags=re.I)
    clean = ' '.join(clean.split()).strip(' ,—–-:|()•')
    low = clean.lower()
    if not low or low in NON_EXECUTIVE_ROLE_REJECT_SET:
        return None
    if low in ROLE_NORMALIZATION_MAP:
        return ROLE_NORMALIZATION_MAP[low]
    for k, v in ROLE_NORMALIZATION_MAP.items():
        if re.search(rf'\b{re.escape(k)}\b', low):
            return v
    if any(bad_tok in low.split() for bad_tok in NON_EXECUTIVE_ROLE_REJECT_SET):
        return None
    return clean[:60] if clean else None


def strip_role_tokens_from_name(raw_name: str) -> str:
    if not raw_name:
        return ''
    cleaned = ACADEMIC_PREFIX_TITLES_RE.sub('', raw_name.strip())
    cleaned = ACADEMIC_SUFFIX_TITLES_RE.sub('', cleaned.strip())
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
        if b_low and len(b_low) >= 4 and p_low not in ('otto',):
            if p_low == b_low:
                return False
            if len(b_low) >= 6 and len(p_low) >= 6 and (p_low.startswith(b_low[:6]) or b_low.startswith(p_low[:6])):
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
    local = clean_escaped_email_prefix(email).split('@', 1)[0].lower()
    if local in NON_PERSON_TOKENS or local in GENERIC_SINGLE_WORD_LOCALS:
        return False
    raw_tokens = [p for p in dm_name.split() if len(p) >= 2]
    if len(raw_tokens) < 2:
        return False
    first_variants = generate_phonetic_token_variants_v23(raw_tokens[0], transliterate_ua_to_latin)
    last_variants = generate_phonetic_token_variants_v23(raw_tokens[-1], transliterate_ua_to_latin)
    norm_local = re.sub(r'[^a-z]', '', local)
    for first_n in first_variants:
        for last_n in last_variants:
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
    raw_tokens = [p for p in dm_name.split() if len(p) >= 2]
    if len(raw_tokens) < 2:
        return False
    first_variants = generate_phonetic_token_variants_v23(raw_tokens[0], transliterate_ua_to_latin)
    last_variants = generate_phonetic_token_variants_v23(raw_tokens[-1], transliterate_ua_to_latin)
    return any(
        len(f) >= 3 and len(l) >= 3 and f in slug_clean and l in slug_clean
        for f in first_variants
        for l in last_variants
    )


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
    clean_em = clean_escaped_email_prefix(email)
    if '@' not in clean_em:
        return None
    local, dom = clean_em.split('@', 1)
    tokens = [t for t in re.split(r'[._+\-]+', local) if t]
    norm_local = re.sub(r'[._+\-]', '', local)
    b_low = (brand_root or '').lower().strip()

    if _matches_prefix_safely(local, tokens, LOW_PRIORITY_PREFIXES):
        return 'legal_or_hr_inbox'

    if dom in PUBLIC_WEBMAIL_DOMAINS:
        if any(s in tokens or s in norm_local for s in ('support', 'help', 'service', 'order', 'orders', 'shop')):
            return 'brand_webmail_support_inbox'
        if b_low and len(b_low) >= 3 and b_low in norm_local:
            return 'brand_webmail_general_inbox'
        return 'brand_webmail_general_inbox'

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

    if b_low and len(b_low) >= 3 and (local == b_low or norm_local == b_low):
        return 'general_office_inbox'

    if '-' not in local and ('_' in local or '.' in local):
        dot_tokens = [t for t in re.split(r'[._]+', local) if t]
        if len(dot_tokens) == 2:
            t1, t2 = dot_tokens[0], dot_tokens[1]
            if (
                t1.isalpha()
                and t2.isalpha()
                and t1 not in NON_PERSON_TOKENS
                and t2 not in NON_PERSON_TOKENS
                and t1 not in GENERIC_SINGLE_WORD_LOCALS
                and t2 not in GENERIC_SINGLE_WORD_LOCALS
                and (not b_low or (t1 != b_low and t2 != b_low))
            ):
                if (len(t1) >= 2 and len(t2) >= 2) or (len(t1) == 1 and len(t2) >= 3) or (len(t1) >= 3 and len(t2) == 1):
                    return 'personal_or_named_inbox'

    return 'department_or_general_inbox'


def generate_dm_email_pattern_candidates(
    dm_name: str | None,
    canonical_domain: str,
    observed_emails: list[str] | None = None,
) -> list[str]:
    if not dm_name or not canonical_domain:
        return []
    dom = canonical_domain.lower().strip().replace('www.', '')
    if not dom or dom in PUBLIC_WEBMAIL_DOMAINS:
        return []

    brand_root = dom.split('.')[0]
    cleaned_exec = split_clean_executive_name(dm_name).get("dm_clean_full_name") or dm_name
    if not is_valid_person_name(cleaned_exec, brand_root):
        return []

    raw_parts = [re.sub(r'[^a-z]', '', transliterate_ua_to_latin(p)) for p in cleaned_exec.split() if len(p) >= 2]
    parts = [p for p in raw_parts if len(p) >= 2]
    if len(parts) < 2:
        return []

    first, last = parts[0], parts[-1]
    f_init = first[0]

    detected_pattern = None
    for em in (observed_emails or []):
        clean_em = clean_escaped_email_prefix(em)
        if '@' not in clean_em:
            continue
        loc, em_dom = clean_em.split('@', 1)
        if em_dom != dom or '-' in loc:
            continue
        if '.' in loc:
            sub = loc.split('.')
            if len(sub) == 2 and sub[0].isalpha() and sub[1].isalpha():
                if len(sub[0]) == 1 and len(sub[1]) >= 3:
                    detected_pattern = 'f.last'
                    break
                if len(sub[0]) >= 2 and len(sub[1]) >= 2:
                    detected_pattern = 'first.last'
                    break

    if detected_pattern == 'f.last':
        return [f'{f_init}.{last}@{dom}', f'{first}.{last}@{dom}', f'{first}@{dom}']
    if detected_pattern == 'first.last':
        return [f'{first}.{last}@{dom}', f'{f_init}.{last}@{dom}', f'{first}@{dom}']

    return [f'{f_init}.{last}@{dom}', f'{first}.{last}@{dom}', f'{first}@{dom}']


async def verify_predicted_emails_via_api(
    client: AsyncSession,
    candidates: list[str],
    reoon_api_key: str | None = None,
    millionverifier_api_key: str | None = None,
) -> tuple[str | None, str | None]:
    r_key = (reoon_api_key or os.environ.get('REOON_API_KEY') or '').strip()
    mv_key = (millionverifier_api_key or os.environ.get('MILLIONVERIFIER_API_KEY') or '').strip()
    if (not r_key and not mv_key) or not candidates:
        return None, None

    for cand in candidates[:3]:
        if r_key:
            try:
                url = f'https://emailverifier.reoon.com/api/v1/verify?email={cand}&key={r_key}&mode=quick'
                resp = await client.get(url, timeout=6.0)
                if resp.status_code == 200:
                    data = resp.json()
                    st = str(data.get('status') or '').lower()
                    if st in ('safe', 'valid', 'deliverable'):
                        return cand, f'mailbox_verified_deliverable (Reoon: {st})'
            except Exception:
                pass
        if mv_key:
            try:
                url = f'https://api.millionverifier.com/api/v3/?api={mv_key}&email={cand}&timeout=5'
                resp = await client.get(url, timeout=6.0)
                if resp.status_code == 200:
                    data = resp.json()
                    res_code = str(data.get('result') or '').lower()
                    if res_code in ('ok', 'valid', 'deliverable'):
                        return cand, f'mailbox_verified_deliverable (MillionVerifier: {res_code})'
            except Exception:
                pass

    return None, None


def is_valid_Scraped_email(email: str, canonical_domain: str) -> tuple[bool, bool]:
    if not email or '@' not in email or len(email) > 90:
        return False, False
    em_low = clean_escaped_email_prefix(email)
    if not em_low or '@' not in em_low:
        return False, False
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
        em = clean_escaped_email_prefix(raw_em)
        is_val, is_ext = is_valid_Scraped_email(em, canonical_domain)
        if not is_val:
            if is_ext:
                had_external_pollution = True
            continue
        em_type = classify_email_type(em, brand_root) or 'department_or_general_inbox'
        score = type_weights.get(em_type, 10)
        em_dom = em.split('@', 1)[1].lower()
        if em_dom not in PUBLIC_WEBMAIL_DOMAINS and em_type != 'legal_or_hr_inbox':
            score += 20
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


async def query_doh_json(
    client: AsyncSession,
    domain: str,
    record_type: str = 'MX'
) -> tuple[bool, list[dict]]:
    doh_endpoints = (
        f'https://dns.google/resolve?name={domain}&type={record_type}',
        f'https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}',
        f'https://dns.quad9.net:5053/dns-query?name={domain}&type={record_type}',
    )
    for use_direct in (False, True):
        for ep in doh_endpoints:
            try:
                kwargs: dict = {'headers': {'Accept': 'application/dns-json'}, 'timeout': 4.0}
                if use_direct:
                    kwargs['proxy'] = None
                resp = await client.get(ep, **kwargs)
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get('Answer') or []
                    return True, answers
            except Exception:
                continue
    return False, []


async def verify_email_deliverability_deep(
    client: AsyncSession,
    email: str | None,
    source_url: str | None = None
) -> str | None:
    if not email or '@' not in email:
        return None
    dom = email.split('@', 1)[1].lower().strip()
    if dom in PUBLIC_WEBMAIL_DOMAINS:
        return f'public_webmail_provider ({dom}; MX_assumed_valid; mailbox_unverified)'

    if dom in _DNS_MX_CACHE:
        return _DNS_MX_CACHE[dom]

    lock = _DNS_DOMAIN_LOCKS.setdefault(dom, asyncio.Lock())
    async with lock:
        if dom in _DNS_MX_CACHE:
            return _DNS_MX_CACHE[dom]

        dns_ok, mx_answers = await query_doh_json(client, dom, 'MX')
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

        _, txt_ans = await query_doh_json(client, dom, 'TXT')
        spf_present = any('v=spf1' in str(a.get('data', '')).lower() for a in txt_ans)

        spf_tag = 'SPF_present' if spf_present else 'SPF_unverified'
        res = f'domain_mail_configured ({provider}; MX_found; {spf_tag}; mailbox_unverified)'
        _DNS_MX_CACHE[dom] = res
        return res


def _is_acceptable_e164_length(e164_str: str, target_region: str) -> bool:
    digits = re.sub(r'\D', '', e164_str or '')
    if len(digits) >= 10 and len(digits) <= 15:
        return True
    if len(digits) == 9 and target_region == 'DE' and e164_str.startswith('+4940'):
        return True
    return False


def extract_valid_phones(
    text: str,
    raw_tel_links: list[tuple[str, str]],
    default_region: str = 'US'
) -> list[tuple[str, int]]:
    target_region = (default_region or 'US').upper().strip()
    expected_prefix = REGION_DIALING_PREFIX_MAP.get(target_region, '+1')
    candidates: dict[str, int] = {}
    clean_text = FAX_CONTEXT_RE.sub(' ', text or '')

    def _add_validated_candidate(raw_str: str, ctx: str, base_score: int) -> None:
        if not raw_str:
            return
        ctx_low = (ctx or '').lower()
        if any(fx in ctx_low for fx in ('telefax', 'fax:', 'факс')):
            return
        cleaned_raw = raw_str.strip()
        if _PHONENUMBERS_AVAILABLE:
            try:
                parsed_num = phonenumbers.parse(cleaned_raw, target_region)
                if not phonenumbers.is_valid_number(parsed_num):
                    return
                e164_str = phonenumbers.format_number(
                    parsed_num, phonenumbers.PhoneNumberFormat.E164
                )
                if not _is_acceptable_e164_length(e164_str, target_region):
                    return
                formatted_intl = phonenumbers.format_number(
                    parsed_num, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                )
                num_region = (phonenumbers.region_code_for_number(parsed_num) or '').upper()
            except Exception:
                return
        else:
            digits = re.sub(r'\D', '', cleaned_raw)
            if len(digits) < 10 or len(digits) > 15:
                return
            e164_str = cleaned_raw if cleaned_raw.startswith('+') else f'{expected_prefix}{digits[-10:]}'
            if not _is_acceptable_e164_length(e164_str, target_region):
                return
            formatted_intl = e164_str
            num_region = target_region if e164_str.startswith(expected_prefix) else ''

        score = base_score
        if num_region == target_region or e164_str.startswith(expected_prefix):
            score += 35

        if any(k in ctx_low for k in B2B_PHONE_KEYWORDS):
            score += 30
        elif any(k in ctx_low for k in RETAIL_PHONE_KEYWORDS):
            score -= 10

        if formatted_intl not in candidates or score > candidates[formatted_intl]:
            candidates[formatted_intl] = score

    for tel_str, ctx in raw_tel_links:
        _add_validated_candidate(tel_str, ctx, 50)

    if _PHONENUMBERS_AVAILABLE:
        try:
            for m in phonenumbers.PhoneNumberMatcher(clean_text[:120000], target_region):
                num_obj = m.number
                if not phonenumbers.is_valid_number(num_obj):
                    continue
                e164_s = phonenumbers.format_number(
                    num_obj, phonenumbers.PhoneNumberFormat.E164
                )
                if not _is_acceptable_e164_length(e164_s, target_region):
                    continue
                intl_str = phonenumbers.format_number(
                    num_obj, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                )
                n_reg = (phonenumbers.region_code_for_number(num_obj) or '').upper()
                sc = 25
                if n_reg == target_region or e164_s.startswith(expected_prefix):
                    sc += 35
                w_start = max(0, m.start - 50)
                w_end = min(len(clean_text), m.end + 50)
                ctx_w = clean_text[w_start:w_end].lower()
                if any(k in ctx_w for k in B2B_PHONE_KEYWORDS):
                    sc += 30
                elif any(k in ctx_w for k in RETAIL_PHONE_KEYWORDS):
                    sc -= 10
                if intl_str not in candidates or sc > candidates[intl_str]:
                    candidates[intl_str] = sc
        except Exception:
            pass
    else:
        for m in re.finditer(r'(?:\+\d{1,3}[\s\-()]*)?(?:\(\d{2,4}\)[\s\-]*|\d{2,4}[\s\-]+)\d{2,4}[\s\-]+\d{2,4}(?:[\s\-]+\d{2,4})?', clean_text[:120000]):
            w_start = max(0, m.start() - 50)
            w_end = min(len(clean_text), m.end() + 50)
            _add_validated_candidate(m.group(0), clean_text[w_start:w_end], 25)

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
    if 'wikidata.org' in u_low:
        return 'wikidata_sparql'
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
    if any(k in r_low for k in ('cmo', 'marketing', 'e-commerce', 'growth', 'digital', 'performance')):
        return 24
    if any(k in r_low for k in ('ceo', 'chief executive', 'managing director', 'general manager', 'vorstand', 'president', 'geschäftsführer')):
        return 20
    if any(k in r_low for k in ('founder', 'co-founder')):
        return 18
    if 'owner' in r_low:
        return 16
    return 10


def is_marketing_or_digital_role(role_str: str | None) -> bool:
    r_low = (role_str or '').lower()
    return any(k in r_low for k in ('cmo', 'marketing', 'e-commerce', 'ecommerce', 'growth', 'digital', 'performance', 'acquisition', 'cro', 'маркетинг'))


def build_decision_makers_json_from_summary(
    dms_found_str: str | None,
    primary_linkedin_url: str | None = None,
    fallback_source_url: str | None = None,
) -> str | None:
    if not dms_found_str:
        return None
    items = []
    for idx, chunk in enumerate(dms_found_str.split(';')):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r'^(.+?)\s*\((.+?)\)\s*\[(.*?)\]$', chunk)
        if not m:
            continue
        name, role, src_url = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        if not src_url and fallback_source_url:
            src_url = fallback_source_url
        norm_role = normalize_executive_role(role)
        if not norm_role:
            continue
        li_match = None
        if primary_linkedin_url and (idx == 0 or verify_person_linkedin_match(name, primary_linkedin_url)):
            li_match = primary_linkedin_url
        elif 'linkedin.com/in/' in src_url.lower():
            li_match = src_url
        items.append({
            'name': name,
            'role': norm_role,
            'source_url': src_url or None,
            'source_type': classify_dm_source_type(src_url) if src_url else None,
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
                            for key_role in ('founder', 'founders'):
                                val = node.get(key_role)
                                p_list = val if isinstance(val, list) else ([val] if isinstance(val, dict) else [])
                                for person in p_list:
                                    if not isinstance(person, dict):
                                        continue
                                    p_name = strip_role_tokens_from_name(str(person.get('name', '')))
                                    p_job = str(person.get('jobTitle') or ('Co-Founder' if key_role == 'founders' else 'Founder'))
                                    norm_r = normalize_executive_role(p_job)
                                    if is_valid_person_name(p_name, brand_root) and norm_r:
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
            full_match_low = m.group(0).lower()
            if 'aufsichtsrat' in full_match_low:
                role_label = 'Chairman of the Supervisory Board'
            elif 'vorstand' in full_match_low:
                role_label = 'Executive Board / CEO (Vorstand)'
            else:
                role_label = 'Managing Director / CEO (Geschäftsführer)'

            base_sc = _dm_role_priority_weight(role_label) + page_bonus + 12

            raw_first = m.group(1)
            first_cand = strip_role_tokens_from_name(raw_first)
            extracted_co_execs = []
            if is_valid_person_name(first_cand, brand_root):
                extracted_co_execs.append(first_cand)

            tail_window = page_text[m.end():min(len(page_text), m.end() + 140)]
            tail_clause = re.split(r'[.;\n|•]|\b(?:Register|Handelsregister|Amtsgericht|USt|Sitz|Kontakt|Telefon|E-Mail)\b', tail_window)[0]
            if tail_clause.lstrip().startswith((',', 'und ', '&')):
                for nm_m in _STANDALONE_NAME_FINDER.finditer(tail_clause):
                    co_cand = strip_role_tokens_from_name(nm_m.group(1))
                    if is_valid_person_name(co_cand, brand_root) and co_cand not in extracted_co_execs:
                        extracted_co_execs.append(co_cand)

            for idx_exec, exec_name in enumerate(extracted_co_execs[:4]):
                sc = base_sc - idx_exec
                k_low = exec_name.lower()
                if k_low not in candidates or sc > candidates[k_low]['score']:
                    candidates[k_low] = {
                        'name': exec_name,
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
                norm_r = normalize_executive_role(raw_r)
                if not norm_r:
                    continue
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
    dms_json_str = build_decision_makers_json_from_summary(dms_found_str, best['li_url'], best['url'])

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
