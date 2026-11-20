from datetime import datetime, timezone
import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

try:
    import phonenumbers
    from phonenumbers import timezone as pn_timezone
    _PHONENUMBERS_TZ_AVAILABLE = True
except ImportError:
    _PHONENUMBERS_TZ_AVAILABLE = False

from .config import (
    KNOWN_MARKETPLACE_DOMAINS,
    MARKETPLACE_TEXT_MARKERS,
    PARKING_AND_BROKER_DENYLIST,
    ROLE_NORMALIZATION_MAP,
    compute_snapshot_age_days,
    truncate_error_msg,
)
from .contacts import (
    build_decision_makers_json_from_summary,
    classify_dm_buyer_fit,
    classify_dm_source_type,
    classify_email_type,
    is_marketing_or_digital_role,
    is_server_verified_email_confidence,
    split_clean_executive_name,
    verify_person_email_match,
    verify_person_linkedin_match,
)
from .tech_detector import build_evidence_json_from_cached_record

KNOWN_DTC_ECOM_DOMAINS = {
    'glossier.com',
    'chubbiesshorts.com',
    'cher17.com',
    'asos.com',
    'laredoute.fr',
    'docmorris.de',
    'coolblue.nl',
    'notino.de',
    'flaconi.de',
    'douglas.de',
    'thomann.de',
    'bergfreunde.de',
    'moyo.ua',
    'yakaboo.ua',
    'apteka911.ua',
    'stls.store',
    'stylus.ua',
}

EU_VIES_COUNTRIES = {
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES",
    "FI", "FR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
    "NL", "PL", "PT", "RO", "SE", "SI", "SK", "XI"
}

RDAP_SUPPORTED_TLDS = {
    "com", "net", "org", "io", "co", "ai", "app", "dev", "tech", "shop", "store",
    "uk", "co.uk", "org.uk", "nl", "pl", "cz", "fr", "eu", "no", "se", "fi",
    "br", "com.br", "au", "com.au", "ca", "in", "me", "biz", "info", "pro", "group"
}

ENTERPRISE_REGISTRAR_MARKERS = (
    "markmonitor", "csc corporate", "corporation service company",
    "safenames", "com laude", "nom-iq", "brandsight"
)

LIQUIDATION_MARKERS_RE = re.compile(
    r"\b(?:gmbh\s+i\.\s*l\.|gmbh\s+i\.\s*abw\.|in\s+liquidation|insolvenzverfahren|"
    r"w\s+likwidacji|w\s+upadłości|в\s+стані\s+припинення|в\s+процесі\s+ліквідації|"
    r"in\s+administration|in\s+receivership)(?!\w)",
    re.IGNORECASE
)
FOR_SALE_TITLE_RE = re.compile(
    r"\b(for\s+sale|buy\s+this\s+domain|domain\s+is\s+available|parked\s+domain|"
    r"domain\s+parking|inquire\s+about\s+this\s+domain|домен\s+продається)\b",
    re.IGNORECASE
)

EXACT_TLD_TO_TZ_AND_LANG: Dict[str, Tuple[str, str]] = {
    "ua": ("Europe/Kyiv", "uk"), "de": ("Europe/Berlin", "de"),
    "at": ("Europe/Vienna", "de"), "ch": ("Europe/Zurich", "de"),
    "pl": ("Europe/Warsaw", "pl"), "cz": ("Europe/Prague", "cs"),
    "nl": ("Europe/Amsterdam", "nl"), "be": ("Europe/Brussels", "nl"),
    "fr": ("Europe/Paris", "fr"), "es": ("Europe/Madrid", "es"),
    "it": ("Europe/Rome", "it"), "uk": ("Europe/London", "en"),
    "co.uk": ("Europe/London", "en"), "ie": ("Europe/Dublin", "en"),
    "se": ("Europe/Stockholm", "en"), "no": ("Europe/Oslo", "en"),
    "dk": ("Europe/Copenhagen", "en"), "fi": ("Europe/Helsinki", "en"),
    "pt": ("Europe/Lisbon", "pt"), "au": ("Australia/Sydney", "en"),
    "com.au": ("Australia/Sydney", "en"),
}

NAME_TOKEN_RE = re.compile(r"[a-zа-яіїєґäöüß]{3,}", re.IGNORECASE)
CYRILLIC_TEXT_RE = re.compile(r"[а-яіїєґА-ЯІЇЄҐ]{3,}")

# v24.4: Суворо підтверджені MarTech-платформи (без CDN, сертифікатів, локалей та CSP-allowlist)
ENTERPRISE_STACK_TOOLS: Set[str] = {
    "Adobe Analytics", "Salesforce", "Salesforce Marketing Cloud", "Segment", "Tealium",
    "Shopify Plus", "Dynamic Yield", "Optimizely", "Braze", "Snowplow",
    "Algolia", "Datadog", "Akeneo PIM", "Pimcore", "Salsify PIM",
    "Oracle NetSuite", "Global-e", "Server-Side GTM (sGTM)",
}

MID_MARKET_STACK_TOOLS: Set[str] = {
    "HubSpot", "Klaviyo", "Amplitude", "Mixpanel", "Zendesk", "Gorgias", "VWO",
    "Personio", "Greenhouse", "Lever", "SmartRecruiters", "Loop Returns", "Sendcloud",
    "Contentful", "Storyblok", "Shopware", "Magento", "Intercom", "Criteo",
}


# ==============================================================================
# v24.4 Enterprise MarTech & Account Intelligence: VIES, RDAP, Scale vs Stack
# ==============================================================================

async def verify_eu_entity_vies_and_gleif(
    http_session: Any,
    raw_vat: Optional[str] = None,
    candidate_legal_name: Optional[str] = None,
    country_hint: Optional[str] = None
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "vat_valid": False,
        "official_legal_name": None,
        "official_address": None,
        "lei_code": None,
        "national_register_id": None,
        "verification_source": None,
    }
    if raw_vat and len(raw_vat) >= 8:
        clean_vat = re.sub(r"[^A-Z0-9]", "", raw_vat.upper())
        prefix, number = clean_vat[:2], clean_vat[2:]
        if prefix == "GR":
            prefix = "EL"
        if prefix in EU_VIES_COUNTRIES and number:
            try:
                resp = await http_session.get(
                    f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{prefix}/vat/{number}",
                    timeout=2.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("isValid") is True:
                        out["vat_valid"] = True
                        out["verification_source"] = "eu_vies_registry"
                        name = (data.get("name") or "").strip()
                        addr = (data.get("address") or "").strip().replace("\n", ", ")
                        if name and name != "---":
                            out["official_legal_name"] = name
                        if addr and addr != "---":
                            out["official_address"] = addr
                        if not country_hint:
                            country_hint = "GR" if prefix == "EL" else prefix
            except Exception:
                pass

    if (not out["official_legal_name"] or not out["lei_code"]) and candidate_legal_name:
        clean_query = candidate_legal_name.strip()
        if len(clean_query) >= 3:
            gleif_url = f"https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]={quote(clean_query)}&page[size]=3"
            try:
                g_resp = await http_session.get(
                    gleif_url,
                    headers={"Accept": "application/vnd.api+json"},
                    timeout=2.0,
                )
                if g_resp.status_code == 200:
                    for rec in (g_resp.json().get("data") or []):
                        attrs = rec.get("attributes") or {}
                        entity = attrs.get("entity") or {}
                        hq = entity.get("headquartersAddress") or entity.get("legalAddress") or {}
                        rec_country = hq.get("country")
                        if country_hint and rec_country and rec_country.upper() != country_hint.upper():
                            continue
                        out["lei_code"] = attrs.get("lei")
                        out["official_legal_name"] = out["official_legal_name"] or (entity.get("legalName") or {}).get("name")
                        out["national_register_id"] = entity.get("registeredAs")
                        if not out["official_address"] and hq:
                            parts = (hq.get("addressLines") or []) + [hq.get("postalCode") or "", hq.get("city") or "", rec_country or ""]
                            out["official_address"] = ", ".join(p for p in parts if p)
                        out["verification_source"] = "eu_vies_and_gleif" if out["vat_valid"] else "gleif_financial_registry"
                        break
            except Exception:
                pass
    return out


def _extract_registrar_name_from_entities(entities: List[Dict[str, Any]]) -> Optional[str]:
    for ent in (entities or []):
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if isinstance(prop, list) and len(prop) >= 4 and prop[0] in ("fn", "org"):
                        val = str(prop[3]).strip()
                        if val:
                            return val
        nested = ent.get("entities")
        if isinstance(nested, list):
            found = _extract_registrar_name_from_entities(nested)
            if found:
                return found
    return None


async def fetch_rdap_domain_maturity_v23(http_session: Any, domain: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "domain_age_years": None,
        "registrar_name": None,
        "has_enterprise_brand_registrar": False,
    }
    clean_dom = domain.lower().strip().rstrip(".")
    parts = clean_dom.split(".")
    if len(parts) < 2:
        return out
    if parts[-1] not in RDAP_SUPPORTED_TLDS and f"{parts[-2]}.{parts[-1]}" not in RDAP_SUPPORTED_TLDS:
        return out

    try:
        resp = await http_session.get(
            f"https://rdap.org/domain/{clean_dom}",
            headers={"Accept": "application/rdap+json"},
            timeout=2.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            for ev in (data.get("events") or []):
                if isinstance(ev, dict) and ev.get("eventAction") == "registration":
                    dt_str = str(ev.get("eventDate") or "")
                    if len(dt_str) >= 4 and dt_str[:4].isdigit():
                        out["domain_age_years"] = max(0, datetime.now(timezone.utc).year - int(dt_str[:4]))
                    break
            reg_name = _extract_registrar_name_from_entities(data.get("entities") or [])
            if reg_name:
                out["registrar_name"] = reg_name
                if any(m in reg_name.lower() for m in ENTERPRISE_REGISTRAR_MARKERS):
                    out["has_enterprise_brand_registrar"] = True
    except Exception:
        pass
    return out


def detect_ma_rebrand_and_insolvency_v23(
    input_domain: str,
    final_url: str,
    page_title: str,
    tls_corporate_sans: Set[str],
    known_redirect_aliases: Dict[str, str],
    legal_text_or_impressum: str,
    shared_pixel_match: bool,
    etld_extractor_func: Callable[[str], tuple[str, str]]
) -> Dict[str, Any]:
    if legal_text_or_impressum and LIQUIDATION_MARKERS_RE.search(legal_text_or_impressum):
        return {"corporate_lifecycle_status": "IN_LIQUIDATION_OR_INSOLVENCY", "redirected_parent_domain": None}

    in_reg, in_brand = etld_extractor_func(input_domain)
    fin_reg, fin_brand = etld_extractor_func(final_url)
    if not in_reg or not fin_reg or in_reg == fin_reg or in_brand == fin_brand:
        return {"corporate_lifecycle_status": "ACTIVE_INDEPENDENT", "redirected_parent_domain": None}

    title_low = (page_title or "").lower()
    if any(fin_reg.endswith(b) for b in PARKING_AND_BROKER_DENYLIST) or FOR_SALE_TITLE_RE.search(title_low):
        return {"corporate_lifecycle_status": "DOMAIN_PARKED_OR_FOR_SALE", "redirected_parent_domain": fin_reg}

    if (
        known_redirect_aliases.get(in_reg) == fin_reg
        or fin_reg in tls_corporate_sans
        or shared_pixel_match
        or (len(in_brand) >= 4 and in_brand in title_low)
    ):
        return {"corporate_lifecycle_status": "ACTIVE_REBRAND_ALIAS", "redirected_parent_domain": fin_reg}

    return {"corporate_lifecycle_status": "REDIRECTED_OR_ACQUIRED", "redirected_parent_domain": fin_reg}


def classify_account_scale_tier(
    estimated_markets_count: int = 1,
    detected_market_locales_count: int = 0,
    catalog_estimated_skus: Optional[int] = None,
    open_positions_total: Optional[int] = None,
    ads_active_last_30d: Optional[bool] = None,
    is_marketplace: bool = False,
) -> Dict[str, Any]:
    basis: List[str] = []
    if is_marketplace:
        basis.append("Multi-brand marketplace / large platform")
    if estimated_markets_count >= 5:
        basis.append(f"{estimated_markets_count} regional markets")
    elif estimated_markets_count >= 2:
        basis.append(f"{estimated_markets_count} markets")
    if detected_market_locales_count >= 5:
        basis.append(f"{detected_market_locales_count} localized hreflang variants")
    if catalog_estimated_skus is not None:
        if catalog_estimated_skus >= 5000:
            basis.append(f"Large catalog (~{catalog_estimated_skus:,} SKUs)")
        elif catalog_estimated_skus >= 500:
            basis.append(f"Mid-size catalog (~{catalog_estimated_skus:,} SKUs)")
    if open_positions_total is not None and int(open_positions_total) >= 15:
        basis.append(f"High-volume hiring ({open_positions_total} open roles)")
    elif open_positions_total is not None and int(open_positions_total) >= 3:
        basis.append(f"Active hiring ({open_positions_total} open roles)")
    if ads_active_last_30d is True:
        basis.append("Active Google Ads (30d)")

    if (
        is_marketplace
        or estimated_markets_count >= 5
        or detected_market_locales_count >= 8
        or (catalog_estimated_skus is not None and catalog_estimated_skus >= 5000)
        or (open_positions_total is not None and int(open_positions_total) >= 25)
    ):
        tier = "Enterprise Scale"
    elif (
        estimated_markets_count >= 2
        or detected_market_locales_count >= 2
        or (catalog_estimated_skus is not None and catalog_estimated_skus >= 500)
        or (open_positions_total is not None and int(open_positions_total) >= 3)
        or ads_active_last_30d is True
    ):
        tier = "Mid-Market Scale"
    else:
        tier = "SMB / Local Scale"
        if not basis:
            basis.append("Single-market web footprint")

    return {
        "account_scale_tier": tier,
        "account_scale_basis": basis[:6],
    }


def classify_martech_stack_tier(
    detected_tech_set: Set[str],
    tech_verification_tiers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    v24.4: Оцінює зрілість MarTech-стеку ВИКЛЮЧНО за підтвердженими MarTech-платформами
    (`runtime_verified` або `configured_in_code`) — повністю ігнорує CDN, TLS/VMC сертифікати,
    локалі hreflang та `allowlisted_in_csp`.
    """
    tiers_map = tech_verification_tiers or {}
    confirmed = sorted(
        t for t in (detected_tech_set or set())
        if tiers_map.get(t) != "allowlisted_in_csp"
    )
    confirmed_set = set(confirmed)

    ent_hits = sorted(confirmed_set & ENTERPRISE_STACK_TOOLS)
    mid_hits = sorted(confirmed_set & MID_MARKET_STACK_TOOLS)
    basis: List[str] = []

    if ent_hits:
        basis.append(f"Enterprise MarTech: {', '.join(ent_hits[:5])}")
    if mid_hits:
        basis.append(f"Mid-Market MarTech: {', '.join(mid_hits[:5])}")

    if len(ent_hits) >= 1:
        tier = "Enterprise"
    elif (
        len(mid_hits) >= 1
        or ("Google Analytics (GA4)" in confirmed_set and "Google Tag Manager" in confirmed_set)
    ):
        tier = "Mid-Market"
        if not basis:
            basis.append("Core Analytics Stack: GA4 + GTM")
    elif len(confirmed_set) >= 1:
        tier = "SMB"
        if not basis:
            basis.append(f"Basic Web Stack: {', '.join(confirmed[:5])}")
    else:
        tier = "Unverified / Minimal"

    return {
        "martech_stack_tier": tier,
        "martech_stack_tier_basis": basis[:6],
    }


def extract_buying_intent_signals(
    hiring_marketing_or_data_roles: Optional[bool] = None,
    open_positions_total: Optional[int] = None,
    ads_active_last_30d: Optional[bool] = None,
    active_ad_formats: Optional[List[str]] = None,
    recent_change_triggers: Optional[List[str]] = None,
    primary_sales_gap: Optional[str] = None,
    sales_gap_confidence: Optional[str] = None,
) -> List[str]:
    """
    v24.4 Buying Intent Signals (P1):
    Агрегує реальні комерційні тригери наміру купівлі:
      - найм на ролі Marketing / Analytics / Data;
      - активний масовий найм за ATS-фідами;
      - верифікована активна реклама Google Ads (30d);
      - зафіксована зміна ЛПР або технологічного стеку (`recent_change_triggers`);
      - технічно підтверджений розрив атрибуції (`issue_confirmed`).
    """
    signals: List[str] = []
    if hiring_marketing_or_data_roles is True:
        signals.append("HIRING_MARKETING_OR_DATA_ROLES")
    if open_positions_total is not None and int(open_positions_total) >= 5:
        signals.append(f"ACTIVE_HIRING ({int(open_positions_total)} open roles)")
    if ads_active_last_30d is True:
        fmts = ", ".join((active_ad_formats or [])[:3]) or "Search"
        signals.append(f"ACTIVE_GOOGLE_ADS_30D ({fmts})")
    if primary_sales_gap and sales_gap_confidence == "issue_confirmed":
        signals.append(f"CONFIRMED_TECH_GAP: {primary_sales_gap}")
    for trig in (recent_change_triggers or []):
        if trig and trig not in signals:
            signals.append(str(trig))
    return signals[:8]


def resolve_prospect_timezone_and_locale_v23(
    domain: str,
    e164_phone: Optional[str] = None,
    detected_country_code: str = "",
    html_lang_attr: str = "",
    page_title: str = "",
    gdpr_jurisdiction: str = "",
    is_eu_gdpr: bool = False,
) -> Dict[str, str]:
    clean_dom = domain.lower().strip().rstrip(".")
    parts = clean_dom.split(".")
    tld_1 = parts[-1] if parts else ""
    tld_2 = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else ""

    tz: Optional[str] = None
    default_lang = "en"
    has_strict_national_tld = False

    if tld_2 in EXACT_TLD_TO_TZ_AND_LANG:
        tz, default_lang = EXACT_TLD_TO_TZ_AND_LANG[tld_2]
        has_strict_national_tld = (default_lang != "en")
    elif tld_1 in EXACT_TLD_TO_TZ_AND_LANG:
        tz, default_lang = EXACT_TLD_TO_TZ_AND_LANG[tld_1]
        has_strict_national_tld = (default_lang != "en")

    if not tz and e164_phone and e164_phone.startswith("+") and _PHONENUMBERS_TZ_AVAILABLE:
        try:
            parsed_num = phonenumbers.parse(e164_phone, None)
            tz_list = list(pn_timezone.time_zones_for_number(parsed_num) or [])
            if tz_list:
                if len(tz_list) > 5 or tz_list[0] in ("America/Adak", "Etc/Unknown"):
                    tz = "America/New_York" if e164_phone.startswith("+1") else str(tz_list[0])
                else:
                    tz = str(tz_list[0])
        except Exception:
            pass

    cc_low = (detected_country_code or "").strip().lower()
    jur_up = (gdpr_jurisdiction or "").strip().upper()

    if not tz:
        if cc_low in EXACT_TLD_TO_TZ_AND_LANG:
            tz, default_lang = EXACT_TLD_TO_TZ_AND_LANG[cc_low]
        elif jur_up == "UK_GDPR":
            tz, default_lang = ("Europe/London", "en")
        elif jur_up == "UA_PDP":
            tz, default_lang = ("Europe/Kyiv", "uk")
        elif jur_up == "CH_FADP":
            tz, default_lang = ("Europe/Zurich", "de")
        elif jur_up == "EU_EEA_GDPR" or is_eu_gdpr:
            tz, default_lang = ("Europe/Berlin", "en")
        elif cc_low == "us":
            tz, default_lang = ("America/New_York", "en")
        elif cc_low == "ca":
            tz, default_lang = ("America/Toronto", "en")
        else:
            tz, default_lang = ("Europe/London", "en")
    elif default_lang == "en" and cc_low in EXACT_TLD_TO_TZ_AND_LANG:
        _, default_lang = EXACT_TLD_TO_TZ_AND_LANG[cc_low]

    clean_html_lang = (html_lang_attr or "").strip().lower()[:2]
    supported_langs = {"uk", "de", "pl", "fr", "es", "it", "nl", "cs", "pt", "en"}

    is_global_com_brand = tld_1 in ("com", "net", "io", "org", "co", "ai", "app", "tech")

    if page_title and CYRILLIC_TEXT_RE.search(page_title):
        outreach_lang = "uk"
    elif is_global_com_brand and clean_html_lang == "en" and not CYRILLIC_TEXT_RE.search(page_title):
        outreach_lang = "en"
    elif clean_html_lang == "en" and (has_strict_national_tld or tz == "Europe/Kyiv"):
        outreach_lang = default_lang if default_lang != "en" else "uk"
    elif clean_html_lang in supported_langs:
        outreach_lang = clean_html_lang
    else:
        outreach_lang = default_lang

    return {"prospect_iana_timezone": tz, "recommended_outreach_lang": outreach_lang}


def compute_account_change_triggers_v23(
    prev_record: Optional[Dict[str, Any]],
    curr_record: Dict[str, Any]
) -> List[str]:
    if not prev_record or not isinstance(prev_record, dict):
        return []
    triggers: List[str] = []

    old_dm = (prev_record.get("decision_maker_name") or "").strip()
    new_dm = (curr_record.get("decision_maker_name") or "").strip()
    if old_dm and new_dm:
        old_t = set(NAME_TOKEN_RE.findall(old_dm.lower()))
        new_t = set(NAME_TOKEN_RE.findall(new_dm.lower()))
        if old_t and new_t and not (old_t & new_t):
            triggers.append(f"NEW_DECISION_MAKER: {new_dm} (replaced {old_dm})")

    if prev_record.get("ads_active_last_30d") is False and curr_record.get("ads_active_last_30d") is True:
        triggers.append("AD_CAMPAIGN_NEWLY_LAUNCHED")

    old_jobs_raw = prev_record.get("open_positions_total")
    new_jobs_raw = curr_record.get("open_positions_total")
    if old_jobs_raw is not None and new_jobs_raw is not None:
        old_jobs = int(old_jobs_raw)
        new_jobs = int(new_jobs_raw)
        if new_jobs >= old_jobs + 3:
            triggers.append(f"HIRING_SURGE (+{new_jobs - old_jobs} open roles)")

    old_tech = {t.strip() for t in str(prev_record.get("detected_technologies") or "").split(";") if t.strip()}
    new_tech = {t.strip() for t in str(curr_record.get("detected_technologies") or "").split(";") if t.strip()}
    added_candidates = new_tech - old_tech

    prev_schema = int(prev_record.get("_schema") or 0)
    if added_candidates and prev_schema < 29:
        ev_json_raw = curr_record.get("technology_evidence_json")
        if ev_json_raw:
            try:
                ev_map = json.loads(ev_json_raw) if isinstance(ev_json_raw, str) else ev_json_raw
                if isinstance(ev_map, dict):
                    added_candidates = {
                        t for t in added_candidates
                        if (ev_map.get(t) or {}).get("verification_tier") != "allowlisted_in_csp"
                        and (ev_map.get(t) or {}).get("source") != "http_headers_or_ssr"
                    }
            except Exception:
                pass

    added = sorted(added_candidates)
    if added:
        triggers.append(f"ADDED_TECH: {', '.join(added[:3])}")
    return triggers


# ==============================================================================
# v24.4: Програмний комплаєнс-гардрейл та 3 Незалежні Осі Скорингу
# ==============================================================================

def is_impressum_cold_email_blocked(
    gdpr_jurisdiction: str | None,
    data_source_sensitivity: str | None,
    has_confirmed_legitimate_interest: bool = False,
) -> bool:
    return (
        (gdpr_jurisdiction or '').strip().upper() == 'EU_EEA_GDPR'
        and (data_source_sensitivity or '').strip().lower() == 'impressum_statutory_disclosure_restricted'
        and not has_confirmed_legitimate_interest
    )


def is_cold_email_compliance_blocked(
    gdpr_jurisdiction: str | None,
    data_source_sensitivity: str | None,
    canonical_domain: str = '',
    country_hint: str = '',
    has_confirmed_legitimate_interest: bool = False,
) -> Tuple[bool, str]:
    """
    v24.4: Програмна перевірка заборони холодного email-аутрічу:
      1. `eu_impressum_cold_email_blocked` — EU_EEA_GDPR + дані з Impressum без opt-in.
      2. `de_at_uwg7_cold_email_blocked` — Німеччина / Австрія (`.de`, `.at` або country_hint DE/AT)
         згідно з жорсткою вимогою §7 UWG (холодний B2B email заборонено без попередньої згоди).
    """
    if has_confirmed_legitimate_interest:
        return False, 'none'
    if is_impressum_cold_email_blocked(gdpr_jurisdiction, data_source_sensitivity, False):
        return True, 'eu_impressum_cold_email_blocked'
    dom_low = (canonical_domain or '').strip().lower()
    cc_up = (country_hint or '').strip().upper()
    if dom_low.endswith(('.de', '.at')) or cc_up in ('DE', 'AT'):
        return True, 'de_at_uwg7_cold_email_blocked'
    return False, 'none'


def enforce_outreach_compliance_guardrail(
    next_best_action: str,
    compliance_block_code: str,
    dm_name: str | None = None,
    dm_role: str | None = None,
    dm_buyer_fit_status: str = 'no_dm_found',
    has_company_li_people: bool = True,
) -> str:
    """
    v24.4 Programmatic Post-Filter (P0/P1):
    Якщо активовано будь-який комплаєнс-блок (`eu_impressum_cold_email_blocked` або
    `de_at_uwg7_cold_email_blocked`), жорстко перезаписує `next_best_action`, повністю
    виключаючи будь-які рекомендації щодо email-аутрічу та залишаючи виключно LinkedIn / теплий інтро.
    """
    if not compliance_block_code or compliance_block_code == 'none':
        return next_best_action

    li_hint = (
        'company_linkedin_people_url or decision_maker_search_query'
        if has_company_li_people
        else 'decision_maker_search_query'
    )
    if dm_name and dm_buyer_fit_status == 'direct_marketing_buyer':
        target_desc = f'{dm_name} ({dm_role})'
    elif dm_name:
        target_desc = f'Head of Marketing / Head of Digital (or request warm LinkedIn intro via {dm_role or "CEO"} {dm_name})'
    else:
        target_desc = 'Head of Marketing / Head of Digital'

    reason_lbl = (
        'EU/DE Impressum (§7 UWG & DSK)'
        if compliance_block_code == 'eu_impressum_cold_email_blocked'
        else 'DE/AT §7 UWG strict opt-in law'
    )
    return (
        f'COMPLIANCE BLOCK ({reason_lbl}): Unsolicited cold email is programmatically blocked. '
        f'Connect with {target_desc} via LinkedIn only ({li_hint}) or obtain prior written opt-in / warm intro.'
    )


def compute_account_potential_score(
    company_category: str,
    account_scale_tier: str = 'SMB / Local Scale',
    martech_stack_tier: str = 'SMB',
    estimated_markets_count: int = 1,
    catalog_estimated_skus: Optional[int] = None,
    ads_active_last_30d: Optional[bool] = None,
    open_positions_total: Optional[int] = None,
    hiring_marketing_or_data_roles: Optional[bool] = None,
    buying_intent_count: int = 0,
) -> int:
    """
    Вісь 1 (v24.4) — Account Potential Score (0–100):
    Наскільки компанія комерційно приваблива (ICP, масштаб, підтверджений MarTech-стек,
    жива реклама Google Ads, найм та Buying Intent Signals) — незалежно від якості контактів.
    """
    if company_category == 'Non-Profit / Education / Institution':
        return 5

    score = 0
    if company_category == 'E-commerce / Retail Brand':
        score += 28
    elif company_category == 'SaaS / Marketplace / Tech Platform':
        score += 25
    elif company_category == 'General Business / Corporate':
        score += 18
    elif company_category == 'B2B Agency / Marketing Media':
        score += 20

    scale_pts = {'Enterprise Scale': 20, 'Mid-Market Scale': 14, 'SMB / Local Scale': 8}
    score += scale_pts.get(account_scale_tier, 8)

    stack_pts = {'Enterprise': 14, 'Mid-Market': 11, 'SMB': 6, 'Unverified / Minimal': 2}
    score += stack_pts.get(martech_stack_tier, 2)

    if estimated_markets_count >= 10:
        score += 10
    elif estimated_markets_count >= 3:
        score += 7
    elif estimated_markets_count >= 2:
        score += 4

    if catalog_estimated_skus is not None:
        if catalog_estimated_skus >= 5000:
            score += 8
        elif catalog_estimated_skus >= 500:
            score += 5
        elif catalog_estimated_skus >= 50:
            score += 2

    if ads_active_last_30d is True:
        score += 12

    if hiring_marketing_or_data_roles is True:
        score += 8
    elif open_positions_total is not None and int(open_positions_total) >= 3:
        score += 5

    score += min(6, int(buying_intent_count or 0) * 2)
    return max(0, min(100, score))


def compute_account_fit_score(
    company_category: str,
    account_scale_tier: str = 'SMB / Local Scale',
    martech_stack_tier: str = 'SMB',
    estimated_markets_count: int = 1,
    catalog_estimated_skus: Optional[int] = None,
    ads_active_last_30d: Optional[bool] = None,
    open_positions_total: Optional[int] = None,
    hiring_marketing_or_data_roles: Optional[bool] = None,
) -> int:
    return compute_account_potential_score(
        company_category,
        account_scale_tier,
        martech_stack_tier,
        estimated_markets_count,
        catalog_estimated_skus,
        ads_active_last_30d,
        open_positions_total,
        hiring_marketing_or_data_roles,
        buying_intent_count=0,
    )


def compute_evidence_confidence_score(
    scan_completeness: str = 'full',
    techs_count: int = 0,
    confirmed_martech_count: int = 0,
    xhr_fetch_traffic_analyzed: bool = False,
    pw_status_str: str = 'not_needed',
    tls_trust_status: str = 'not_checked',
    best_email_confidence: str = 'NONE',
    sales_gap_confidence: Optional[str] = None,
    is_cached_or_seed: bool = False,
) -> int:
    """
    Вісь 2 (v24.4) — Evidence Confidence Score (0–100):
    Наскільки ми об'єктивно впевнені у зібраних даних:
      - повнота сканування (`full` vs `partial_*`);
      - кількість підтверджених у коді/рантаймі MarTech-платформ (без CSP-only);
      - виконання аналізу XHR/Fetch трафіку Playwright;
      - серверна верифікація email (`M365_AD_VERIFIED` / `SMTP_API_VERIFIED`);
      - рівень доказовості технічної проблеми (`issue_confirmed` > `issue_suspected`);
      - штрафи за таймаути/помилки Playwright та TLS.
    """
    score = 0
    if scan_completeness == 'full':
        score += 34
    elif scan_completeness in ('partial_gtm', 'partial_cached'):
        score += 18
    elif scan_completeness == 'partial_csp_headers':
        score += 8
    else:
        score += 4

    if confirmed_martech_count >= 3:
        score += 18
    elif confirmed_martech_count >= 1:
        score += 10
    elif techs_count >= 1:
        score += 4

    if xhr_fetch_traffic_analyzed:
        score += 16

    if best_email_confidence in ('M365_AD_VERIFIED', 'SMTP_API_VERIFIED'):
        score += 18
    elif best_email_confidence == 'OBSERVED_ON_SITE':
        score += 9
    elif best_email_confidence == 'GRAVATAR_OR_PGP_MATCH':
        score += 6

    if sales_gap_confidence == 'issue_confirmed':
        score += 14
    elif sales_gap_confidence == 'issue_suspected':
        score += 8
    elif sales_gap_confidence == 'server_side_tracking_not_detected_in_client':
        score += 3

    pw_low = (pw_status_str or '').lower()
    pw_err = any(tok in pw_low for tok in ('timeout', 'error', 'blocked', 'empty', 'rejected', 'failed'))
    tls_low = (tls_trust_status or '').lower()
    tls_err = tls_low in ('tls_timeout', 'tls_handshake_failed', 'unreachable')

    if pw_err:
        score -= 18
    if tls_err:
        score -= 10
    if is_cached_or_seed:
        score -= 10

    if scan_completeness != 'full':
        score = min(score, 62)
    if pw_err or tls_err:
        score = min(score, 68)

    return max(0, min(100, score))


def compute_technical_opportunity_score(
    company_category: str,
    tech_info: dict,
    primary_sales_gap: Optional[str] = None,
    sales_gap_confidence: Optional[str] = None,
    ads_active_last_30d: Optional[bool] = None,
    red_flags_count: int = 0,
    xhr_fetch_traffic_analyzed: bool = False,
) -> int:
    if company_category == 'Non-Profit / Education / Institution':
        return 0

    scan_comp = str(tech_info.get('tech_scan_completeness') or 'full')
    if scan_comp == 'partial_csp_headers':
        return 18

    score = 0
    tiers = tech_info.get('tech_verification_tiers') or {}
    confirmed_ad_pixels = sum(
        1 for k, lbl in (
            ('has_meta_pixel', 'Meta Pixel'),
            ('has_google_ads', 'Google Ads Conversion'),
            ('has_tiktok_pixel', 'TikTok Pixel'),
            ('has_linkedin_pixel', 'LinkedIn Insight Tag'),
            ('has_pinterest_tag', 'Pinterest Tag'),
        )
        if tech_info.get(k) is True and tiers.get(lbl) != 'allowlisted_in_csp'
    )

    if confirmed_ad_pixels >= 2:
        score += 22
    elif confirmed_ad_pixels == 1:
        score += 12
    if tech_info.get('has_ga4') or tech_info.get('has_gtm'):
        score += 8

    traffic_checked = bool(xhr_fetch_traffic_analyzed or tech_info.get('xhr_fetch_traffic_analyzed'))

    if primary_sales_gap == 'DUPLICATE_GA4_TRACKING':
        score += 48 if sales_gap_confidence == 'issue_confirmed' else 34
    elif primary_sales_gap == 'EU_CONSENT_MODE_V2_GAP':
        score += 44 if sales_gap_confidence == 'issue_confirmed' else 30
    elif primary_sales_gap == 'ADS_ACTIVE_NO_SERVER_SIDE_TRACKING':
        score += 32 if traffic_checked else 18
    elif primary_sales_gap == 'CLIENT_SIDE_MULTI_PIXEL_NO_SGTM':
        score += 24 if traffic_checked else 14
    elif primary_sales_gap:
        score += 14

    if ads_active_last_30d is True:
        score += 14
    if red_flags_count >= 2:
        score += 10
    elif red_flags_count == 1:
        score += 5

    return max(0, min(100, score))


def derive_contactability_level(
    best_email: str | None,
    best_email_type: str | None,
    dm_name: str | None,
    dm_linkedin_url: str | None,
    primary_phone: str | None,
    best_email_confidence: str = 'NONE',
) -> str:
    is_same_person_email = verify_person_email_match(dm_name, best_email)
    is_same_person_li = verify_person_linkedin_match(dm_name, dm_linkedin_url)

    if dm_name and (is_same_person_email or is_same_person_li):
        return 'direct_dm_verified'
    if best_email_confidence in ('M365_AD_VERIFIED', 'SMTP_API_VERIFIED') and best_email_type == 'personal_or_named_inbox':
        return 'direct_dm_verified'
    if best_email_type == 'marketing_or_exec_role':
        return 'role_inbox_ready'
    if best_email_type == 'personal_or_named_inbox' and best_email:
        return 'role_inbox_ready'
    if best_email or dm_name or primary_phone:
        return 'gatekeeper_only'
    return 'unreached'


def compute_sales_actionability_score(
    contactability_level: str,
    dm_buyer_fit_status: str,
    best_email_confidence: str = 'NONE',
    has_company_linkedin_people_url: bool = False,
    impressum_email_blocked: bool = False,
    company_category: str = '',
) -> int:
    if company_category == 'Non-Profit / Education / Institution':
        return 0

    base_map = {
        'direct_dm_verified': 66,
        'role_inbox_ready': 54,
        'gatekeeper_only': 32,
        'unreached': 8,
    }
    score = base_map.get(contactability_level, 10)

    if dm_buyer_fit_status == 'direct_marketing_buyer':
        score += 22
    elif dm_buyer_fit_status == 'escalation_needed_via_ceo':
        score += 6

    if best_email_confidence in ('M365_AD_VERIFIED', 'SMTP_API_VERIFIED'):
        score += 12
    elif best_email_confidence == 'GRAVATAR_OR_PGP_MATCH':
        score += 5
    elif best_email_confidence == 'OBSERVED_ON_SITE':
        score += 4

    if has_company_linkedin_people_url:
        score += 8

    if impressum_email_blocked:
        score = min(score - 22, 52 if has_company_linkedin_people_url else 35)

    return max(0, min(100, score))


def compute_sales_readiness_score(
    company_category: str,
    dm_buyer_fit_status: str,
    contactability_level: str,
    evidence_confidence_score: int,
    technical_opportunity_score: int,
    best_email_confidence: str = 'NONE',
    compliance_blocked: bool = False,
    has_company_li_people: bool = False,
    buying_intent_count: int = 0,
) -> int:
    """
    Вісь 3 (v24.4) — Sales Readiness Score (0–100):
    Зважена оцінка готовності ліда до передачі у відділ продажів:
      - операційний покупець (`direct_marketing_buyer`), а не лише CEO;
      - валідний канал зв'язку;
      - рівень доведеності даних (`evidence_confidence_score`);
      - юридичний дозвіл на контакт (`not compliance_blocked`).
    Жорсткі стелі гарантують, що акаунти з низькою впевненістю даних (<35),
    лише з CEO (`<=64`) або під комплаєнс-блоком (`<=58`) НЕ отримують статус `SALES_READY`.
    """
    if company_category == 'Non-Profit / Education / Institution':
        return 0

    score = 0
    if dm_buyer_fit_status == 'direct_marketing_buyer':
        score += 38
    elif dm_buyer_fit_status == 'escalation_needed_via_ceo':
        score += 16
    elif contactability_level == 'role_inbox_ready':
        score += 18
    elif contactability_level == 'gatekeeper_only':
        score += 8

    if contactability_level == 'direct_dm_verified':
        score += 20 if best_email_confidence in ('M365_AD_VERIFIED', 'SMTP_API_VERIFIED') else 14
    elif contactability_level == 'role_inbox_ready':
        score += 14
    elif contactability_level == 'gatekeeper_only':
        score += 6
    if has_company_li_people:
        score += 4

    score += int(round(technical_opportunity_score * 0.18))
    score += int(round(evidence_confidence_score * 0.14))
    score += min(6, int(buying_intent_count or 0) * 2)

    if dm_buyer_fit_status == 'escalation_needed_via_ceo':
        score = min(score, 64)
    if dm_buyer_fit_status == 'no_dm_found' and contactability_level != 'role_inbox_ready':
        score = min(score, 48)
    if evidence_confidence_score < 35:
        score = min(score, 35)
    if compliance_blocked:
        score = min(score - 15, 58)
    if company_category == 'B2B Agency / Marketing Media':
        score = min(score, 55)

    return max(0, min(100, score))


def derive_sales_readiness_status(
    company_category: str,
    account_potential_score: int,
    evidence_confidence_score: int,
    sales_readiness_score: int,
    dm_buyer_fit_status: str,
    compliance_blocked: bool = False,
) -> str:
    """
    v24.4 Суворий комерційний статус готовності ліда:
      - `SALES_READY`: лише при `sales_readiness_score >= 70`, `evidence_confidence_score >= 55`,
        наявності операційного маркетолога (`direct_marketing_buyer`) та відсутності юридичного блоку.
      - `ESCALATION_NEEDED`: знайдено лише CEO / Founder / Managing Director (`escalation_needed_via_ceo`).
      - `RESEARCH_PRIORITY`: високий потенціал (`account_potential_score >= 55`), але бракує
        операційного покупця, впевненості даних або діє комплаєнс-блок email.
      - `PARTNER_PIPELINE`: B2B-агенція / медіа.
      - `DISQUALIFIED`: некомерційна / освітня установа.
      - `UNVERIFIED`: низький потенціал та недостатньо доказів.
    """
    if company_category == 'Non-Profit / Education / Institution':
        return 'DISQUALIFIED'
    if company_category == 'B2B Agency / Marketing Media':
        return 'PARTNER_PIPELINE'
    if (
        sales_readiness_score >= 70
        and evidence_confidence_score >= 55
        and dm_buyer_fit_status == 'direct_marketing_buyer'
        and not compliance_blocked
    ):
        return 'SALES_READY'
    if dm_buyer_fit_status == 'escalation_needed_via_ceo':
        return 'ESCALATION_NEEDED'
    if account_potential_score >= 55:
        return 'RESEARCH_PRIORITY'
    return 'UNVERIFIED'


def compute_actionable_priority_score(
    account_potential_score: int,
    evidence_confidence_score: int,
    sales_readiness_score: int,
    company_category: str = '',
) -> int:
    """
    Зведений рейтинг черги (0–100) із домінуванням `sales_readiness_score` (55%),
    щоб акаунти з низькою якістю даних не виходили на високий пріоритет (~60).
    """
    if company_category == 'Non-Profit / Education / Institution':
        return 5

    raw = (
        (sales_readiness_score * 0.55)
        + (evidence_confidence_score * 0.25)
        + (account_potential_score * 0.20)
    )
    if evidence_confidence_score < 35:
        raw = min(raw, 38)
    return max(0, min(100, int(round(raw))))


# ==============================================================================
# Core Qualification, Scoring & Sales Hook Engine
# ==============================================================================

def is_marketplace_platform(canonical_domain: str, page_title: str, meta_desc: str) -> bool:
    if canonical_domain.lower() in KNOWN_MARKETPLACE_DOMAINS:
        return True
    combined = f'{page_title} {meta_desc}'.lower()
    return any(m in combined for m in MARKETPLACE_TEXT_MARKERS)


def classify_company_category(
    domain: str,
    page_title: str,
    meta_desc: str,
    detected_tech: list[str],
    html_sample: str = ''
) -> tuple[str, str]:
    dom_low = (domain or '').lower().replace('www.', '')
    text = f'{dom_low} {page_title} {meta_desc}'.lower()
    if len(html_sample) > 60000:
        html_low = (html_sample[:40000] + '\n' + html_sample[-20000:]).lower()
    else:
        html_low = html_sample.lower()

    agency_keywords = (
        'агентство', 'агенція', 'agency', 'digital marketing', 'діджитал-маркетинг',
        'онлайн-маркетинг', 'маркетингова агенція', 'seo agency', 'ppc agency',
        'web studio', 'веб-студія', 'розробка сайтів', 'software development',
        'медіа про інтернет-маркетинг', 'performance marketing agency', 'агентство інтернет-маркетингу',
        'werbeagentur', 'digitalagentur', 'marketingagentur', 'online-marketing-agentur', 'seo-agentur',
        'agence digitale', 'agence web', 'agence marketing', 'agence de communication', 'agence seo',
        'agencia de marketing', 'agencia digital', 'agencia seo', 'agencia de publicidad',
        'agenzia web', 'agenzia di marketing', 'agenzia digitale', 'agenzia comunicazione',
        'marketingbureau', 'internetbureau', 'online marketing bureau', 'mediabureau',
        'agencja marketingowa', 'agencja interaktywna', 'agencja seo', 'agencja reklamowa',
        'agência digital', 'agência de marketing', 'webbyrå', 'reklambyrå', 'kommunikationsbyrå', 'mediebyrå',
        'promodo', 'netpeak', 'inweb', 'newage'
    )
    if any(k in text for k in agency_keywords):
        return 'B2B Agency / Marketing Media', 'high'

    ecom_keywords = (
        'інтернет-магазин', 'интернет-магазин', 'онлайн магазин', 'online store',
        'shop', 'купити', 'купить', 'купуй', 'доставка по', 'колекція', 'бренд одягу',
        'бренд взуття', 'жіночого одягу', 'женского белья', 'каталог товарів',
        'checkout', 'add to cart', 'кошик', 'shoes', 'apparel', 'clothing',
        'млн товарів', 'знижки до', 'кешбек', 'доставка ліків', 'замовити ліки',
        'аптека', 'apteka', 'ліки', 'pharmacy', 'онлайн-аптека', 'медикаменти',
        'onlineshop', 'online-shop', 'warenkorb', 'versandkostenfrei', 'jetzt kaufen', 'bestellen',
        'parfümerie', 'parfumerie', 'drogerie', 'outdoor', 'klettern', 'bergfreunde', 'musikhaus',
        'boutique en ligne', 'livraison gratuite', 'panier', 'acheter en ligne', 'magasin en ligne',
        'tienda online', 'carrito', 'envío gratis', 'comprar online', 'tienda en línea',
        'negozio online', 'carrello', 'spedizione gratuita', 'acquista online', 'shopping online',
        'webwinkel', 'webshop', 'winkelwagen', 'gratis verzending', 'bestel online',
        'sklep internetowy', 'koszyk', 'darmowa dostawa', 'kup teraz', 'zakupy online',
        'loja online', 'frete grátis', 'carrinho', 'comprar agora',
        'webbutik', 'varukorg', 'fri frakt', 'handla online', 'nettbutikk', 'handlekurv',
        'fashion', 'fashion online', 'accessories', 'footwear', 'sportswear', 'streetwear',
        'skincare', 'makeup', 'fragrance', 'cosmetics', 'beauty products', 'body care', 'shorts', 'swimwear',
        'mode', 'bekleidung', 'kleidung', 'schuhe', 'taschen', 'accessoires',
        'damenmode', 'herrenmode', 'online-shop für mode', 'top-marken', 'versandapotheke', 'online-apotheke',
        'prêt-à-porter', 'vêtements', 'chaussures', 'sacs', 'mode en ligne',
        'moda', 'abbigliamento', 'scarpe', 'borse', 'moda online',
        'kleding', 'schoenen', 'tassen', 'modewinkel',
        'odzież', 'buty', 'torebki', 'moda online',
        'ropa', 'zapatos', 'bolsos', 'moda mujer', 'vestuário', 'calçado'
    )
    has_product_schema = (
        '"@type":"product"' in html_low
        or '"@type": "product"' in html_low
        or 'og:type" content="product"' in html_low
    )
    if (
        dom_low in KNOWN_MARKETPLACE_DOMAINS
        or dom_low in KNOWN_DTC_ECOM_DOMAINS
        or any(cms in detected_tech for cms in ('Shopify', 'WooCommerce', 'Magento', 'Shopware'))
        or has_product_schema
        or any(k in text for k in ecom_keywords)
    ):
        return 'E-commerce / Retail Brand', 'high'

    saas_keywords = (
        'saas', 'cloud platform', 'crm', 'sales crm', 'pipeline management', 'sales pipeline',
        'api', 'b2b software', 'automation platform', 'document workflow', 'form builder',
        'hr software', 'helpdesk', 'live chat', 'customer support platform',
        'майданчик', 'тендер', 'prozorro', 'прозорро', 'закупівлі', 'mobility app',
        'call tracking', 'колтрекінг', 'business phone', 'virtual pbx', 'telephony',
        'end-to-end analytics', 'наскрізна аналітика', 'marketing performance platform',
        'email service', 'automation service', 'chatbot', 'cloud-lösung', 'softwarelösung',
        'logiciel saas', 'plateforme cloud', 'software de gestión', 'piattaforma cloud',
        'oprogramowanie dla firm', 'system crm', 'ringostat', 'sendpulse', 'macpaw', 'readdle', 'grammarly',
        'seo', 'serp', 'keyword', 'keywords', 'backlink', 'backlinks', 'site audit', 'rank tracker',
        'website builder', 'конструктор сайтів', 'створення сайту', 'ai website builder',
        'customer communication', 'customer data platform', 'cdp',
        'omnichannel', 'no-code', 'low-code', 'workflow automation',
        'serpstat', 'weblium', 'esputnik', 'creatio', 'helpcrunch',
        'pipedrive', 'typeform', 'gorgias', 'personio', 'airslate', 'preply', 'zapier'
    )
    if any(k in text for k in saas_keywords):
        return 'SaaS / Marketplace / Tech Platform', 'high'

    spa_ecom_markers = (
        'cdn.shopify.com',
        'myshopify.com',
        'window.shopify',
        'shopify.theme',
        '/cart.js',
        '/checkout',
        '"cart"',
        '"product"',
        '"variant"',
        'add to cart',
        'add-to-cart',
        'addtocart',
    )
    spa_hits = sum(1 for m in spa_ecom_markers if m in html_low or m in text)
    if spa_hits >= 2:
        return 'E-commerce / Retail Brand', 'medium'

    has_commercial_stack = (
        'AW-' in html_sample
        or 'snap.licdn.com' in html_low
        or 'googleadservices.com' in html_low
        or any(t in detected_tech for t in ('Google Ads Conversion', 'LinkedIn Insight Tag', 'Meta Pixel', 'TikTok Pixel', 'Intercom'))
    )
    is_explicit_npo = (
        dom_low.endswith(('.edu', '.edu.ua', '.ac.uk', '.gov', '.gov.ua', '.org', '.org.ua', '.gob.es', '.gouv.fr'))
        or any(
            phrase in text for phrase in (
                'благодійний фонд', 'charitable foundation', 'громадська організація',
                'gemeinnützige', 'eingetragener verein', 'association loi 1901',
                'fundación sin ánimo de lucro', 'fondazione onlus', 'stichting',
                'fundacja', 'stowarzyszenie', 'allmännyttig stiftelse'
            )
        )
    )

    if is_explicit_npo or (
        not has_commercial_stack and any(
            re.search(rf'\b{re.escape(w)}\b', text) for w in (
                'університет', 'university', 'college', 'академія', 'інститут', 'ngo',
                'universität', 'hochschule', 'université', 'universidad', 'università',
                'universiteit', 'uniwersytet', 'universidade'
            )
        )
    ):
        return 'Non-Profit / Education / Institution', 'high' if is_explicit_npo else 'medium'

    if has_commercial_stack:
        if any(k in text for k in ('platform', 'software', 'app', 'apps', 'cloud', 'security system', 'analytics')):
            return 'SaaS / Marketplace / Tech Platform', 'medium'
        return 'General Business / Corporate', 'high'

    return 'General Business / Corporate', 'medium'


def build_linkedin_xray_query(
    canonical_domain: str,
    company_category: str = '',
    country_hint: str = ''
) -> str:
    brand_root = canonical_domain.split('.')[0].capitalize()
    dom_low = canonical_domain.lower()
    hint_up = (country_hint or '').upper().strip()

    if company_category == 'Non-Profit / Education / Institution':
        return (
            f'site:linkedin.com/in ("{canonical_domain}" OR "{brand_root}") '
            f'("Директор" OR "Голова правління" OR "Ректор" OR "Director" OR "Board Member" OR "Founder" OR "Vorstand")'
        )

    if dom_low.endswith(('.de', '.at', '.ch')) or hint_up in ('DE', 'AT', 'CH'):
        local_roles = ' OR "Marketingleiter" OR "Leiter Marketing" OR "Head of E-Commerce" OR "Head of Digital"'
    elif dom_low.endswith('.fr') or hint_up == 'FR':
        local_roles = ' OR "Directeur Marketing" OR "Responsable Marketing" OR "Directeur E-commerce"'
    elif dom_low.endswith('.es') or hint_up == 'ES':
        local_roles = ' OR "Director de Marketing" OR "Responsable de Marketing" OR "Head of Digital"'
    elif dom_low.endswith('.it') or hint_up == 'IT':
        local_roles = ' OR "Direttore Marketing" OR "Responsabile Marketing" OR "Head of E-commerce"'
    elif dom_low.endswith(('.nl', '.be')) or hint_up in ('NL', 'BE'):
        local_roles = ' OR "Marketing Directeur" OR "Hoofd Marketing" OR "E-commerce Manager"'
    elif dom_low.endswith('.pl') or hint_up == 'PL':
        local_roles = ' OR "Dyrektor Marketingu" OR "Head of E-commerce" OR "Head of Digital"'
    elif dom_low.endswith('.pt') or hint_up == 'PT':
        local_roles = ' OR "Diretor de Marketing" OR "Head of Digital"'
    elif dom_low.endswith(('.se', '.no', '.dk', '.fi')) or hint_up in ('SE', 'NO', 'DK', 'FI'):
        local_roles = ' OR "Marknadschef" OR "Markedssjef" OR "Head of Digital"'
    elif dom_low.endswith('.ua') or hint_up == 'UA':
        local_roles = ' OR "Директор з маркетингу" OR "Керівник відділу маркетингу" OR "Head of Digital"'
    else:
        local_roles = ''

    return (
        f'site:linkedin.com/in ("{canonical_domain}" OR "{brand_root}") '
        f'("CMO" OR "Chief Marketing Officer" OR "Head of Marketing" OR "Marketing Director" '
        f'OR "Head of E-commerce" OR "Head of Digital" OR "Head of Growth"{local_roles})'
    )


def compute_data_quality_score(
    contact_quality_tier: str | None,
    techs_count: int,
    dm_name: str | None,
    dm_linkedin_url: str | None,
    primary_phone: str | None,
    scan_completeness: str = 'full',
    is_cached_or_seed: bool = False,
    company_category: str = '',
    is_manual_seed: bool = False,
    is_same_person_email: bool = False,
    pw_status_str: str = 'not_needed',
    tls_trust_status: str = 'not_checked',
    best_email_confidence: str = 'NONE',
    email_deliverability_check: str | None = None,
) -> int:
    if company_category == 'Non-Profit / Education / Institution':
        return 10

    score = 0
    t_str = contact_quality_tier or ''
    is_unmatched_staff_email = ('Different from Listed Executive' in t_str or 'Listed Executive is' in t_str)
    server_verified = is_server_verified_email_confidence(best_email_confidence, email_deliverability_check)

    if is_same_person_email and server_verified:
        score += 55
    elif is_same_person_email:
        score += 42
    elif 'Tier A-' in t_str or 'Agency Tier A' in t_str:
        score += 38
    elif 'Tier A' in t_str:
        score += 42
    elif 'Tier B+' in t_str or 'Agency Tier B+' in t_str:
        score += 32
    elif 'Tier B' in t_str:
        score += 26
    elif 'Tier C' in t_str or 'Agency Tier C' in t_str:
        score += 18
    elif 'Tier D' in t_str:
        score += 6

    if dm_name and not is_unmatched_staff_email:
        score += 15
    if dm_linkedin_url:
        score += 8
    if primary_phone:
        score += 6

    if techs_count >= 4:
        score += 16
    elif techs_count >= 2:
        score += 12
    elif techs_count == 1:
        score += 6

    if server_verified:
        score += 10

    if scan_completeness != 'full' or techs_count == 0:
        if scan_completeness == 'partial_cached' and techs_count >= 4 and not dm_name and not primary_phone:
            score -= 8
        else:
            score -= 15

    pw_low = (pw_status_str or '').lower()
    pw_had_error = any(tok in pw_low for tok in ('timeout', 'error', 'blocked', 'empty', 'rejected', 'failed'))
    if pw_had_error:
        score -= 15

    tls_low = (tls_trust_status or '').lower()
    tls_had_error = tls_low in ('tls_timeout', 'tls_handshake_failed', 'unreachable')
    if tls_had_error:
        score -= 10

    if not server_verified:
        score = min(score, 84)
    if pw_had_error or tls_had_error:
        score = min(score, 75)

    has_any_signal_or_contact = (techs_count >= 1) or ('Tier F' not in t_str and bool(t_str))
    floor_score = 10 if has_any_signal_or_contact else 0
    score = max(floor_score, min(100, score))

    if company_category == 'B2B Agency / Marketing Media':
        return min(40, score)
    if is_manual_seed:
        return min(65, score)

    return score


def build_sales_hook(
    canonical_domain: str,
    company_category: str,
    tech_info: dict,
    dm_name: str | None,
    dm_role: str | None,
    dm_linkedin_url: str | None,
    best_email: str | None,
    is_eu_gdpr: bool = False,
    pw_used: bool = False,
    best_email_type: str | None = None,
    is_marketplace: bool = False,
    ads_active_last_30d: bool | None = None,
    active_ad_formats: list[str] | None = None,
    dm_buyer_fit_status: str | None = None,
) -> str:
    brand = canonical_domain.split('.')[0].capitalize() if canonical_domain else 'Company'
    if company_category == 'Non-Profit / Education / Institution':
        return f'{brand} is a non-profit/institutional entity — exclude from commercial outbound.'

    brand_token = canonical_domain.split('.')[0].lower() if canonical_domain else ''
    em_type = best_email_type or classify_email_type(best_email, brand_token)
    buyer_fit = dm_buyer_fit_status or classify_dm_buyer_fit(dm_name, dm_role)
    is_unmatched_named_inbox = bool(
        best_email
        and em_type == 'personal_or_named_inbox'
        and dm_name
        and not verify_person_email_match(dm_name, best_email)
    )

    if company_category == 'B2B Agency / Marketing Media':
        if is_unmatched_named_inbox:
            dm_part = f' (Named Contact: {best_email} | Listed {dm_role or "Executive"}: {dm_name})'
        elif dm_name:
            dm_part = f' (Exec: {dm_name}, {dm_role})'
        elif best_email:
            dm_part = f' (Contact: {best_email})'
        else:
            dm_part = ''
        return (
            f'{brand} — B2B Agency{dm_part}. Partner Hook: '
            f'"Are you open to white-label analytics/sGTM implementation or lead-data partnership for your e-com clients?"'
        )

    techs = tech_info.get('detected_technologies_list') or []
    cms = tech_info.get('detected_cms')
    scan_comp = str(tech_info.get('tech_scan_completeness') or 'full')
    ga4_count = int(tech_info.get('all_ga4_ids_count') or 0)
    gtm_ids = tech_info.get('gtm_ids') or []
    has_gtm = bool(tech_info.get('has_gtm'))
    has_sgtm = bool(tech_info.get('has_sgtm'))
    has_ga4 = bool(tech_info.get('has_ga4'))
    has_meta = bool(tech_info.get('has_meta_pixel'))
    has_gads = bool(tech_info.get('has_google_ads'))
    has_tiktok = bool(tech_info.get('has_tiktok_pixel'))
    has_li = bool(tech_info.get('has_linkedin_pixel'))
    has_consent = bool(tech_info.get('has_cookie_banner'))
    has_cm_v2 = bool(tech_info.get('has_consent_mode_v2_signals'))
    dup_ga4_ids = tech_info.get('duplicate_ga4_ids') or []
    dup_runtime_confirmed = bool(tech_info.get('duplicate_ga4_runtime_confirmed'))
    xhr_analyzed = bool(tech_info.get('xhr_fetch_traffic_analyzed'))

    if buyer_fit == 'direct_marketing_buyer' and dm_name:
        dm_intro = f'{dm_name} ({dm_role})'
    elif buyer_fit == 'escalation_needed_via_ceo' and dm_name:
        dm_intro = f'Head of Marketing / Head of E-commerce (Account: {brand}; escalation via listed {dm_role or "CEO"}: {dm_name})'
    elif is_unmatched_named_inbox:
        dm_intro = f'Head of Marketing / Digital Lead (via named contact {best_email}; listed {dm_role or "Exec"}: {dm_name})'
    else:
        dm_intro = 'Head of Marketing / Head of Digital'

    li_badge = ' [LinkedIn verified]' if (dm_linkedin_url and buyer_fit == 'direct_marketing_buyer') else ''
    stack_str = ', '.join(techs[:5]) if techs else ('Consent-gated / unverified stack' if has_consent else 'No public ad pixels detected')
    cms_str = f' on {cms}' if cms else ''

    if scan_comp == 'partial_csp_headers':
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"CSP Allowlist Signals: {stack_str} (tag firing unverified due to strict bot protection). "
            f"Opening Hook: \"Reaching out regarding {brand}'s digital analytics & attribution setup — "
            f"who currently oversees marketing measurement and server-side tracking on your team?\""
        )

    if dup_ga4_ids:
        dup_id = dup_ga4_ids[0]
        dup_tag = 'duplicate_runtime_hits_confirmed' if dup_runtime_confirmed else 'duplicate_configuration_suspected'
        gtm_ref = f"container {gtm_ids[0]} and " if gtm_ids else "your GTM container and "
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} [Red Flag: Duplicate GA4 Tagging ({dup_id} in both HTML & GTM — {dup_tag})]. "
            f"Opening Hook: \"Noticed {brand}'s {gtm_ref}page HTML both reference GA4 property {dup_id} — "
            f"have you audited trigger deduplication so pageviews and conversions aren't double-counted?\""
        )

    if ga4_count >= 5:
        prop_clause = f"across your {ga4_count} regional GA4 properties"
        gap_angle = (
            "EEA Consent Mode v2 (gcs/gcd) signaling and cross-domain attribution"
            if (is_eu_gdpr and has_gads and not has_cm_v2)
            else ("server-side tracking / first-party data collection" if not has_sgtm else "CAPI event match quality")
        )
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} ({ga4_count} GA4 properties detected). "
            f"Opening Hook: \"Saw {brand} manages multi-market tracking {prop_clause} — "
            f"how is your team currently standardizing {gap_angle} across regions?\""
        )

    if ads_active_last_30d is True and not has_sgtm:
        formats_str = ', '.join(active_ad_formats) if active_ad_formats else 'Search & Display'
        sgtm_scope_lbl = (
            'issue_suspected (XHR/Fetch checked; custom API/Worker possible)'
            if xhr_analyzed
            else 'server_side_tracking_not_detected_in_client'
        )
        obs_detail = (
            "our browser XHR/Fetch traffic check didn't observe first-party /collect or Zaraz/sGTM requests"
            if xhr_analyzed
            else "we didn't spot a client-facing sGTM endpoint in the public markup"
        )
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} [Active Ads Verified: {formats_str}; {sgtm_scope_lbl}]. "
            f"Opening Hook: \"Saw {brand} is actively running {formats_str} ads in Google Ads Transparency — "
            f"{obs_detail}; are you routing conversions via a custom server-side/API setup or exploring sGTM?\""
        )

    cm_v2_gap_note = ''
    if (
        is_eu_gdpr
        and has_gads
        and not has_cm_v2
        and scan_comp == 'full'
        and (pw_used or has_consent)
    ):
        cm_v2_gap_note = ' [EU Consent Mode v2 gap: Google Ads active without gcs/gcd parameters observed]'

    paid_channels = [c for c, flag in (('Meta', has_meta), ('Google Ads', has_gads), ('TikTok', has_tiktok), ('LinkedIn', has_li)) if flag]

    if has_sgtm and paid_channels:
        paid_str = ' + '.join(paid_channels)
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} (Server-Side Tracking verified){cm_v2_gap_note}. "
            f"Opening Hook: \"Saw {brand} has {paid_str} tags configured alongside server-side tracking — "
            f"how are you currently benchmarking CAPI event match quality and attribution across channels?\""
        )

    if (has_meta or has_tiktok) and not has_gads:
        social_ch = 'Meta & TikTok' if (has_meta and has_tiktok) else ('Meta Pixel' if has_meta else 'TikTok Pixel')
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str}. Observation: Paid social tags ({social_ch}) configured in HTML/GTM, without observable Google Ads Conversion tags. "
            f"Opening Hook: \"Saw {brand} has {social_ch} tracking configured — are you routing Google Ads/PMax attribution "
            f"through a separate server-side setup or focusing paid acquisition on social?\""
        )

    if paid_channels:
        paid_str = ' + '.join(paid_channels)
        if cm_v2_gap_note:
            return (
                f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
                f"Stack: {stack_str}{cm_v2_gap_note}. "
                f"Opening Hook: \"Noticed {brand} has {paid_str} tags configured in the EU market without observable "
                f"Google Consent Mode v2 (gcs/gcd) parameters — have you audited EEA conversion modeling yet?\""
            )
        sgtm_note = 'issue_suspected' if xhr_analyzed else 'server_side_tracking_not_detected_in_client'
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str}. Client-side ad tracking tags ({paid_str}) configured on site ({sgtm_note}). "
            f"Opening Hook: \"Noticed {brand} is running client-side {paid_str} tags{cms_str} without an observable sGTM endpoint — "
            f"are you already handling server-side conversion APIs internally or benchmarking ITP signal loss?\""
        )

    if has_gtm or has_ga4:
        if has_consent:
            return (
                f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
                f"Stack: {stack_str} (strict CMP consent banner active). "
                f"Opening Hook: \"With {brand}'s EU cookie banner gating tracking scripts prior to consent, "
                f"have you benchmarked how much attribution is dropping before Consent Mode v2 modeling kicks in?\""
            )
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} (analytics active, zero paid ad pixels in static HTML). "
            f"Opening Hook: \"Noticed {brand} has GA4/GTM configured without visible Meta or Google Ads remarketing tags — "
            f"is paid acquisition handled via a server-side container or consent-gated trigger?\""
        )

    return (
        f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
        f"Stack: {stack_str}. "
        f"Opening Hook: \"Reaching out regarding {brand}'s digital analytics & attribution setup — "
        f"who currently oversees marketing measurement and CRO benchmarks on your team?\""
    )


def evaluate_qualification_v180(
    company_category: str,
    tech_info: dict,
    best_email: str | None,
    best_email_type: str | None,
    primary_phone: str | None,
    dm_name: str | None,
    dm_role: str | None,
    dm_linkedin_url: str | None,
    dm_source_is_legal: bool,
    dm_source_type: str | None,
    linkedin_url: str | None,
    had_marketplace_pollution: bool = False,
    pw_status_str: str = 'not_needed',
    predicted_dm_email: str | None = None,
    is_mp_platform: bool = False,
    gdpr_jurisdiction: str = '',
    data_source_sensitivity: str = '',
    has_confirmed_legitimate_interest: bool = False,
    dm_buyer_fit_status: str | None = None,
    company_linkedin_people_url: str | None = None,
    canonical_domain: str = '',
    country_hint: str = '',
) -> tuple[str, str, str, str, str, str, str, str, str]:
    detected_list = tech_info.get('detected_technologies_list', [])
    ad_tags = []
    if tech_info.get('has_meta_pixel') or 'Meta Pixel' in detected_list:
        ad_tags.append('Meta Pixel')
    if tech_info.get('has_google_ads') or 'Google Ads Conversion' in detected_list:
        ad_tags.append('Google Ads Conversion')
    if tech_info.get('has_tiktok_pixel') or 'TikTok Pixel' in detected_list:
        ad_tags.append('TikTok Pixel')
    if tech_info.get('has_linkedin_pixel') or 'LinkedIn Insight Tag' in detected_list:
        ad_tags.append('LinkedIn Insight Tag')
    if tech_info.get('has_pinterest_tag') or 'Pinterest Tag' in detected_list:
        ad_tags.append('Pinterest Tag')

    analytics_tags = []
    if tech_info.get('has_ga4') or 'Google Analytics (GA4)' in detected_list:
        analytics_tags.append('GA4')
    if tech_info.get('has_gtm') or 'Google Tag Manager' in detected_list:
        analytics_tags.append('GTM')
    if tech_info.get('has_sgtm') or 'Server-Side GTM (sGTM)' in detected_list:
        analytics_tags.append('sGTM')

    for ux_tool in (
        'Adobe Analytics', 'Segment', 'Tealium', 'Amplitude', 'Mixpanel',
        'Microsoft Clarity', 'Hotjar', 'HubSpot', 'Klaviyo', 'Intercom',
    ):
        if ux_tool in detected_list and ux_tool not in analytics_tags:
            analytics_tags.append(ux_tool)

    all_signals = ad_tags + analytics_tags
    detected_cms = tech_info.get('detected_cms_list', [])
    has_cookie_banner = tech_info.get('has_cookie_banner', False)
    scan_comp = tech_info.get('tech_scan_completeness', 'full')

    pw_blocked_by_waf = (
        pw_status_str.startswith('launched_blocked')
        or pw_status_str in ('skipped_hopeless_waf', 'launched_empty_shell', 'launched_empty')
    )

    if all_signals:
        if scan_comp == 'partial_csp_headers':
            detected_signals_str = f"{', '.join(all_signals)} (CSP Header Allowlist Only)"
        else:
            detected_signals_str = ', '.join(all_signals)
    elif detected_cms:
        consent_note = ' — ad tags likely consent-gated' if has_cookie_banner else ''
        detected_signals_str = f"None detected ({', '.join(detected_cms)} platform only{consent_note})"
    else:
        detected_signals_str = 'None detected'

    is_agency = (company_category == 'B2B Agency / Marketing Media')
    buyer_fit = dm_buyer_fit_status or classify_dm_buyer_fit(dm_name, dm_role)
    compliance_blocked, compliance_block_code = is_cold_email_compliance_blocked(
        gdpr_jurisdiction,
        data_source_sensitivity,
        canonical_domain=canonical_domain,
        country_hint=country_hint,
        has_confirmed_legitimate_interest=has_confirmed_legitimate_interest,
    )

    if company_category == 'E-commerce / Retail Brand':
        icp_fit_tier = 'Tier 1: Target ICP (E-commerce / Retail Brand)'
    elif company_category in ('SaaS / Marketplace / Tech Platform', 'General Business / Corporate'):
        icp_fit_tier = f'Tier 2: Secondary ICP ({company_category})'
    elif is_agency:
        icp_fit_tier = 'Partner / Competitor Segment (Agency / Media — Exclude from Standard Client Outreach)'
    else:
        icp_fit_tier = 'Non-Target ICP (Non-Profit / Education / Institution)'

    if scan_comp == 'partial_csp_headers':
        tech_signal = (
            f"Unverified Stack (CSP Allowlist Only — Browser Render Needed; "
            f"domains observed in security policy: {', '.join(all_signals[:5])})"
        )
    elif len(ad_tags) >= 2 and analytics_tags:
        tech_signal = (
            f"High Stack Maturity: Multi-pixel ad tracking ({', '.join(ad_tags)}) + {'/'.join(analytics_tags[:2])} "
            "(Verified in HTML/GTM; confirms tracking infrastructure, not current ad spend)"
        )
    elif len(ad_tags) == 1:
        if scan_comp == 'partial_gtm':
            partial_note = ' (Partial GTM macro unpack — secondary ad tags may be server-side or consent-gated)'
        elif scan_comp != 'full':
            partial_note = ' (Partial scan due to browser timeout — GA4/GTM unverified)'
        else:
            partial_note = ' (Secondary tags not found in static HTML/GTM or gated by Cookie Consent)'
        tech_signal = f"Moderate Stack Maturity: Single ad pixel ({ad_tags[0]}) detected{partial_note}"
    elif analytics_tags:
        if scan_comp == 'partial_gtm':
            gtm_note = 'partial GTM macro unpack; ad pixels likely server-side (sGTM) or consent-gated'
        else:
            gtm_note = 'ad pixels not found in static HTML/GTM (not proof of absence if server-side/consent-gated)'
        tech_signal = f"Basic Analytics Only ({', '.join(analytics_tags)}) — {gtm_note}"
    else:
        tech_signal = (
            'Low / Unverified Tech Signal: No tracking tags found in static HTML '
            '(Tag absence is not confirmed if site uses strict Cookie Consent or custom JS loader)'
        )

    is_same_person_email = verify_person_email_match(dm_name, best_email)
    is_same_person_li = verify_person_linkedin_match(dm_name, dm_linkedin_url)
    dm_is_direct_mkt_buyer = (buyer_fit == 'direct_marketing_buyer')
    is_mp_founder_with_vendor_b2b = (
        is_mp_platform
        and not dm_is_direct_mkt_buyer
        and best_email_type == 'b2b_partnerships'
    )

    source_extra_note = ''
    if compliance_blocked:
        source_extra_note = (
            f' COMPLIANCE BLOCK ({compliance_block_code}): Unsolicited cold email is prohibited under §7 UWG / DSK — '
            f'use LinkedIn or warm intro only.'
        )
    elif dm_source_is_legal and dm_source_type not in ('impressum_page', 'impressum_page_cached'):
        source_extra_note = ' DM identified from legal/terms document — verify active operational role via LinkedIn before outbound.'
    elif dm_source_type in ('product_or_service_page', 'blog_or_press_page', 'product_or_service_page_cached', 'blog_or_press_page_cached'):
        source_extra_note = f' DM identified on {dm_source_type} — verify active role via LinkedIn.'

    if is_agency:
        if dm_name and best_email_type == 'personal_or_named_inbox' and not is_same_person_email:
            contact_quality = (
                f'Agency Tier B+ (Named Staff Inbox {best_email} Found, '
                f'Listed Executive is {dm_name})'
            )
            enrichment_status = 'agency_partner_unmatched_executive_and_staff_email'
            confidence_warning = (
                f'Note: Agency partnership contact — route to {best_email}, not to {dm_name}.{source_extra_note}'
            )
        elif dm_name:
            contact_quality = f'Agency Tier A- (Executive {dm_name} Identified — Route to Partner Pipeline)'
            enrichment_status = 'agency_partner_executive_identified'
            confidence_warning = source_extra_note.strip() or 'None'
        else:
            contact_quality = f'Agency Tier C ({best_email or "General Channel"} — Route to Partner Pipeline)'
            enrichment_status = 'agency_partner_channel'
            confidence_warning = source_extra_note.strip() or 'None'
    elif dm_name and is_same_person_email and dm_is_direct_mkt_buyer:
        contact_quality = f'Tier A (Verified Marketing Buyer: {dm_name}, {dm_role} + Matching Direct Email)'
        enrichment_status = 'verified_marketing_buyer_and_matching_email'
        confidence_warning = source_extra_note.strip() or 'None'
    elif dm_name and is_same_person_email:
        contact_quality = f'Tier A- (Verified CEO/Executive: {dm_name} + Direct Email — escalation_needed_via_ceo)'
        enrichment_status = 'escalation_needed_via_ceo'
        confidence_warning = (
            f'Note: {dm_name} ({dm_role}) is CEO/Founder level, not operational marketing — '
            f'use LinkedIn marketing people filter or ask for internal referral to CMO/Head of Digital.{source_extra_note}'
        )
    elif dm_name and is_same_person_li:
        role_tag = 'Marketing Buyer' if dm_is_direct_mkt_buyer else 'CEO/Executive (escalation_needed_via_ceo)'
        contact_quality = (
            f'Tier A- ({role_tag} {dm_name} + Name-Matched LinkedIn URL Verified; '
            f'Site Email is {best_email_type or "None"})'
        )
        enrichment_status = (
            'decision_maker_linkedin_verified_paired_with_site_contact'
            if dm_is_direct_mkt_buyer
            else 'escalation_needed_via_ceo'
        )
        confidence_warning = f'Note: Decision-maker LinkedIn slug matches person name; site email is a company/department inbox.{source_extra_note}'
    elif dm_name and best_email_type == 'marketing_or_exec_role':
        contact_quality = f'Tier A- (Decision-Maker Found: {dm_name} + Direct Marketing Role Inbox: {best_email})'
        enrichment_status = (
            'decision_maker_found_plus_marketing_role_inbox'
            if dm_is_direct_mkt_buyer
            else 'escalation_needed_via_ceo'
        )
        confidence_warning = f'Note: Executive identified on site and paired with dedicated marketing@ department inbox.{source_extra_note}'
    elif dm_name and is_mp_founder_with_vendor_b2b:
        contact_quality = (
            f'Tier B (Marketplace Founder/Executive {dm_name} + Vendor/B2B Desk {best_email} — escalation_needed_via_ceo)'
        )
        enrichment_status = 'escalation_needed_via_ceo'
        confidence_warning = (
            f'Note: {dm_name} ({dm_role}) is corporate founder/board level and {best_email} handles commercial/vendor inquiries; '
            f'locate operational CMO / Head of Digital via LinkedIn before pitching analytics.{source_extra_note}'
        )
    elif dm_name and best_email_type in ('b2b_partnerships', 'wholesale_or_sales_inbox'):
        contact_quality = (
            f'Tier B (Executive Found: {dm_name} + Commercial/Partner Inbox: {best_email} — Request CMO Referral)'
        )
        enrichment_status = 'escalation_needed_via_ceo' if not dm_is_direct_mkt_buyer else 'executive_paired_with_partner_or_sales_channel'
        confidence_warning = (
            f'Note: Listed executive ({dm_name}) paired with partner/commercial inbox ({best_email}); '
            f'request referral to CMO / Head of Digital.{source_extra_note}'
        )
    elif dm_name and best_email_type == 'personal_or_named_inbox' and not is_same_person_email:
        contact_quality = (
            f'Tier B+ (Named Staff Inbox {best_email} Found, '
            f'Different from Listed Executive {dm_name})'
        )
        enrichment_status = 'unmatched_executive_and_staff_email'
        confidence_warning = (
            f'Warning: Email {best_email} belongs to a different person than '
            f'the executive found ({dm_name}). Do not address {best_email} as {dm_name}.{source_extra_note}'
        )
    elif dm_name and best_email_type in (
        'legal_or_hr_inbox', 'customer_support_inbox', 'pr_and_media_inbox',
        'influencer_gifting_inbox', 'admissions_or_department_inbox'
    ):
        contact_quality = (
            f'Tier C- (Executive {dm_name} Identified on Site, '
            f'but Email {best_email} is {best_email_type} — Do Not Cold Pitch Email)'
        )
        enrichment_status = 'escalation_needed_via_ceo' if not dm_is_direct_mkt_buyer else 'executive_named_but_only_non_sales_inbox_on_site'
        confidence_warning = (
            f'Warning: {dm_name} found on site, but {best_email} is {best_email_type}. '
            f'Use LinkedIn to locate Head of Marketing rather than emailing {best_email}.{source_extra_note}'
        )
    elif dm_name and best_email_type in ('brand_webmail_support_inbox', 'brand_webmail_general_inbox'):
        contact_quality = (
            f'Tier C (Owner/Executive {dm_name} Identified + Brand Webmail {best_email} Found)'
        )
        enrichment_status = 'escalation_needed_via_ceo' if not dm_is_direct_mkt_buyer else 'owner_identified_paired_with_brand_webmail'
        confidence_warning = (
            f'Note: Company uses public webmail ({best_email}) as its primary contact.{source_extra_note}'
        )
    elif dm_name and (best_email or primary_phone):
        tier_prefix = 'Tier B-' if not all_signals else 'Tier B'
        contact_quality = f'{tier_prefix} (Decision-Maker Found: {dm_name}, Paired with Generic/B2B Inbox)'
        enrichment_status = 'escalation_needed_via_ceo' if not dm_is_direct_mkt_buyer else 'decision_maker_named_separately_from_generic_inbox'
        confidence_warning = f'Warning: Person name verified on site; email is company role/generic inbox (not direct personal email).{source_extra_note}'
    elif best_email_type in ('personal_or_named_inbox', 'marketing_or_exec_role'):
        contact_quality = f'Tier B+ (Direct / Named Role Inbox: {best_email_type}, Full Name Unlisted)'
        enrichment_status = 'named_or_role_email_found_needs_title_match'
        confidence_warning = source_extra_note.strip() or 'None'
    elif best_email_type == 'b2b_partnerships':
        contact_quality = 'Tier B (B2B / Corporate Partnership Inbox — Good for B2B Pitch, Needs Referral for Analytics/Tech)'
        enrichment_status = 'b2b_role_inbox_only_needs_linkedin_dm'
        confidence_warning = f'Note: B2B/Corporate inbox is for commercial partnerships; request referral to CMO/Head of Digital.{source_extra_note}'
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox'):
        contact_quality = 'Tier C (Generic Office Inbox — Suitable for Gatekeeper Routing Only)'
        enrichment_status = 'generic_inbox_only_needs_linkedin_dm'
        confidence_warning = source_extra_note.strip() or 'None'
    elif best_email_type == 'brand_webmail_support_inbox':
        contact_quality = f'Tier C (Primary Brand Webmail Inbox: {best_email} — Suitable for Initial Routing)'
        enrichment_status = 'brand_webmail_only_needs_linkedin_dm'
        confidence_warning = f'Note: Brand uses a single Gmail/Webmail inbox for inquiries; request forwarding to marketing/management.{source_extra_note}'
    elif best_email_type == 'influencer_gifting_inbox':
        contact_quality = f'Tier C- (influencer_gifting_inbox: {best_email} — Creator/PR Gifting Channel)'
        enrichment_status = 'influencer_gifting_inbox_needs_linkedin_dm'
        confidence_warning = f'Warning: Email is for creator/influencer gifting (gteam/collabs), not B2B tech/analytics procurement.{source_extra_note}'
    elif best_email_type in ('wholesale_or_sales_inbox', 'regional_branch_inbox', 'department_or_general_inbox', 'admissions_or_department_inbox'):
        contact_quality = f'Tier C- ({best_email_type} — Non-Marketing Department Channel)'
        enrichment_status = 'non_marketing_department_inbox_needs_linkedin_dm'
        confidence_warning = f'Warning: Email belongs to {best_email_type}, not marketing decision-maker.{source_extra_note}'
    elif best_email_type in ('customer_support_inbox', 'pr_and_media_inbox', 'legal_or_hr_inbox'):
        contact_quality = f'Tier D (Low Sales Fit: {best_email_type} — Do Not Cold Pitch Services Here)'
        enrichment_status = 'support_or_pr_inbox_only_requires_dm_enrichment'
        confidence_warning = f'Warning: Email is {best_email_type}; avoid direct cold sales pitch.{source_extra_note}'
    elif primary_phone:
        contact_quality = 'Tier D (Phone Only — No Email Found on Public Pages)'
        enrichment_status = 'phone_only_requires_email_and_dm_enrichment'
        confidence_warning = f'Warning: No public email found; phone routing or LinkedIn required.{source_extra_note}'
    else:
        contact_quality = 'Tier F (No Actionable Contacts Found on Website)'
        if had_marketplace_pollution:
            enrichment_status = 'marketplace_external_emails_filtered_needs_linkedin_dm'
            confidence_warning = 'Warning: External third-party brand emails filtered out (marketplace_pollution); locate internal DM via LinkedIn.'
        elif pw_blocked_by_waf:
            enrichment_status = 'playwright_blocked_by_waf_needs_residential_proxy'
            confidence_warning = (
                f'Warning: Deep browser scan returned empty shell or was blocked by WAF ({pw_status_str}); '
                f'retry with residential proxy or enrich via LinkedIn.'
            )
        elif pw_status_str == 'rendered':
            enrichment_status = 'lead_form_only_no_public_contacts'
            confidence_warning = (
                'Warning: Zero public emails/phones on site (contact info gated behind interactive lead forms only — '
                'not scanner failure); requires external B2B enrichment.'
            )
        else:
            enrichment_status = 'no_public_contacts_found'
            confidence_warning = 'Warning: Zero public contacts on site; requires external B2B enrichment.'

    # Вердикт із жорсткою забороною статусу Sales-Ready для CEO-only або комплаєнс-блоку
    if company_category == 'Non-Profit / Education / Institution':
        readiness_verdict = 'Disqualified (Non-Target Institutional / NGO Segment)'
    elif is_agency:
        readiness_verdict = 'Partner Pipeline Only (Agency / Media Segment)'
    elif not all_signals and not best_email and not primary_phone:
        if pw_blocked_by_waf:
            readiness_verdict = 'Unverified (Playwright Blocked by WAF — Retry with Residential Proxy)'
        else:
            readiness_verdict = 'Unverified (No Tech Signals & No Public Contacts Observed — Needs Manual Review)'
    elif compliance_blocked:
        if dm_name and dm_is_direct_mkt_buyer:
            readiness_verdict = f'LinkedIn / Warm-Intro Only ({dm_name} Identified; Cold Email Blocked under §7 UWG)'
        elif dm_name:
            readiness_verdict = f'LinkedIn / Warm-Intro Only (Escalation via {dm_name}; Cold Email Blocked under §7 UWG)'
        else:
            readiness_verdict = 'LinkedIn / Warm-Intro Only (Cold Email Restricted under §7 UWG)'
    elif dm_name and is_same_person_li and dm_is_direct_mkt_buyer:
        if all_signals:
            readiness_verdict = f'Sales-Ready via LinkedIn Outbound ({dm_name}, {dm_role} Verified + Tech Stack Confirmed)'
        else:
            readiness_verdict = f'Contact-Ready via LinkedIn Outbound ({dm_name} Profile Verified; Tech Stack Unverified — Check Manually)'
    elif dm_name and is_same_person_email and dm_is_direct_mkt_buyer:
        readiness_verdict = f'Sales-Ready Tier 1 (Verified Marketing Buyer: {dm_name}, {dm_role} + Matching Direct Email)'
    elif dm_name and not dm_is_direct_mkt_buyer:
        if is_same_person_email or is_same_person_li:
            readiness_verdict = f'Escalation-Ready via CEO ({dm_name} Verified — Request Intro to CMO / Head of Digital)'
        elif is_mp_founder_with_vendor_b2b:
            readiness_verdict = (
                f'Escalation-Needed (Marketplace Founder {dm_name} + Commercial B2B Desk — Locate CMO/Head of Digital)'
            )
        else:
            readiness_verdict = f'Escalation-Needed ({dm_name}, {dm_role} Listed — Locate CMO / Head of Digital via LinkedIn)'
    elif best_email_type == 'marketing_or_exec_role' and all_signals and scan_comp != 'partial_csp_headers':
        readiness_verdict = 'Research Priority + Marketing Role Inbox (Locate Named CMO / Head of Digital on LinkedIn)'
    elif not all_signals or scan_comp == 'partial_csp_headers':
        if best_email_type in ('b2b_partnerships', 'marketing_or_exec_role'):
            dm_part = f' + {dm_name}' if dm_name else ''
            readiness_verdict = f'Partnership-Ready{dm_part} (B2B/Marketing Channel Found; Tech Stack Unverified — Check Manually)'
        elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox', 'personal_or_named_inbox') or dm_name:
            dm_part = f' + {dm_name} Known' if dm_name else ''
            readiness_verdict = f'Gatekeeper-Ready{dm_part} (Contact Found; Tracking Gated by Consent or Unverified — Verify Manually)'
        else:
            readiness_verdict = 'Unverified (Support/Non-Sales Contact Only & No Verified Tech Signals)'
    elif best_email_type == 'b2b_partnerships':
        readiness_verdict = 'Partnership-Ready Only (B2B Inbox Found — Needs CMO Referral for Analytics/Tech Pitch)'
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox'):
        readiness_verdict = 'Gatekeeper-Ready Only (Office/Brand Inbox — Locate DM on LinkedIn Before Cold Outbound)'
    else:
        readiness_verdict = 'Tech-Qualified Account Only (Needs LinkedIn Marketing Buyer Enrichment Before Outbound)'

    if is_agency:
        opportunity = (
            'Agency/Media Segment: Explore white-label analytics partnership, '
            'data enrichment API integration, or B2B referral collaboration'
        )
    elif company_category == 'Non-Profit / Education / Institution':
        opportunity = 'Non-commercial / Institutional organization — disqualify from standard B2B sales'
    elif scan_comp == 'partial_csp_headers':
        opportunity = 'Partial scan (CSP headers only) — run full browser audit or verify tracking setup before technical pitch'
    elif len(ad_tags) >= 2:
        opportunity = (
            f"Hypothesis for discovery audit: multi-channel ad tracking tags ({', '.join(ad_tags)}) configured; "
            "offer complimentary tracking/attribution review or CRO benchmark to verify if optimization is needed"
        )
    elif len(ad_tags) == 1:
        opportunity = (
            f"Hypothesis for discovery audit: single ad network tag ({ad_tags[0]}) visible; "
            "verify paid channel mix and explore cross-channel acquisition or tracking review"
        )
    else:
        opportunity = 'Verify manually if tags are gated by Cookie Consent before proposing GA4/GTM implementation'

    phone_note = f' or call {primary_phone}' if primary_phone else ' (no public phone listed)'
    has_real_signals = bool(all_signals) and scan_comp != 'partial_csp_headers'
    stack_ref_clause = (
        f' referencing detected stack ({detected_signals_str})'
        if has_real_signals
        else ' to initiate B2B discovery (verify tracking stack manually first)'
    )
    pred_email_clause = f'; test predicted DM email {predicted_dm_email} via verifier' if predicted_dm_email else ''

    has_company_li_people = bool(
        company_linkedin_people_url
        or (linkedin_url and 'linkedin.com/company/' in linkedin_url.lower())
    )
    li_nav_hint = (
        'company_linkedin_people_url or decision_maker_search_query'
        if has_company_li_people
        else 'decision_maker_search_query'
    )

    if company_category == 'Non-Profit / Education / Institution':
        next_action = 'Exclude from commercial B2B cold outreach'
    elif is_agency:
        next_action = f"Route to Agency Partnership pipeline; reach out via {best_email or linkedin_url or 'LinkedIn'}{pred_email_clause}{phone_note}"
    elif not all_signals and not best_email and not primary_phone:
        if pw_blocked_by_waf:
            next_action = (
                f'Retry with residential proxy — Playwright blocked by WAF ({pw_status_str}); '
                f'do NOT skip this lead (use {li_nav_hint} on LinkedIn meanwhile)'
            )
        else:
            next_action = 'Review website manually or run with browser rescue (no tech signals or contacts detected)'
    elif dm_name and is_same_person_li:
        if dm_is_direct_mkt_buyer:
            next_action = (
                f"Send personalized LinkedIn message to {dm_name} ({dm_role}) at {dm_linkedin_url}"
                f"{stack_ref_clause}{pred_email_clause}"
            )
        else:
            next_action = (
                f"Use {li_nav_hint} to locate operational CMO / Head of Digital first, or message {dm_name} ({dm_role}) "
                f"at {dm_linkedin_url} requesting an internal intro to the marketing lead (escalation_needed_via_ceo)"
            )
    elif dm_name and is_same_person_email:
        if dm_is_direct_mkt_buyer:
            next_action = (
                f"Send personalized MarTech audit email to {dm_name} ({dm_role}) at {best_email}"
                f"{stack_ref_clause}"
            )
        else:
            next_action = (
                f"Locate operational CMO / Head of E-commerce via {li_nav_hint} first; "
                f"alternatively send a brief referral note to {dm_name} ({dm_role}) at {best_email} "
                f"asking who owns analytics/tracking (escalation_needed_via_ceo)"
            )
    elif dm_name and is_mp_founder_with_vendor_b2b:
        next_action = (
            f"Locate operational CMO / Head of Digital via {li_nav_hint} before pitching analytics "
            f"(listed DM {dm_name} is {dm_role}, and {best_email} is a commercial/vendor B2B desk; escalation_needed_via_ceo){phone_note}"
        )
    elif dm_name and best_email_type in ('b2b_partnerships', 'wholesale_or_sales_inbox'):
        next_action = (
            f"Open {li_nav_hint} to locate CMO/Head of Digital{pred_email_clause}, "
            f"or request warm referral via {best_email} (listed executive: {dm_name})"
        )
    elif best_email_type in (
        'customer_support_inbox', 'pr_and_media_inbox', 'wholesale_or_sales_inbox',
        'regional_branch_inbox', 'admissions_or_department_inbox', 'legal_or_hr_inbox',
        'department_or_general_inbox', 'influencer_gifting_inbox'
    ):
        dm_hint = f" ({dm_name})" if dm_name else ""
        if predicted_dm_email and dm_name:
            next_action = (
                f"DO NOT send cold marketing pitch to {best_email} ({best_email_type}); "
                f"locate CMO/Head of Digital via {li_nav_hint} or test predicted DM email {predicted_dm_email} via verifier{phone_note}"
            )
        else:
            next_action = (
                f"DO NOT send cold marketing pitch to {best_email} ({best_email_type}); "
                f"locate Marketing Lead / DM{dm_hint} via {li_nav_hint}{phone_note}"
            )
    elif best_email_type == 'b2b_partnerships':
        next_action = (
            f"Send partnership/referral inquiry to {best_email} asking for introduction to Head of Marketing/Analytics; "
            f"use {li_nav_hint} to find CMO/Head of Marketing first{phone_note}"
        )
    elif best_email_type == 'marketing_or_exec_role':
        next_action = (
            f"Send tailored discovery audit offer to {best_email} ({best_email_type})"
            f"{stack_ref_clause}{pred_email_clause}"
        )
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox'):
        dm_hint = f" ({dm_name})" if dm_name else ""
        next_action = (
            f"Locate CMO / Head of E-commerce{dm_hint} via {li_nav_hint}{pred_email_clause} first; "
            f"use {best_email} only for warm gatekeeper routing / referral request"
        )
    elif primary_phone:
        next_action = f"Use {li_nav_hint}{pred_email_clause} or call {primary_phone} for routing"
    else:
        next_action = (
            f"Run {li_nav_hint} in LinkedIn / Apollo{pred_email_clause} to locate marketing decision-maker{phone_note}"
        )

    # Фінальний програмний пост-фільтр комплаєнсу: унеможливлює пропозицію email при блоці §7 UWG / Impressum
    if company_category != 'Non-Profit / Education / Institution':
        next_action = enforce_outreach_compliance_guardrail(
            next_action,
            compliance_block_code,
            dm_name=dm_name,
            dm_role=dm_role,
            dm_buyer_fit_status=buyer_fit,
            has_company_li_people=has_company_li_people,
        )

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


def build_manual_seed_record(
    seed: dict,
    domain_key: str,
    canonical_domain: str,
    aliases_str: str,
    clean_website_url: str,
    normalized_final_redirect: str,
    was_redirected: bool,
    redirect_chain_str: str | None,
    is_eu_gdpr: bool,
    fail_status: str,
    short_err_msg: str,
    checked_at: str,
    playwright_available: bool = True
) -> dict:
    from .domain_helpers import (
        build_compliance_note,
        derive_data_source_sensitivity,
        derive_gdpr_jurisdiction,
        derive_human_contact_tier,
        derive_legal_basis_for_processing,
        derive_pii_fields,
        derive_sales_actionability_class,
        detect_country_hint,
    )

    verified_at = seed.get('verified_at', checked_at)
    age_days = compute_snapshot_age_days(verified_at) or 0
    cat = seed.get('company_category', 'E-commerce / Retail Brand')
    cat_conf = seed.get('category_confidence', 'high')
    best_email = seed.get('best_email')
    brand_token = canonical_domain.split('.')[0].lower()
    best_email_type = seed.get('best_email_type') or classify_email_type(best_email, brand_token)
    primary_phone = seed.get('primary_phone')
    dm_name = seed.get('decision_maker_name')
    raw_role = seed.get('decision_maker_role')
    dm_role = ROLE_NORMALIZATION_MAP.get((raw_role or '').lower(), raw_role)
    dm_src = seed.get('decision_maker_source_url')
    dm_src_type = seed.get('decision_maker_source_type') or classify_dm_source_type(dm_src)
    dm_buyer_fit = classify_dm_buyer_fit(dm_name, dm_role)
    li_url = seed.get('linkedin_url')
    is_mp = bool(seed.get('marketplace_platform', canonical_domain in KNOWN_MARKETPLACE_DOMAINS))

    seed_tech_list = [x.strip() for x in (seed.get('detected_technologies') or '').split(';') if x.strip()]
    seed_tech_set = set(seed_tech_list)

    tech_info = {
        'has_meta_pixel': ('Meta Pixel' in seed_tech_set) or bool(seed.get('has_meta_pixel', True)),
        'has_tiktok_pixel': ('TikTok Pixel' in seed_tech_set) or bool(seed.get('has_tiktok_pixel', False)),
        'has_google_ads': ('Google Ads Conversion' in seed_tech_set) or bool(seed.get('has_google_ads', True)),
        'has_linkedin_pixel': ('LinkedIn Insight Tag' in seed_tech_set) or bool(seed.get('has_linkedin_pixel', False)),
        'has_pinterest_tag': ('Pinterest Tag' in seed_tech_set) or bool(seed.get('has_pinterest_tag', False)),
        'has_hubspot': ('HubSpot' in seed_tech_set) or bool(seed.get('has_hubspot', False)),
        'has_klaviyo': ('Klaviyo' in seed_tech_set) or bool(seed.get('has_klaviyo', False)),
        'has_ga4': ('Google Analytics (GA4)' in seed_tech_set) or bool(seed.get('has_ga4', True)),
        'has_gtm': ('Google Tag Manager' in seed_tech_set) or bool(seed.get('has_gtm', True)),
        'has_sgtm': ('Server-Side GTM (sGTM)' in seed_tech_set) or bool(seed.get('has_sgtm', False)),
        'all_ga4_ids': seed.get('all_ga4_ids'),
        'all_ga4_ids_count': 1 if seed.get('all_ga4_ids') else 0,
        'ga4_detection_confidence': seed.get('ga4_detection_confidence', 'Verified (Manual Audit Seed)'),
        'detected_cms_list': [x.strip() for x in (seed.get('detected_cms') or '').split(';') if x.strip()],
        'detected_cms': seed.get('detected_cms'),
        'has_cookie_banner': bool(seed.get('consent_mode_likely', False)),
        'xhr_fetch_traffic_analyzed': False,
        'xhr_fetch_requests_inspected': 0,
        'xhr_first_party_collect_endpoints': [],
        'server_side_tracking_assessment': 'not_detected_in_static_html',
        'detected_technologies_list': seed_tech_list,
        'confirmed_martech_platforms': seed_tech_list,
        'technology_evidence': seed.get('technology_evidence', 'Verified via manual_seed'),
        'technology_evidence_summary': seed.get('technology_evidence_summary', 'GTM, GA4, Meta Pixel (Manual Seed)'),
        'technology_evidence_json': build_evidence_json_from_cached_record(seed, source_label='manual_seed'),
        'tech_scan_completeness': 'full'
    }

    c_hint = detect_country_hint(canonical_domain, '', '', primary_phone, '')
    jur_str = derive_gdpr_jurisdiction(canonical_domain, primary_phone, c_hint, '')
    data_sens = derive_data_source_sensitivity(dm_src_type, seed.get('email_source_type', 'contact_page'), jur_str)
    comp_blk, comp_code = is_cold_email_compliance_blocked(jur_str, data_sens, canonical_domain, c_hint, False)

    company_li_people_url = (
        f"{li_url.rstrip('/')}/people/?keywords=marketing"
        if (li_url and 'linkedin.com/company/' in li_url.lower())
        else f"https://www.linkedin.com/search/results/people/?keywords={quote(brand_token + ' marketing')}"
    )

    (
        sales_readiness_verdict,
        icp_fit_tier,
        technical_signal_strength,
        contact_quality_tier,
        enrichment_status,
        _,
        detected_signals,
        sales_opportunity,
        next_best_action
    ) = evaluate_qualification_v180(
        cat,
        tech_info,
        best_email,
        best_email_type,
        primary_phone,
        dm_name,
        dm_role,
        seed.get('decision_maker_linkedin_url'),
        False,
        dm_src_type,
        li_url,
        False,
        'not_attempted_manual_seed',
        is_mp_platform=is_mp,
        gdpr_jurisdiction=jur_str,
        data_source_sensitivity=data_sens,
        has_confirmed_legitimate_interest=False,
        dm_buyer_fit_status=dm_buyer_fit,
        company_linkedin_people_url=company_li_people_url,
        canonical_domain=canonical_domain,
        country_hint=c_hint,
    )

    sales_hook = build_sales_hook(
        canonical_domain,
        cat,
        tech_info,
        dm_name,
        dm_role,
        seed.get('decision_maker_linkedin_url'),
        best_email,
        is_eu_gdpr=is_eu_gdpr,
        pw_used=False,
        best_email_type=best_email_type,
        is_marketplace=is_mp,
        dm_buyer_fit_status=dm_buyer_fit,
    )

    deliv_str = seed.get(
        'email_deliverability_check',
        'domain_mail_configured (Google Workspace; MX_found; SPF_present; verified_manual_seed)'
    )
    raw_all_emails = seed.get('all_emails') or best_email or ''
    seed_emails_list = [e.strip() for e in raw_all_emails.split(';') if e.strip()]
    all_emails_class_str = (
        '; '.join(f'{em} ({classify_email_type(em, brand_token)})' for em in seed_emails_list)
        if seed_emails_list else None
    )
    all_emails_deliv_str = (
        '; '.join(f'{em}: {deliv_str}' for em in seed_emails_list[:3])
        if seed_emails_list else None
    )

    dms_found_str = seed.get('decision_makers_found') or (
        f'{dm_name} ({dm_role}) [{dm_src}]' if dm_name else None
    )
    dms_json_str = build_decision_makers_json_from_summary(dms_found_str, seed.get('decision_maker_linkedin_url'), dm_src)

    em_conf = 'OBSERVED_ON_SITE' if best_email else 'NONE'
    dq_score = compute_data_quality_score(
        contact_quality_tier,
        len(seed_tech_list),
        dm_name,
        seed.get('decision_maker_linkedin_url'),
        primary_phone,
        'full',
        True,
        company_category=cat,
        is_manual_seed=True,
        is_same_person_email=verify_person_email_match(dm_name, best_email),
        pw_status_str='not_attempted_manual_seed',
        tls_trust_status='not_checked',
        best_email_confidence=em_conf,
        email_deliverability_check=deliv_str,
    )

    scale_tier_info = classify_account_scale_tier(1, 0, None, None, None, is_marketplace=is_mp)
    stack_tier_info = classify_martech_stack_tier(seed_tech_set)
    contact_lvl = derive_contactability_level(
        best_email,
        best_email_type,
        dm_name,
        seed.get('decision_maker_linkedin_url'),
        primary_phone,
        em_conf,
    )
    acc_pot = compute_account_potential_score(
        cat, scale_tier_info['account_scale_tier'], stack_tier_info['martech_stack_tier'], 1, None, None
    )
    ev_conf = compute_evidence_confidence_score(
        'full', len(seed_tech_list), len(seed_tech_list), False,
        'not_attempted_manual_seed', 'not_checked', em_conf, None, is_cached_or_seed=True
    )
    tech_opp = compute_technical_opportunity_score(cat, tech_info, None, None, None, 0, False)
    sales_act = compute_sales_actionability_score(
        contact_lvl, dm_buyer_fit, em_conf, bool(company_li_people_url), comp_blk, cat
    )
    sales_readiness = compute_sales_readiness_score(
        cat, dm_buyer_fit, contact_lvl, ev_conf, tech_opp, em_conf, comp_blk, bool(company_li_people_url), 0
    )
    readiness_status = derive_sales_readiness_status(
        cat, acc_pot, ev_conf, sales_readiness, dm_buyer_fit, comp_blk
    )
    actionable_score = compute_actionable_priority_score(acc_pot, ev_conf, sales_readiness, cat)

    tz_info = resolve_prospect_timezone_and_locale_v23(
        canonical_domain,
        primary_phone,
        c_hint,
        '',
        page_title=seed.get('page_title') or '',
        gdpr_jurisdiction=jur_str,
        is_eu_gdpr=is_eu_gdpr,
    )

    return {
        'input_domain': domain_key,
        'canonical_domain': canonical_domain,
        'aliases': aliases_str,
        'input_was_redirected': was_redirected,
        'redirect_chain': redirect_chain_str,
        'website_url': clean_website_url,
        'final_redirect_url': normalized_final_redirect,
        'status': f'seeded_from_manual_audit (live_{fail_status})',
        'cached_snapshot_source': 'manual_seed',
        'cached_snapshot_age_days': age_days,
        'error_message': truncate_error_msg(f'Live {short_err_msg}; served verified manual_seed from {verified_at}'),
        'sales_readiness_status': readiness_status,
        'account_potential_score': acc_pot,
        'evidence_confidence_score': ev_conf,
        'sales_readiness_score': sales_readiness,
        'data_quality_score': dq_score,
        'account_fit_score': acc_pot,
        'technical_opportunity_score': tech_opp,
        'sales_actionability_score': sales_act,
        'actionable_priority_score': actionable_score,
        'contactability_level': contact_lvl,
        'dm_buyer_fit_status': dm_buyer_fit,
        'outreach_compliance_block': comp_code,
        'sales_readiness_verdict': sales_readiness_verdict,
        'sales_actionability_class': derive_sales_actionability_class(sales_readiness_verdict, cat),
        'company_category': cat,
        'category_confidence': cat_conf,
        'marketplace_platform': is_mp,
        'marketplace_platform_pollution_detected': False,
        'icp_fit_tier': icp_fit_tier,
        'technical_signal_strength': technical_signal_strength,
        'tech_scan_completeness': 'full',
        'tech_rescan_needed': False,
        'contact_quality_tier': contact_quality_tier,
        'contact_quality_tier_human': derive_human_contact_tier(contact_quality_tier, cat),
        'contact_enrichment_status': enrichment_status,
        'data_confidence_warning': (
            f'Note: Live crawl encountered {short_err_msg}; returning verified manual_seed '
            f'(age={age_days}d, verified_at={verified_at}).'
        ),
        'gdpr_eu_domain': is_eu_gdpr,
        'gdpr_jurisdiction': jur_str,
        'legal_basis_for_processing': derive_legal_basis_for_processing(
            canonical_domain, c_hint, bool(best_email or dm_name or primary_phone), gdpr_jurisdiction=jur_str
        ),
        'data_source_sensitivity': data_sens,
        'data_subject_can_request_deletion': True,
        'data_retention_policy_days': 365,
        'personal_data_fields_in_record': derive_pii_fields(best_email, best_email_type, dm_name, primary_phone, seed.get('decision_maker_linkedin_url')),
        'compliance_note': build_compliance_note(canonical_domain, c_hint, gdpr_jurisdiction=jur_str),
        'playwright_available': playwright_available,
        'playwright_used': False,
        'playwright_status': 'not_attempted_manual_seed',
        'playwright_attempts_count': 0,
        'playwright_paths_attempted': None,
        'page_title': seed.get('page_title'),
        'meta_description': seed.get('meta_description'),
        'best_email': best_email,
        'email_domain': f'{canonical_domain} (matches_site)' if best_email else None,
        'best_email_type': best_email_type,
        'best_email_confidence': em_conf,
        'dm_predicted_email': None,
        'dm_predicted_email_status': 'not_generated',
        'email_source_type': seed.get('email_source_type', 'contact_page'),
        'email_source_note': seed.get('email_source_note', 'Verified via manual audit seed'),
        'named_email_owner_role_hint': None,
        'email_deliverability_check': deliv_str,
        'email_verification_confidence': em_conf,
        'all_emails_deliverability': all_emails_deliv_str,
        'all_emails_classification': all_emails_class_str,
        'email_source_url': seed.get('email_source_url', clean_website_url),
        'compliance_dpo_email': None,
        'primary_phone': primary_phone,
        'e164_phone': seed.get('e164_phone') or (re.sub(r'[\s\-()]', '', primary_phone) if primary_phone else None),
        'whatsapp_business_phone': None,
        'phone_availability': 'public' if primary_phone else 'not_public',
        'phone_source_url': seed.get('phone_source_url', clean_website_url),
        'decision_maker_name': dm_name,
        'dm_first_name': split_clean_executive_name(dm_name or '')['dm_first_name'] or None,
        'dm_last_name': split_clean_executive_name(dm_name or '')['dm_last_name'] or None,
        'decision_maker_role': dm_role,
        'decision_maker_scope': 'target_entity' if dm_name else 'none',
        'decision_maker_source_url': dm_src,
        'decision_maker_source_type': dm_src_type,
        'decision_makers_found': dms_found_str,
        'decision_makers_json': dms_json_str,
        'decision_maker_linkedin_url': seed.get('decision_maker_linkedin_url'),
        'company_linkedin_people_url': company_li_people_url,
        'decision_maker_search_query': build_linkedin_xray_query(canonical_domain, cat),
        'linkedin_url': li_url,
        'instagram_url': seed.get('instagram_url'),
        'facebook_url': seed.get('facebook_url'),
        'telegram_url': seed.get('telegram_url'),
        'tiktok_url': seed.get('tiktok_url'),
        'youtube_url': seed.get('youtube_url'),
        'social_source_url': seed.get('social_source_url', clean_website_url),
        'detected_signals': detected_signals,
        'detected_cms': seed.get('detected_cms'),
        'consent_mode_likely': bool(seed.get('consent_mode_likely', False)),
        'ga4_detection_confidence': tech_info['ga4_detection_confidence'],
        'has_google_ads_confidence': 'verified_present' if tech_info['has_google_ads'] else 'verified_absent',
        'sales_hook': sales_hook,
        'sales_opportunity': sales_opportunity,
        'next_best_action': next_best_action,
        'primary_sales_gap': None,
        'sales_gap_confidence': None,
        'technology_evidence_summary': tech_info['technology_evidence_summary'],
        'technology_evidence': tech_info['technology_evidence'],
        'technology_evidence_json': tech_info['technology_evidence_json'],
        'has_meta_pixel': tech_info['has_meta_pixel'],
        'has_tiktok_pixel': tech_info['has_tiktok_pixel'],
        'has_google_ads': tech_info['has_google_ads'],
        'has_linkedin_pixel': tech_info['has_linkedin_pixel'],
        'has_pinterest_tag': tech_info['has_pinterest_tag'],
        'has_hubspot': tech_info['has_hubspot'],
        'has_klaviyo': tech_info['has_klaviyo'],
        'has_ga4': tech_info['has_ga4'],
        'has_gtm': tech_info['has_gtm'],
        'has_sgtm': tech_info['has_sgtm'],
        'all_ga4_ids': tech_info['all_ga4_ids'],
        'all_ga4_ids_count': 1 if tech_info['all_ga4_ids'] else None,
        'detected_technologies': seed.get('detected_technologies'),
        'confirmed_martech_platforms': seed_tech_list,
        'detected_payment_gateways': [],
        'xhr_fetch_traffic_analyzed': False,
        'xhr_fetch_requests_inspected': 0,
        'xhr_first_party_collect_endpoints': [],
        'server_side_tracking_assessment': 'not_detected_in_static_html',
        'account_scale_tier': scale_tier_info['account_scale_tier'],
        'account_scale_basis': scale_tier_info['account_scale_basis'],
        'martech_stack_tier': stack_tier_info['martech_stack_tier'],
        'martech_stack_tier_basis': stack_tier_info['martech_stack_tier_basis'],
        'buying_intent_signals': [],
        'estimated_markets_count': 1,
        'detected_market_locales': [],
        'catalog_estimated_skus': None,
        'ecom_avg_price': None,
        'ecom_currency': None,
        'logistics_and_returns_stack': [],
        'ads_rpc_status': 'not_checked',
        'ads_active_last_30d': None,
        'active_ad_formats': [],
        'advertiser_sister_domains': [],
        'detected_marketing_agency': None,
        'open_positions_total': None,
        'hiring_departments': [],
        'hiring_marketing_or_data_roles': None,
        'dmarc_policy': None,
        'email_security_gateway': None,
        'plain_text_outreach_required': False,
        'tls_trust_status': 'not_checked',
        'prospect_iana_timezone': tz_info['prospect_iana_timezone'],
        'recommended_outreach_lang': tz_info['recommended_outreach_lang'],
        'corporate_lifecycle_status': 'ACTIVE_INDEPENDENT',
        'outreach_dedup_status': 'PRIMARY_OUTREACH_TARGET',
        'recent_change_triggers': [],
        'compliance_ids': {},
        'provenance_meta': {},
        'all_emails': seed.get('all_emails', best_email),
        'all_phones': seed.get('all_phones', primary_phone),
        'last_checked_at': verified_at
    }
