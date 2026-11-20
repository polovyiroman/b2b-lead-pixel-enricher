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
    build_company_linkedin_people_url,
    build_decision_makers_json_from_summary,
    build_marketing_department_escalation_note,
    classify_dm_buyer_fit,
    classify_dm_source_type,
    classify_email_type,
    is_ceo_or_founder_role,
    is_marketing_or_digital_role,
    is_server_verified_email_confidence,
    split_clean_executive_name,
    verify_person_email_match,
    verify_person_linkedin_match,
)
from .domain_helpers import (
    KNOWN_DTC_ECOM_DOMAINS,
    classify_company_category,
    is_scan_failed_completeness,
)
from .tech_detector import build_evidence_json_from_cached_record

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

# v24.5: Багатосигнальний розподіл MarTech (1 тег на кшталт Segment чи Datadog НЕ дає Enterprise — фікс Notion)
CORE_ENTERPRISE_PLATFORMS: Set[str] = {
    "Adobe Analytics", "Salesforce", "Salesforce Marketing Cloud", "Tealium",
    "Shopify Plus", "Dynamic Yield", "Optimizely", "Braze",
    "Akeneo PIM", "Pimcore", "Salsify PIM", "Oracle NetSuite", "Global-e",
}

ENTERPRISE_STACK_TOOLS: Set[str] = CORE_ENTERPRISE_PLATFORMS | {
    "Segment", "Snowplow", "Algolia", "Datadog", "Server-Side GTM (sGTM)",
}

MID_MARKET_STACK_TOOLS: Set[str] = {
    "HubSpot", "Klaviyo", "Amplitude", "Mixpanel", "Zendesk", "Gorgias", "VWO",
    "Personio", "Greenhouse", "Lever", "SmartRecruiters", "Loop Returns", "Sendcloud",
    "Contentful", "Storyblok", "Shopware", "Magento", "Intercom", "Criteo",
}


# ==============================================================================
# v24.5 Enterprise MarTech & Account Intelligence: VIES, RDAP, Scale vs Stack
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
    wikidata_employees: Optional[int] = None,
    tls_corporate_sans_count: int = 0,
    localized_domains_count: int = 0,
    has_enterprise_brand_registrar: bool = False,
    scan_completeness: str = 'full',
) -> Dict[str, Any]:
    """
    v24.5 Доказова класифікація масштабу бізнесу (фікс Adidas):
      - Використовує Wikidata headcount, enterprise-реєстратори брендів (MarkMonitor/CSC),
        локалізовані домени/TLS SANs, каталог SKU та найм.
      - Якщо скан частковий і жодних доказів масштабу не зібрано, повертає `'Unverified Scale'`
        замість хибного `'SMB / Local Scale'`.
    """
    basis: List[str] = []
    if is_marketplace:
        basis.append("Multi-brand marketplace / large platform")
    if wikidata_employees is not None and int(wikidata_employees) >= 500:
        basis.append(f"Enterprise headcount (~{int(wikidata_employees):,} employees)")
    elif wikidata_employees is not None and int(wikidata_employees) >= 50:
        basis.append(f"Mid-Market headcount (~{int(wikidata_employees):,} employees)")
    if has_enterprise_brand_registrar:
        basis.append("Enterprise brand-protection registrar (MarkMonitor/CSC)")
    if localized_domains_count >= 1:
        basis.append(f"{localized_domains_count} localized brand domains")
    if estimated_markets_count >= 5:
        basis.append(f"{estimated_markets_count} regional markets")
    elif estimated_markets_count >= 2:
        basis.append(f"{estimated_markets_count} markets")
    if tls_corporate_sans_count >= 4:
        basis.append(f"{tls_corporate_sans_count} corporate TLS SAN domains")
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
        or (wikidata_employees is not None and int(wikidata_employees) >= 500)
        or has_enterprise_brand_registrar
        or estimated_markets_count >= 5
        or localized_domains_count >= 4
        or tls_corporate_sans_count >= 4
        or (catalog_estimated_skus is not None and catalog_estimated_skus >= 5000)
        or (open_positions_total is not None and int(open_positions_total) >= 25)
    ):
        tier = "Enterprise Scale"
    elif (
        (wikidata_employees is not None and int(wikidata_employees) >= 50)
        or estimated_markets_count >= 2
        or localized_domains_count >= 1
        or (catalog_estimated_skus is not None and catalog_estimated_skus >= 500)
        or (open_positions_total is not None and int(open_positions_total) >= 3)
        or ads_active_last_30d is True
    ):
        tier = "Mid-Market Scale"
    elif scan_completeness != 'full' and not basis:
        tier = "Unverified Scale"
        basis.append("Insufficient verified scale signals due to partial scan")
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
    v24.5 Багатосигнальна оцінка MarTech-стеку (фікс Notion):
      - `Enterprise` потребує або >=2 enterprise-інструментів, або 1 ключової enterprise-платформи
        (`Adobe Analytics`, `Salesforce`, `Shopify Plus`, `Tealium`, `Braze`, `Optimizely` тощо)
        у поєднанні з глибиною підтвердженого стеку (>=3 інструменти або Mid-Market стек).
      - Одиночний тег на кшталт `Segment` або `Datadog` без супровідного стеку дає `Mid-Market`,
        а не `Enterprise`.
      - `allowlisted_in_csp` повністю ігнорується.
    """
    tiers_map = tech_verification_tiers or {}
    confirmed = sorted(
        t for t in (detected_tech_set or set())
        if tiers_map.get(t) != "allowlisted_in_csp"
    )
    confirmed_set = set(confirmed)

    ent_hits = sorted(confirmed_set & ENTERPRISE_STACK_TOOLS)
    core_ent_hits = sorted(confirmed_set & CORE_ENTERPRISE_PLATFORMS)
    mid_hits = sorted(confirmed_set & MID_MARKET_STACK_TOOLS)
    basis: List[str] = []

    if ent_hits:
        basis.append(f"Enterprise MarTech: {', '.join(ent_hits[:5])}")
    if mid_hits:
        basis.append(f"Mid-Market MarTech: {', '.join(mid_hits[:5])}")

    if len(ent_hits) >= 2 or (len(core_ent_hits) >= 1 and (len(mid_hits) >= 1 or len(confirmed_set) >= 3)):
        tier = "Enterprise"
    elif (
        len(ent_hits) == 1
        or len(mid_hits) >= 1
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
    signals: List[str] = []
    if hiring_marketing_or_data_roles is True:
        signals.append("HIRING_MARKETING_OR_DATA_ROLES")
    if open_positions_total is not None and int(open_positions_total) >= 5:
        signals.append(f"ACTIVE_HIRING ({int(open_positions_total)} open roles)")
    if ads_active_last_30d is True:
        fmts = ", ".join((active_ad_formats or [])[:3]) or "Search"
        signals.append(f"ACTIVE_GOOGLE_ADS_30D ({fmts})")
    if primary_sales_gap and sales_gap_confidence in ("issue_confirmed", "RUNTIME_NETWORK_VERIFIED"):
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
# v24.5: Програмний комплаєнс-гардрейл та 3 Незалежні Осі (null на failed scan)
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
    company_linkedin_people_url: str | None = None,
) -> str:
    if not compliance_block_code or compliance_block_code == 'none':
        return next_best_action

    reason_lbl = (
        'EU/DE Impressum (§7 UWG & DSK)'
        if compliance_block_code == 'eu_impressum_cold_email_blocked'
        else 'DE/AT §7 UWG strict opt-in law'
    )
    if dm_name and dm_buyer_fit_status == 'direct_marketing_buyer':
        li_ref = company_linkedin_people_url or 'LinkedIn'
        return (
            f'COMPLIANCE BLOCK ({reason_lbl}): Unsolicited cold email is programmatically blocked. '
            f'Connect with {dm_name} ({dm_role}) via LinkedIn only ({li_ref}) or obtain prior written opt-in.'
        )

    esc_note = build_marketing_department_escalation_note(dm_name, dm_role, company_linkedin_people_url)
    return (
        f'COMPLIANCE BLOCK ({reason_lbl}): Unsolicited cold email is programmatically blocked. '
        f'{esc_note} (LinkedIn only — no cold email).'
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
    scan_completeness: str = 'full',
) -> Optional[int]:
    """
    Вісь 1 (v24.5) — Account Potential Score (0–100 або None при `partial_blocked`/`partial_timeout`/`http_404`).
    """
    if is_scan_failed_completeness(scan_completeness):
        return None
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

    scale_pts = {
        'Enterprise Scale': 20,
        'Mid-Market Scale': 14,
        'SMB / Local Scale': 8,
        'Unverified Scale': 4,
    }
    score += scale_pts.get(account_scale_tier or '', 4)

    stack_pts = {'Enterprise': 14, 'Mid-Market': 11, 'SMB': 6, 'Unverified / Minimal': 2}
    score += stack_pts.get(martech_stack_tier or '', 2)

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
    scan_completeness: str = 'full',
) -> Optional[int]:
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
        scan_completeness=scan_completeness,
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
    tech_verification_tiers: Optional[Dict[str, str]] = None,
) -> Optional[int]:
    """
    Вісь 2 (v24.5) — Evidence Confidence Score (0–100 або None при `partial_blocked`/`partial_timeout`/`http_404`):
    Оцінює рівень доведеності даних за жорсткою ієрархією:
      `RUNTIME_NETWORK_VERIFIED` > `CONFIGURED_IN_GTM` > `DETECTED_IN_HTML` > `allowlisted_in_csp`.
    """
    if is_scan_failed_completeness(scan_completeness):
        return None

    tiers = tech_verification_tiers or {}
    rt_count = sum(1 for v in tiers.values() if v == 'RUNTIME_NETWORK_VERIFIED')
    gtm_count = sum(1 for v in tiers.values() if v == 'CONFIGURED_IN_GTM')

    score = 0
    if scan_completeness == 'full':
        score += 30
    elif scan_completeness in ('partial_gtm', 'partial_cached'):
        score += 16
    elif scan_completeness == 'partial_csp_headers':
        score += 6
    else:
        score += 4

    if rt_count >= 2:
        score += 22
    elif rt_count == 1:
        score += 16
    elif gtm_count >= 1:
        score += 12
    elif confirmed_martech_count >= 2:
        score += 10
    elif confirmed_martech_count == 1:
        score += 7
    elif techs_count >= 1:
        score += 3

    if xhr_fetch_traffic_analyzed:
        score += 14

    if best_email_confidence in ('M365_AD_VERIFIED', 'SMTP_API_VERIFIED'):
        score += 18
    elif best_email_confidence == 'OBSERVED_ON_SITE':
        score += 9
    elif best_email_confidence == 'GRAVATAR_OR_PGP_MATCH':
        score += 6

    if sales_gap_confidence in ('issue_confirmed', 'RUNTIME_NETWORK_VERIFIED'):
        score += 16
    elif sales_gap_confidence == 'issue_suspected':
        score += 7
    elif sales_gap_confidence == 'SERVER_SIDE_TRACKING_STATUS_UNKNOWN':
        score += 2

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
        score = min(score, 58)
    if pw_err or tls_err:
        score = min(score, 65)

    return max(0, min(100, score))


def compute_technical_opportunity_score(
    company_category: str,
    tech_info: dict,
    primary_sales_gap: Optional[str] = None,
    sales_gap_confidence: Optional[str] = None,
    ads_active_last_30d: Optional[bool] = None,
    red_flags_count: int = 0,
    xhr_fetch_traffic_analyzed: bool = False,
) -> Optional[int]:
    scan_comp = str(tech_info.get('tech_scan_completeness') or 'full')
    if is_scan_failed_completeness(scan_comp):
        return None
    if company_category == 'Non-Profit / Education / Institution':
        return 0
    if scan_comp == 'partial_csp_headers':
        return 12

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
        score += 20
    elif confirmed_ad_pixels == 1:
        score += 10
    if tech_info.get('has_ga4') or tech_info.get('has_gtm'):
        score += 8

    # Найвищі бали ЛИШЕ за мережево доведені технічні розриви (Moat агенції)
    if primary_sales_gap == 'DUPLICATE_GA4_TRACKING':
        score += 52 if sales_gap_confidence in ('issue_confirmed', 'RUNTIME_NETWORK_VERIFIED') else 30
    elif primary_sales_gap == 'GA4_CONSENT_GATED_OR_SILENT':
        score += 44
    elif primary_sales_gap == 'EU_CONSENT_MODE_V2_GAP':
        score += 46 if sales_gap_confidence in ('issue_confirmed', 'RUNTIME_NETWORK_VERIFIED') else 28
    elif primary_sales_gap in ('ADS_ACTIVE_NO_SERVER_SIDE_TRACKING', 'SERVER_SIDE_TRACKING_STATUS_UNKNOWN'):
        # Ніколи не завищуємо бал на гіпотезі про відсутність sGTM!
        score += 16 if (xhr_fetch_traffic_analyzed or tech_info.get('xhr_fetch_traffic_analyzed')) else 10
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
    scan_completeness: str = 'full',
) -> Optional[int]:
    if is_scan_failed_completeness(scan_completeness):
        return None
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
    evidence_confidence_score: Optional[int],
    technical_opportunity_score: Optional[int],
    best_email_confidence: str = 'NONE',
    compliance_blocked: bool = False,
    has_company_li_people: bool = False,
    buying_intent_count: int = 0,
    scan_completeness: str = 'full',
) -> Optional[int]:
    """
    Вісь 3 (v24.5) — Sales Readiness Score (0–100 або None при `partial_blocked`/`partial_timeout`/`http_404`):
    Жорстко враховує наявність операційного маркетолога (`direct_marketing_buyer`), доведену проблему,
    високу впевненість даних (`evidence_confidence_score`) та відсутність юридичного блоку.
    """
    if (
        is_scan_failed_completeness(scan_completeness)
        or evidence_confidence_score is None
        or technical_opportunity_score is None
    ):
        return None
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
    account_potential_score: Optional[int],
    evidence_confidence_score: Optional[int],
    sales_readiness_score: Optional[int],
    dm_buyer_fit_status: str,
    compliance_blocked: bool = False,
    scan_completeness: str = 'full',
) -> str:
    """
    v24.5 Суворий статус готовності:
      - `UNVERIFIED_SCAN_FAILED` — будь-який `partial_blocked`, `partial_timeout`, `partial_empty_render`, `http_404`
        або `None` у числових оцінках (запобігає потраплянню заблокованих сайтів у топ воронки).
      - `SALES_READY` — лише при `sales_readiness_score >= 70`, `evidence_confidence_score >= 55`,
        наявності операційного маркетолога (`direct_marketing_buyer`) та відсутності юридичного блоку.
      - `ESCALATION_NEEDED` — знайдено лише CEO / Founder / Owner (`escalation_needed_via_ceo`).
      - `RESEARCH_PRIORITY` — високий потенціал (`account_potential_score >= 55`), але потрібен пошук маркетолога.
    """
    if (
        is_scan_failed_completeness(scan_completeness)
        or account_potential_score is None
        or evidence_confidence_score is None
        or sales_readiness_score is None
    ):
        return 'UNVERIFIED_SCAN_FAILED'
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
    account_potential_score: Optional[int],
    evidence_confidence_score: Optional[int],
    sales_readiness_score: Optional[int],
    company_category: str = '',
    scan_completeness: str = 'full',
) -> Optional[int]:
    if (
        is_scan_failed_completeness(scan_completeness)
        or account_potential_score is None
        or evidence_confidence_score is None
        or sales_readiness_score is None
    ):
        return None
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
) -> Optional[int]:
    if is_scan_failed_completeness(scan_completeness):
        return None
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
    company_linkedin_people_url: str | None = None,
) -> Optional[str]:
    """
    v24.5 Evidence-Driven Sales Hook:
      - При `partial_blocked`/`partial_timeout`/`http_404` повертає `None` (жодних вигаданих хуків!).
      - Ніколи не звертається до CEO/Founder (John Collison / Kim Kardashian) як до покупця MarTech —
        чітко вказує на відділ маркетингу та `company_linkedin_people_url`.
      - Ніколи не звинувачує клієнта у відсутності sGTM (`SERVER_SIDE_TRACKING_STATUS_UNKNOWN`).
      - Підсвічує мережево доведені проблеми (`RUNTIME_NETWORK_VERIFIED` duplicate GA4 events / `CONSENT_GATED_OR_SILENT`).
    """
    scan_comp = str(tech_info.get('tech_scan_completeness') or 'full')
    if is_scan_failed_completeness(scan_comp):
        return None

    brand = canonical_domain.split('.')[0].capitalize() if canonical_domain else 'Company'
    if company_category == 'Non-Profit / Education / Institution':
        return f'{brand} is a non-profit/institutional entity — exclude from commercial outbound.'

    brand_token = canonical_domain.split('.')[0].lower() if canonical_domain else ''
    em_type = best_email_type or classify_email_type(best_email, brand_token)
    buyer_fit = dm_buyer_fit_status or classify_dm_buyer_fit(dm_name, dm_role)
    li_people = company_linkedin_people_url or build_company_linkedin_people_url(None, canonical_domain)

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
    dup_ga4_events = tech_info.get('duplicate_ga4_events') or []
    dup_runtime_confirmed = bool(tech_info.get('duplicate_ga4_runtime_confirmed'))
    tag_rt_status = str(tech_info.get('tag_runtime_status') or '')

    if buyer_fit == 'direct_marketing_buyer' and dm_name:
        dm_intro = f'{dm_name} ({dm_role})'
    else:
        dm_intro = f'Head of Marketing / Head of Digital (check marketing team: {li_people})'

    li_badge = ' [LinkedIn verified]' if (dm_linkedin_url and buyer_fit == 'direct_marketing_buyer') else ''
    stack_str = ', '.join(techs[:5]) if techs else ('Consent-gated / unverified stack' if has_consent else 'No public ad pixels detected')
    cms_str = f' on {cms}' if cms else ''

    if scan_comp == 'partial_csp_headers':
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"CSP Allowlist Only: {stack_str} (runtime firing unverified). "
            f"Discovery Note: \"Verify marketing team ownership via LinkedIn before pitching tracking optimization.\""
        )

    # 1. Найсильніший доказ: RUNTIME_NETWORK_VERIFIED подвійне спрацювання подій у GA4
    if dup_ga4_ids and dup_runtime_confirmed:
        dup_id = dup_ga4_ids[0]
        ev_str = f" ({', '.join(dup_ga4_events[:2])})" if dup_ga4_events else ""
        ads_clause = " while actively running Google Ads" if ads_active_last_30d else ""
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"PROVEN RUNTIME ISSUE [RUNTIME_NETWORK_VERIFIED]: Duplicate GA4 /g/collect hits for {dup_id}{ev_str}{ads_clause}. "
            f"Opening Hook: \"Our network audit observed duplicate GA4 /g/collect events for {dup_id}{ev_str} on {brand} — "
            f"happy to share the exact XHR trace so your team can verify conversions aren't double-counted.\""
        )

    if dup_ga4_ids:
        dup_id = dup_ga4_ids[0]
        gtm_ref = f"container {gtm_ids[0]} and " if gtm_ids else "GTM container and "
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Suspected Config Issue [CONFIGURED_IN_GTM + DETECTED_IN_HTML]: GA4 {dup_id} referenced in both {gtm_ref}HTML. "
            f"Opening Hook: \"Noticed {brand}'s {gtm_ref}page HTML both reference GA4 {dup_id} — "
            f"have you verified trigger deduplication in runtime network traffic?\""
        )

    if tag_rt_status == 'CONSENT_GATED_OR_SILENT':
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Runtime Observation [CONSENT_GATED_OR_SILENT]: GA4 is configured in code, but zero /g/collect hits fired during browser render. "
            f"Opening Hook: \"Noticed GA4 is present in {brand}'s markup but didn't fire /g/collect hits in our browser session — "
            f"is that intentional consent gating or a broken trigger worth auditing?\""
        )

    if ga4_count >= 5:
        prop_clause = f"across your {ga4_count} GA4 properties"
        gap_angle = (
            "EEA Consent Mode v2 (gcs/gcd) signaling"
            if (is_eu_gdpr and has_gads and not has_cm_v2)
            else "cross-property event governance and attribution consistency"
        )
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} ({ga4_count} GA4 properties detected). "
            f"Opening Hook: \"Saw {brand} manages multi-property tracking {prop_clause} — "
            f"how is your team currently standardizing {gap_angle}?\""
        )

    # Крок 1 P0: НІКОЛИ не стверджуємо про відсутність sGTM — використовуємо SERVER_SIDE_TRACKING_STATUS_UNKNOWN
    if ads_active_last_30d is True and not has_sgtm:
        formats_str = ', '.join(active_ad_formats) if active_ad_formats else 'Search & Display'
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} [Active Ads Verified: {formats_str}; SERVER_SIDE_TRACKING_STATUS_UNKNOWN]. "
            f"Opening Hook: \"Saw {brand} is actively running {formats_str} campaigns in Google Ads Transparency — "
            f"how is your team currently validating attribution and server-side conversion match quality (API / sGTM / Workers)?\""
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
            f"Opening Hook: \"Saw {brand} runs {paid_str} alongside server-side tracking — "
            f"how are you currently benchmarking CAPI event match quality and deduplication?\""
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
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} [SERVER_SIDE_TRACKING_STATUS_UNKNOWN]. "
            f"Opening Hook: \"Noticed {brand} has {paid_str} tracking active{cms_str} — "
            f"how is your marketing team currently auditing attribution accuracy and server-side conversion coverage?\""
        )

    if has_gtm or has_ga4:
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str}. "
            f"Opening Hook: \"Reaching out to {brand}'s digital analytics team — "
            f"how are you currently auditing GA4/GTM event quality and consent-mode attribution?\""
        )

    return (
        f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
        f"Stack: {stack_str}. "
        f"Opening Hook: \"Reaching out regarding {brand}'s digital analytics & attribution setup — "
        f"who currently oversees marketing measurement on your team?\""
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
    scan_comp = str(tech_info.get('tech_scan_completeness') or 'full')

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

    resolved_li_people = company_linkedin_people_url or build_company_linkedin_people_url(linkedin_url, canonical_domain)

    if company_category == 'E-commerce / Retail Brand':
        icp_fit_tier = 'Tier 1: Target ICP (E-commerce / Retail Brand)'
    elif company_category in ('SaaS / Marketplace / Tech Platform', 'General Business / Corporate'):
        icp_fit_tier = f'Tier 2: Secondary ICP ({company_category})'
    elif is_agency:
        icp_fit_tier = 'Partner / Competitor Segment (Agency / Media — Exclude from Standard Client Outreach)'
    else:
        icp_fit_tier = 'Non-Target ICP (Non-Profit / Education / Institution)'

    if is_scan_failed_completeness(scan_comp):
        tech_signal = f"Unverified — Scan Failed ({scan_comp}; Playwright: {pw_status_str})"
    elif scan_comp == 'partial_csp_headers':
        tech_signal = (
            f"Unverified Stack (CSP Allowlist Only — Browser Render Needed; "
            f"domains observed in security policy: {', '.join(all_signals[:5])})"
        )
    elif len(ad_tags) >= 2 and analytics_tags:
        tech_signal = (
            f"High Stack Maturity: Multi-pixel ad tracking ({', '.join(ad_tags)}) + {'/'.join(analytics_tags[:2])} "
            "(Verified in HTML/GTM/Runtime; confirms tracking infrastructure, not current ad spend)"
        )
    elif len(ad_tags) == 1:
        partial_note = (
            ' (Partial GTM macro unpack — secondary ad tags may be server-side or consent-gated)'
            if scan_comp == 'partial_gtm'
            else ' (Secondary tags not observed in static HTML/GTM or gated by Cookie Consent)'
        )
        tech_signal = f"Moderate Stack Maturity: Single ad pixel ({ad_tags[0]}) detected{partial_note}"
    elif analytics_tags:
        tech_signal = f"Basic Analytics Only ({', '.join(analytics_tags)}) — ad pixels not observed in static HTML/GTM"
    else:
        tech_signal = (
            'Low / Unverified Tech Signal: No tracking tags observed in HTML '
            '(Tag absence is not confirmed if site uses strict Cookie Consent or server-side routing)'
        )

    is_same_person_email = verify_person_email_match(dm_name, best_email)
    is_same_person_li = verify_person_linkedin_match(dm_name, dm_linkedin_url)
    dm_is_direct_mkt_buyer = (buyer_fit == 'direct_marketing_buyer')

    source_extra_note = ''
    if compliance_blocked:
        source_extra_note = (
            f' COMPLIANCE BLOCK ({compliance_block_code}): Unsolicited cold email is prohibited under §7 UWG / DSK — '
            f'use LinkedIn or warm intro only.'
        )
    elif dm_source_is_legal and dm_source_type not in ('impressum_page', 'impressum_page_cached'):
        source_extra_note = ' DM identified from legal/terms document — verify active operational role via LinkedIn before outbound.'

    if is_agency:
        if dm_name and best_email_type == 'personal_or_named_inbox' and not is_same_person_email:
            contact_quality = f'Agency Tier B+ (Named Staff Inbox {best_email} Found, Listed Executive is {dm_name})'
            enrichment_status = 'agency_partner_unmatched_executive_and_staff_email'
            confidence_warning = f'Note: Agency partnership contact — route to {best_email}, not to {dm_name}.{source_extra_note}'
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
    elif dm_name and is_same_person_li and dm_is_direct_mkt_buyer:
        contact_quality = f'Tier A- (Marketing Buyer {dm_name}, {dm_role} + LinkedIn Verified)'
        enrichment_status = 'decision_maker_linkedin_verified_paired_with_site_contact'
        confidence_warning = f'Note: Marketing buyer LinkedIn slug verified.{source_extra_note}'
    elif dm_name and not dm_is_direct_mkt_buyer:
        contact_quality = f'Tier B (Corporate Executive Only: {dm_name}, {dm_role} — Head of Marketing Not Found)'
        enrichment_status = 'escalation_needed_via_ceo'
        confidence_warning = (
            f'Note: {dm_name} ({dm_role}) is CEO/Founder/Owner level, not operational marketing buyer. '
            f'Check marketing department via LinkedIn: {resolved_li_people or "LinkedIn People tab"}.{source_extra_note}'
        )
    elif dm_name and best_email_type == 'marketing_or_exec_role':
        contact_quality = f'Tier A- (Marketing Buyer Found: {dm_name} + Marketing Role Inbox: {best_email})'
        enrichment_status = 'decision_maker_found_plus_marketing_role_inbox'
        confidence_warning = source_extra_note.strip() or 'None'
    elif best_email_type in ('personal_or_named_inbox', 'marketing_or_exec_role'):
        contact_quality = f'Tier B+ (Direct / Named Role Inbox: {best_email_type}, Full Name Unlisted)'
        enrichment_status = 'named_or_role_email_found_needs_title_match'
        confidence_warning = source_extra_note.strip() or 'None'
    elif best_email_type == 'b2b_partnerships':
        contact_quality = 'Tier B (B2B / Corporate Partnership Inbox — Needs Marketing Lead on LinkedIn)'
        enrichment_status = 'b2b_role_inbox_only_needs_linkedin_dm'
        confidence_warning = f'Note: Commercial partnership inbox; locate Head of Marketing via LinkedIn.{source_extra_note}'
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox'):
        contact_quality = 'Tier C (Generic Office Inbox — Gatekeeper Routing Only)'
        enrichment_status = 'generic_inbox_only_needs_linkedin_dm'
        confidence_warning = source_extra_note.strip() or 'None'
    elif best_email_type in (
        'customer_support_inbox', 'pr_and_media_inbox', 'legal_or_hr_inbox',
        'influencer_gifting_inbox', 'wholesale_or_sales_inbox', 'regional_branch_inbox',
        'department_or_general_inbox', 'admissions_or_department_inbox'
    ):
        contact_quality = f'Tier D (Non-Marketing Channel: {best_email_type} — Do Not Cold Pitch Services Here)'
        enrichment_status = 'support_or_pr_inbox_only_requires_dm_enrichment'
        confidence_warning = f'Warning: Email is {best_email_type}; locate Head of Marketing via LinkedIn.{source_extra_note}'
    elif primary_phone:
        contact_quality = 'Tier D (Phone Only — No Email Found on Public Pages)'
        enrichment_status = 'phone_only_requires_email_and_dm_enrichment'
        confidence_warning = f'Warning: No public email found; check marketing department via LinkedIn.{source_extra_note}'
    else:
        contact_quality = 'Tier F (No Actionable Contacts Found on Website)'
        if had_marketplace_pollution:
            enrichment_status = 'marketplace_external_emails_filtered_needs_linkedin_dm'
            confidence_warning = 'Warning: External third-party brand emails filtered out; check marketing department via LinkedIn.'
        elif pw_blocked_by_waf:
            enrichment_status = 'playwright_blocked_by_waf_needs_residential_proxy'
            confidence_warning = f'Warning: Browser scan blocked by WAF ({pw_status_str}); scores nullified.'
        else:
            enrichment_status = 'no_public_contacts_found'
            confidence_warning = 'Warning: Zero public contacts on site; check marketing department via LinkedIn.'

    if is_scan_failed_completeness(scan_comp):
        readiness_verdict = f'Unverified — Scan Failed ({scan_comp}; scores set to null)'
    elif company_category == 'Non-Profit / Education / Institution':
        readiness_verdict = 'Disqualified (Non-Target Institutional / NGO Segment)'
    elif is_agency:
        readiness_verdict = 'Partner Pipeline Only (Agency / Media Segment)'
    elif not all_signals and not best_email and not primary_phone:
        readiness_verdict = 'Unverified (No Tech Signals & No Public Contacts Observed — Needs Manual Review)'
    elif compliance_blocked:
        if dm_name and dm_is_direct_mkt_buyer:
            readiness_verdict = f'LinkedIn / Warm-Intro Only ({dm_name} Identified; Cold Email Blocked under §7 UWG)'
        else:
            readiness_verdict = 'LinkedIn / Warm-Intro Only (Cold Email Restricted under §7 UWG)'
    elif dm_name and is_same_person_li and dm_is_direct_mkt_buyer:
        readiness_verdict = f'Sales-Ready via LinkedIn Outbound ({dm_name}, {dm_role} Verified)'
    elif dm_name and is_same_person_email and dm_is_direct_mkt_buyer:
        readiness_verdict = f'Sales-Ready Tier 1 (Verified Marketing Buyer: {dm_name}, {dm_role} + Matching Direct Email)'
    elif dm_name and not dm_is_direct_mkt_buyer:
        readiness_verdict = f'Escalation-Needed (Only {dm_role or "CEO/Founder"} {dm_name} Found — Locate Head of Marketing via LinkedIn)'
    elif best_email_type == 'marketing_or_exec_role' and all_signals and scan_comp != 'partial_csp_headers':
        readiness_verdict = 'Research Priority + Marketing Role Inbox (Locate Named CMO / Head of Digital on LinkedIn)'
    else:
        readiness_verdict = 'Research Priority (Head of Marketing Not Found on Site — Check Marketing Department via LinkedIn)'

    if is_scan_failed_completeness(scan_comp):
        opportunity = f'Scan failed ({scan_comp}) — cannot evaluate technical opportunity without runtime access'
    elif is_agency:
        opportunity = 'Agency/Media Segment: Explore white-label analytics partnership or data API integration'
    elif company_category == 'Non-Profit / Education / Institution':
        opportunity = 'Non-commercial / Institutional organization — disqualify from standard B2B sales'
    elif scan_comp == 'partial_csp_headers':
        opportunity = 'Partial scan (CSP headers only) — runtime network audit required before technical pitch'
    elif tech_info.get('duplicate_ga4_ids') and tech_info.get('duplicate_ga4_runtime_confirmed'):
        ev_d = ', '.join((tech_info.get('duplicate_ga4_events') or [])[:2])
        opportunity = f"PROVEN RUNTIME ISSUE [RUNTIME_NETWORK_VERIFIED]: Duplicate GA4 firing ({tech_info['duplicate_ga4_ids'][0]} {ev_d})"
    elif tech_info.get('tag_runtime_status') == 'CONSENT_GATED_OR_SILENT':
        opportunity = 'RUNTIME OBSERVATION [CONSENT_GATED_OR_SILENT]: GA4 configured in code/GTM with zero /g/collect hits observed'
    elif len(ad_tags) >= 2:
        opportunity = (
            f"Discovery audit candidate: multi-channel ad tags ({', '.join(ad_tags)}) observed "
            "(SERVER_SIDE_TRACKING_STATUS_UNKNOWN — verify server-side setup during discovery)"
        )
    elif len(ad_tags) == 1:
        opportunity = f"Discovery audit candidate: {ad_tags[0]} observed (SERVER_SIDE_TRACKING_STATUS_UNKNOWN)"
    else:
        opportunity = 'Verify runtime tracking behavior in browser before proposing analytics optimization'

    # Крок 3 P0: Явна інструкція перевірки відділу маркетингу через LinkedIn, якщо знайдено лише CEO або немає маркетолога
    if is_scan_failed_completeness(scan_comp):
        next_action = (
            f'Scan failed ({scan_comp}) — retry with residential proxy. '
            f'{build_marketing_department_escalation_note(dm_name, dm_role, resolved_li_people)}'
        )
    elif company_category == 'Non-Profit / Education / Institution':
        next_action = 'Exclude from commercial B2B cold outreach'
    elif is_agency:
        next_action = f"Route to Agency Partnership pipeline via {best_email or resolved_li_people or 'LinkedIn'}"
    elif dm_name and dm_is_direct_mkt_buyer and is_same_person_email:
        next_action = f"Send evidence-based MarTech audit note to {dm_name} ({dm_role}) at {best_email}"
    elif dm_name and dm_is_direct_mkt_buyer and is_same_person_li:
        next_action = f"Message {dm_name} ({dm_role}) on LinkedIn at {dm_linkedin_url}"
    elif dm_name and dm_is_direct_mkt_buyer:
        pred_part = f" or verify predicted email {predicted_dm_email}" if predicted_dm_email else ""
        next_action = (
            f"Locate {dm_name} ({dm_role}) on LinkedIn ({resolved_li_people or 'decision_maker_search_query'}){pred_part}"
        )
    else:
        next_action = build_marketing_department_escalation_note(dm_name, dm_role, resolved_li_people)

    if company_category != 'Non-Profit / Education / Institution' and not is_scan_failed_completeness(scan_comp):
        next_action = enforce_outreach_compliance_guardrail(
            next_action,
            compliance_block_code,
            dm_name=dm_name,
            dm_role=dm_role,
            dm_buyer_fit_status=buyer_fit,
            company_linkedin_people_url=resolved_li_people,
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
    sgtm_flag = ('Server-Side GTM (sGTM)' in seed_tech_set) or bool(seed.get('has_sgtm', False))

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
        'has_sgtm': sgtm_flag,
        'all_ga4_ids': seed.get('all_ga4_ids'),
        'all_ga4_ids_count': 1 if seed.get('all_ga4_ids') else 0,
        'ga4_detection_confidence': seed.get('ga4_detection_confidence', 'DETECTED_IN_HTML (Manual Audit Seed)'),
        'detected_cms_list': [x.strip() for x in (seed.get('detected_cms') or '').split(';') if x.strip()],
        'detected_cms': seed.get('detected_cms'),
        'has_cookie_banner': bool(seed.get('consent_mode_likely', False)),
        'xhr_fetch_traffic_analyzed': False,
        'xhr_fetch_requests_inspected': 0,
        'xhr_first_party_collect_endpoints': [],
        'server_side_tracking_assessment': 'DETECTED_IN_HTML_SGTM' if sgtm_flag else 'SERVER_SIDE_TRACKING_STATUS_UNKNOWN',
        'detected_technologies_list': seed_tech_list,
        'confirmed_martech_platforms': seed_tech_list,
        'tech_verification_tiers': {t: 'DETECTED_IN_HTML' for t in seed_tech_list},
        'technology_evidence': seed.get('technology_evidence', 'Verified via manual_seed'),
        'technology_evidence_summary': seed.get('technology_evidence_summary', 'GTM, GA4, Meta Pixel (Manual Seed)'),
        'technology_evidence_json': build_evidence_json_from_cached_record(seed, source_label='manual_seed'),
        'tech_scan_completeness': 'full'
    }

    c_hint = detect_country_hint(canonical_domain, '', '', primary_phone, '')
    jur_str = derive_gdpr_jurisdiction(canonical_domain, primary_phone, c_hint, '')
    data_sens = derive_data_source_sensitivity(dm_src_type, seed.get('email_source_type', 'contact_page'), jur_str)
    comp_blk, comp_code = is_cold_email_compliance_blocked(jur_str, data_sens, canonical_domain, c_hint, False)
    company_li_people_url = build_company_linkedin_people_url(li_url, canonical_domain)

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
        company_linkedin_people_url=company_li_people_url,
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
        'not_attempted_manual_seed', 'not_checked', em_conf, None, is_cached_or_seed=True,
        tech_verification_tiers=tech_info['tech_verification_tiers'],
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
        'server_side_tracking_assessment': tech_info['server_side_tracking_assessment'],
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
