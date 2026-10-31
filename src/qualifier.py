import json
import re
from .config import (
    KNOWN_MARKETPLACE_DOMAINS,
    MARKETPLACE_TEXT_MARKERS,
    ROLE_NORMALIZATION_MAP,
    compute_snapshot_age_days,
    truncate_error_msg,
)
from .contacts import (
    build_decision_makers_json_from_summary,
    classify_dm_source_type,
    classify_email_type,
    is_marketing_or_digital_role,
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
        'promodo', 'netpeak'
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
        or any(cms in detected_tech for cms in ('Shopify', 'WooCommerce'))
        or has_product_schema
        or any(k in text for k in ecom_keywords)
    ):
        return 'E-commerce / Retail Brand', 'high'

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

    saas_keywords = (
        'saas', 'cloud platform', 'crm', 'api', 'b2b software', 'automation platform',
        'майданчик', 'тендер', 'prozorro', 'прозорро', 'закупівлі', 'mobility app',
        'call tracking', 'колтрекінг', 'business phone', 'virtual pbx', 'telephony',
        'end-to-end analytics', 'наскрізна аналітика', 'marketing performance platform',
        'email service', 'automation service', 'chatbot', 'cloud-lösung', 'softwarelösung',
        'logiciel saas', 'plateforme cloud', 'software de gestión', 'piattaforma cloud',
        'oprogramowanie dla firm', 'system crm', 'ringostat', 'sendpulse', 'macpaw', 'readdle', 'grammarly',
        'seo', 'serp', 'keyword', 'keywords', 'backlink', 'backlinks', 'site audit', 'rank tracker',
        'website builder', 'конструктор сайтів', 'створення сайту', 'ai website builder',
        'helpdesk', 'live chat', 'customer communication', 'customer data platform', 'cdp',
        'omnichannel', 'no-code', 'low-code', 'workflow automation',
        'serpstat', 'weblium', 'esputnik', 'creatio', 'helpcrunch'
    )
    if any(k in text for k in saas_keywords):
        return 'SaaS / Marketplace / Tech Platform', 'high'

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
        local_roles = ' OR "Geschäftsführer" OR "Marketingleiter" OR "Inhaber" OR "Gründer"'
    elif dom_low.endswith('.fr') or hint_up == 'FR':
        local_roles = ' OR "Directeur Marketing" OR "PDG" OR "Directeur Général" OR "Fondateur"'
    elif dom_low.endswith('.es') or hint_up == 'ES':
        local_roles = ' OR "Director de Marketing" OR "Director General" OR "Fundador"'
    elif dom_low.endswith('.it') or hint_up == 'IT':
        local_roles = ' OR "Direttore Marketing" OR "Amministratore Delegato" OR "Fondatore"'
    elif dom_low.endswith(('.nl', '.be')) or hint_up in ('NL', 'BE'):
        local_roles = ' OR "Algemeen Directeur" OR "Marketing Directeur" OR "Oprichter" OR "Eigenaar"'
    elif dom_low.endswith('.pl') or hint_up == 'PL':
        local_roles = ' OR "Prezes Zarządu" OR "Dyrektor Marketingu" OR "Właściciel" OR "Założyciel"'
    elif dom_low.endswith('.pt') or hint_up == 'PT':
        local_roles = ' OR "Diretor de Marketing" OR "Diretor Geral" OR "Sócio-Gerente"'
    elif dom_low.endswith(('.se', '.no', '.dk', '.fi')) or hint_up in ('SE', 'NO', 'DK', 'FI'):
        local_roles = ' OR "Marknadschef" OR "VD" OR "Grundare" OR "Daglig leder"'
    elif dom_low.endswith('.ua') or hint_up == 'UA':
        local_roles = ' OR "Директор з маркетингу" OR "Засновник" OR "Власник"'
    else:
        local_roles = ''

    return (
        f'site:linkedin.com/in ("{canonical_domain}" OR "{brand_root}") '
        f'("CMO" OR "Chief Marketing Officer" OR "Head of Marketing" OR "Marketing Director" '
        f'OR "Head of E-commerce" OR "Founder" OR "CEO"{local_roles})'
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
) -> int:
    if company_category == 'Non-Profit / Education / Institution':
        return 10

    score = 0
    t_str = contact_quality_tier or ''
    is_unmatched_staff_email = ('Different from Listed Executive' in t_str or 'Listed Executive is' in t_str)

    if is_same_person_email:
        score += 65
    elif 'Tier A-' in t_str or 'Agency Tier A' in t_str:
        score += 40
    elif 'Tier A' in t_str:
        score += 45
    elif 'Tier B+' in t_str or 'Agency Tier B+' in t_str:
        score += 34
    elif 'Tier B' in t_str:
        score += 28
    elif 'Tier C' in t_str or 'Agency Tier C' in t_str:
        score += 18
    elif 'Tier D' in t_str:
        score += 6

    if dm_name and not is_unmatched_staff_email:
        score += 15
    if dm_linkedin_url:
        score += 10
    if primary_phone:
        score += 8

    if techs_count >= 4:
        score += 22
    elif techs_count >= 2:
        score += 15
    elif techs_count == 1:
        score += 6

    if scan_completeness != 'full' or techs_count == 0:
        if scan_completeness == 'partial_cached' and techs_count >= 4 and not dm_name and not primary_phone:
            score -= 8
        else:
            score -= 15

    has_any_signal_or_contact = (techs_count >= 1) or ('Tier F' not in t_str and bool(t_str))
    floor_score = 12 if has_any_signal_or_contact else 0
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
) -> str:
    """
    Удосконалення №2 (v21.5):
    Усуває розсинхрон між decision_maker_name та власником best_email у sales_hook (напр. на netpeak.net та esputnik.com).
    Якщо best_email є іменною поштою іншої людини (не dm_name), чітко розділяє Named Contact та Listed Executive!
    """
    brand = canonical_domain.split('.')[0].capitalize() if canonical_domain else 'Company'
    if company_category == 'Non-Profit / Education / Institution':
        return f'{brand} is a non-profit/institutional entity — exclude from commercial outbound.'

    brand_token = canonical_domain.split('.')[0].lower() if canonical_domain else ''
    em_type = best_email_type or classify_email_type(best_email, brand_token)
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

    if is_unmatched_named_inbox:
        dm_intro = f'Marketing Lead (via named contact {best_email}; listed {dm_role or "Exec"}: {dm_name})'
    elif dm_name:
        dm_intro = f'{dm_name} ({dm_role})'
    else:
        dm_intro = 'Marketing Lead'

    li_badge = ' [LinkedIn verified]' if dm_linkedin_url else ''
    stack_str = ', '.join(techs[:5]) if techs else ('Consent-gated / unverified stack' if has_consent else 'No public ad pixels detected')
    cms_str = f' on {cms}' if cms else ''

    if dup_ga4_ids:
        dup_id = dup_ga4_ids[0]
        dup_tag = 'duplicate_runtime_hits_confirmed' if dup_runtime_confirmed else 'duplicate_configuration_suspected'
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} [Red Flag: Duplicate GA4 Tagging ({dup_id} in both HTML & GTM — {dup_tag})]. "
            f"Opening Hook: \"Noticed {brand}'s GA4 property ({dup_id}) is present both in the page HTML "
            f"and inside your GTM container — have you verified whether GTM firing triggers are deduplicating pageviews and conversions?\""
        )

    cm_v2_gap_note = ''
    if (
        is_eu_gdpr
        and has_gads
        and not has_cm_v2
        and tech_info.get('tech_scan_completeness') == 'full'
        and (pw_used or has_consent)
    ):
        cm_v2_gap_note = ' [EU Consent Mode v2 gap: Google Ads active without gcs/gcd parameters observed]'

    paid_channels = [c for c, flag in (('Meta', has_meta), ('Google Ads', has_gads), ('TikTok', has_tiktok), ('LinkedIn', has_li)) if flag]

    if has_sgtm and paid_channels:
        paid_str = ' + '.join(paid_channels)
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str} (Server-Side GTM verified){cm_v2_gap_note}. "
            f"Opening Hook: \"Saw {brand} has {paid_str} tags configured alongside Server-Side GTM — "
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
        return (
            f"{brand} ({company_category}{cms_str}) — Target: {dm_intro}{li_badge}. "
            f"Stack: {stack_str}. Multi-platform ad tracking tags ({paid_str}) configured on site (current campaign spend unverified). "
            f"Opening Hook: \"Saw {brand} has {paid_str} tracking configured alongside GA4 — "
            f"how are you currently validating cross-channel attribution and server-side signal recovery across your funnel?\""
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

    for ux_tool in ('Microsoft Clarity', 'Hotjar', 'HubSpot', 'Klaviyo', 'Intercom'):
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
        detected_signals_str = ', '.join(all_signals)
    elif detected_cms:
        consent_note = ' — ad tags likely consent-gated' if has_cookie_banner else ''
        detected_signals_str = f"None detected ({', '.join(detected_cms)} platform only{consent_note})"
    else:
        detected_signals_str = 'None detected'

    is_agency = (company_category == 'B2B Agency / Marketing Media')

    if company_category == 'E-commerce / Retail Brand':
        icp_fit_tier = 'Tier 1: Target ICP (E-commerce / Retail Brand)'
    elif company_category in ('SaaS / Marketplace / Tech Platform', 'General Business / Corporate'):
        icp_fit_tier = f'Tier 2: Secondary ICP ({company_category})'
    elif is_agency:
        icp_fit_tier = 'Partner / Competitor Segment (Agency / Media — Exclude from Standard Client Outreach)'
    else:
        icp_fit_tier = 'Non-Target ICP (Non-Profit / Education / Institution)'

    if len(ad_tags) >= 2 and analytics_tags:
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
    dm_is_direct_mkt_buyer = is_marketing_or_digital_role(dm_role)
    is_mp_founder_with_vendor_b2b = (
        is_mp_platform
        and not dm_is_direct_mkt_buyer
        and best_email_type == 'b2b_partnerships'
    )

    source_extra_note = ''
    if dm_source_is_legal and dm_source_type not in ('impressum_page', 'impressum_page_cached'):
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
                f'Note: Agency partnership contact — route to {best_email}, not to {dm_name}.'
            )
        elif dm_name:
            contact_quality = f'Agency Tier A- (Executive {dm_name} Identified — Route to Partner Pipeline)'
            enrichment_status = 'agency_partner_executive_identified'
            confidence_warning = 'None'
        else:
            contact_quality = f'Agency Tier C ({best_email or "General Channel"} — Route to Partner Pipeline)'
            enrichment_status = 'agency_partner_channel'
            confidence_warning = 'None'
    elif dm_name and is_same_person_email:
        contact_quality = f'Tier A (Verified Match: {dm_name} + Direct Personal Email)'
        enrichment_status = 'verified_decision_maker_and_matching_email'
        confidence_warning = source_extra_note.strip() or 'None'
    elif dm_name and is_same_person_li:
        contact_quality = (
            f'Tier A- (Decision-Maker {dm_name} + Name-Matched LinkedIn URL Verified; '
            f'Site Email is {best_email_type or "None"})'
        )
        enrichment_status = 'decision_maker_linkedin_verified_paired_with_site_contact'
        confidence_warning = f'Note: Decision-maker LinkedIn slug matches person name; site email is a company/department inbox.{source_extra_note}'
    elif dm_name and best_email_type == 'marketing_or_exec_role':
        contact_quality = f'Tier A- (Decision-Maker Found: {dm_name} + Direct Marketing Role Inbox: {best_email})'
        enrichment_status = 'decision_maker_found_plus_marketing_role_inbox'
        confidence_warning = f'Note: Executive identified on site and paired with dedicated marketing@ department inbox.{source_extra_note}'
    elif dm_name and is_mp_founder_with_vendor_b2b:
        contact_quality = (
            f'Tier B (Marketplace Founder/Executive {dm_name} + Vendor/B2B Desk {best_email} — Locate CMO for MarTech)'
        )
        enrichment_status = 'marketplace_founder_and_vendor_b2b_desk_needs_cmo'
        confidence_warning = (
            f'Note: {dm_name} ({dm_role}) is corporate founder/board level and {best_email} handles commercial/vendor inquiries; '
            f'locate operational CMO / Head of Digital via LinkedIn before pitching analytics.{source_extra_note}'
        )
    elif dm_name and best_email_type in ('b2b_partnerships', 'wholesale_or_sales_inbox') and len(all_signals) >= 1:
        contact_quality = (
            f'Tier A- (Decision-Maker Found: {dm_name} + Commercial B2B/Sales Channel: {best_email})'
        )
        enrichment_status = 'decision_maker_paired_with_commercial_b2b_channel'
        confidence_warning = (
            f'Note: Verified executive ({dm_name}) paired with commercial B2B/Sales inbox ({best_email}).{source_extra_note}'
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
        enrichment_status = 'executive_named_but_only_non_sales_inbox_on_site'
        confidence_warning = (
            f'Warning: {dm_name} found on site, but {best_email} is {best_email_type}. '
            f'Use LinkedIn X-Ray to contact {dm_name} rather than emailing {best_email}.{source_extra_note}'
        )
    elif dm_name and best_email_type in ('brand_webmail_support_inbox', 'brand_webmail_general_inbox'):
        contact_quality = (
            f'Tier C (Owner/Executive {dm_name} Identified + Brand Webmail {best_email} Found)'
        )
        enrichment_status = 'owner_identified_paired_with_brand_webmail'
        confidence_warning = (
            f'Note: Company uses public webmail ({best_email}) as its primary contact.{source_extra_note}'
        )
    elif dm_name and (best_email or primary_phone):
        tier_prefix = 'Tier B-' if not all_signals else 'Tier B'
        contact_quality = f'{tier_prefix} (Decision-Maker Found: {dm_name}, Paired with Generic/B2B Inbox)'
        enrichment_status = 'decision_maker_named_separately_from_generic_inbox'
        confidence_warning = f'Warning: Person name verified on site; email is company role/generic inbox (not direct personal email).{source_extra_note}'
    elif best_email_type in ('personal_or_named_inbox', 'marketing_or_exec_role'):
        contact_quality = f'Tier B+ (Direct / Named Role Inbox: {best_email_type}, Full Name Unlisted)'
        enrichment_status = 'named_or_role_email_found_needs_title_match'
        confidence_warning = 'None'
    elif best_email_type == 'b2b_partnerships':
        contact_quality = 'Tier B (B2B / Corporate Partnership Inbox — Good for B2B Pitch, Needs Referral for Analytics/Tech)'
        enrichment_status = 'b2b_role_inbox_only_needs_linkedin_dm'
        confidence_warning = 'Note: B2B/Corporate inbox is for commercial partnerships; request referral to CMO/Head of Digital.'
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox'):
        contact_quality = 'Tier C (Generic Office Inbox — Suitable for Gatekeeper Routing Only)'
        enrichment_status = 'generic_inbox_only_needs_linkedin_dm'
        confidence_warning = 'None'
    elif best_email_type == 'brand_webmail_support_inbox':
        contact_quality = f'Tier C (Primary Brand Webmail Inbox: {best_email} — Suitable for Initial Routing)'
        enrichment_status = 'brand_webmail_only_needs_linkedin_dm'
        confidence_warning = 'Note: Brand uses a single Gmail/Webmail inbox for inquiries; request forwarding to marketing/management.'
    elif best_email_type == 'influencer_gifting_inbox':
        contact_quality = f'Tier C- (influencer_gifting_inbox: {best_email} — Creator/PR Gifting Channel)'
        enrichment_status = 'influencer_gifting_inbox_needs_linkedin_dm'
        confidence_warning = 'Warning: Email is for creator/influencer gifting (gteam/collabs), not B2B tech/analytics procurement.'
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

    if company_category == 'Non-Profit / Education / Institution':
        readiness_verdict = 'Disqualified (Non-Target Institutional / NGO Segment)'
    elif is_agency:
        readiness_verdict = 'Partner Pipeline Only (Agency / Media Segment)'
    elif not all_signals and not best_email and not primary_phone:
        if pw_blocked_by_waf:
            readiness_verdict = 'Unverified (Playwright Blocked by WAF — Retry with Residential Proxy)'
        else:
            readiness_verdict = 'Unqualified (No Tech Signals & No Actionable Contacts — Needs Manual Review)'
    elif dm_name and is_same_person_li:
        if all_signals:
            readiness_verdict = f'Sales-Ready via LinkedIn Outbound ({dm_name} Profile Verified + Tech Stack Confirmed)'
        else:
            readiness_verdict = f'Contact-Ready via LinkedIn Outbound ({dm_name} Profile Verified; Tech Stack Unverified — Check Manually)'
    elif dm_name and is_same_person_email:
        readiness_verdict = 'Sales-Ready Tier 1 (Verified Decision-Maker + Matching Direct Email)'
    elif dm_name and is_mp_founder_with_vendor_b2b:
        readiness_verdict = (
            f'Partnership-Ready Only (Marketplace Founder {dm_name} + Commercial B2B Desk — Locate CMO/Head of Digital for MarTech Pitch)'
        )
    elif dm_name and best_email_type in ('b2b_partnerships', 'wholesale_or_sales_inbox') and all_signals:
        readiness_verdict = f'Sales-Ready Tier 1.5 (Verified Decision-Maker {dm_name} + Commercial B2B/Sales Channel)'
    elif best_email_type == 'marketing_or_exec_role' and all_signals:
        readiness_verdict = 'Sales-Ready Tier 2 (Direct Marketing / Executive Role Inbox)'
    elif not all_signals:
        if best_email_type in ('b2b_partnerships', 'marketing_or_exec_role'):
            dm_part = f' + {dm_name}' if dm_name else ''
            readiness_verdict = f'Partnership-Ready{dm_part} (B2B/Marketing Channel Found; Tech Stack Unverified — Check Manually)'
        elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox', 'personal_or_named_inbox') or dm_name:
            dm_part = f' + {dm_name} Known' if dm_name else ''
            readiness_verdict = f'Gatekeeper-Ready{dm_part} (Contact Found; Tracking Gated by Consent or Absent — Verify Manually)'
        else:
            readiness_verdict = 'Unverified (Support/Non-Sales Contact Only & No Tech Signals Detected in Static HTML)'
    elif best_email_type == 'b2b_partnerships':
        readiness_verdict = 'Partnership-Ready Only (B2B Inbox Found — Needs CMO Referral for Analytics/Tech Pitch)'
    elif enrichment_status == 'owner_identified_paired_with_brand_webmail':
        readiness_verdict = f'Gatekeeper-Ready + Owner Known ({dm_name} Identified — Route via Brand Webmail or LinkedIn)'
    elif dm_name and best_email_type == 'general_office_inbox':
        readiness_verdict = f'Gatekeeper-Ready + DM Known ({dm_name} Identified — Route via Office Inbox or LinkedIn)'
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox'):
        readiness_verdict = 'Gatekeeper-Ready Only (Office/Brand Inbox — Locate DM on LinkedIn Before Cold Outbound)'
    else:
        readiness_verdict = 'Tech-Qualified Account Only (Needs LinkedIn DM Enrichment Before Outbound)'

    if is_agency:
        opportunity = (
            'Agency/Media Segment: Explore white-label analytics partnership, '
            'data enrichment API integration, or B2B referral collaboration'
        )
    elif company_category == 'Non-Profit / Education / Institution':
        opportunity = 'Non-commercial / Institutional organization — disqualify from standard B2B sales'
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
    has_real_signals = bool(all_signals)
    stack_ref_clause = (
        f' referencing detected stack ({detected_signals_str})'
        if has_real_signals
        else ' to initiate B2B discovery (verify tracking stack manually first)'
    )
    pred_email_clause = f'; test predicted DM email {predicted_dm_email} via verifier' if predicted_dm_email else ''

    if is_agency:
        next_action = f"Route to Agency Partnership pipeline; reach out via {best_email or linkedin_url or 'LinkedIn'}{pred_email_clause}{phone_note}"
    elif company_category == 'Non-Profit / Education / Institution':
        next_action = 'Exclude from commercial B2B cold outreach'
    elif not all_signals and not best_email and not primary_phone:
        if pw_blocked_by_waf:
            next_action = (
                f'Retry with residential proxy — Playwright blocked by WAF ({pw_status_str}); '
                f'do NOT skip this lead (use decision_maker_search_query on LinkedIn meanwhile)'
            )
        else:
            next_action = 'Skip or review website manually (no tech signals or contacts detected)'
    elif dm_name and is_same_person_li:
        next_action = (
            f"Send personalized LinkedIn message to {dm_name} ({dm_role}) at {dm_linkedin_url}"
            f"{stack_ref_clause}{pred_email_clause}"
        )
    elif dm_name and is_mp_founder_with_vendor_b2b:
        next_action = (
            f"Locate operational CMO / Head of Digital via decision_maker_search_query on LinkedIn before pitching analytics "
            f"(listed DM {dm_name} is {dm_role}, and {best_email} is a commercial/vendor B2B desk){phone_note}"
        )
    elif dm_name and best_email_type in ('b2b_partnerships', 'wholesale_or_sales_inbox'):
        next_action = (
            f"Contact {dm_name} ({dm_role}) via LinkedIn{pred_email_clause} or send B2B discovery proposal to {best_email}"
            f"{stack_ref_clause}{phone_note}"
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
                f"test predicted DM email {predicted_dm_email} via verifier or message {dm_name} via decision_maker_search_query on LinkedIn{phone_note}"
            )
        else:
            next_action = (
                f"DO NOT send cold marketing pitch to {best_email} ({best_email_type}); "
                f"locate Marketing Lead / DM{dm_hint} via decision_maker_search_query on LinkedIn{phone_note}"
            )
    elif best_email_type == 'b2b_partnerships':
        next_action = (
            f"Send partnership/referral inquiry to {best_email} asking for introduction to Head of Marketing/Analytics; "
            f"NO DM found on site — use decision_maker_search_query on LinkedIn to find CMO/Head of Marketing first{phone_note}"
        )
    elif best_email_type == 'marketing_or_exec_role':
        next_action = (
            f"Send tailored discovery audit offer to {best_email} ({best_email_type})"
            f"{stack_ref_clause}{pred_email_clause}"
        )
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox'):
        dm_hint = f" ({dm_name})" if dm_name else ""
        next_action = (
            f"Locate CMO / Head of E-commerce{dm_hint} via decision_maker_search_query on LinkedIn{pred_email_clause} first; "
            f"use {best_email} only for warm gatekeeper routing / referral request"
        )
    elif primary_phone:
        next_action = f"Use decision_maker_search_query on LinkedIn{pred_email_clause} or call {primary_phone} for routing"
    else:
        next_action = (
            f"Run decision_maker_search_query in LinkedIn / Apollo{pred_email_clause} to locate marketing decision-maker{phone_note}"
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
        'ga4_detection_confidence': seed.get('ga4_detection_confidence', 'Verified (Manual Audit Seed)'),
        'detected_cms_list': [x.strip() for x in (seed.get('detected_cms') or '').split(';') if x.strip()],
        'detected_cms': seed.get('detected_cms'),
        'has_cookie_banner': bool(seed.get('consent_mode_likely', False)),
        'detected_technologies_list': seed_tech_list,
        'technology_evidence': seed.get('technology_evidence', 'Verified via manual_seed'),
        'technology_evidence_summary': seed.get('technology_evidence_summary', 'GTM, GA4, Meta Pixel (Manual Seed)'),
        'technology_evidence_json': build_evidence_json_from_cached_record(seed, source_label='manual_seed'),
        'tech_scan_completeness': 'full'
    }

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
        is_mp_platform=False,
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
        'data_quality_score': dq_score,
        'sales_readiness_verdict': sales_readiness_verdict,
        'company_category': cat,
        'category_confidence': cat_conf,
        'marketplace_platform': is_mp,
        'marketplace_platform_pollution_detected': False,
        'icp_fit_tier': icp_fit_tier,
        'technical_signal_strength': technical_signal_strength,
        'tech_scan_completeness': 'full',
        'tech_rescan_needed': False,
        'contact_quality_tier': contact_quality_tier,
        'contact_enrichment_status': enrichment_status,
        'data_confidence_warning': (
            f'Note: Live crawl encountered {short_err_msg}; returning verified manual_seed '
            f'(age={age_days}d, verified_at={verified_at}).'
        ),
        'gdpr_eu_domain': is_eu_gdpr,
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
        'email_source_type': seed.get('email_source_type', 'contact_page'),
        'email_source_note': seed.get('email_source_note', 'Verified via manual audit seed'),
        'named_email_owner_role_hint': None,
        'email_deliverability_check': deliv_str,
        'all_emails_deliverability': all_emails_deliv_str,
        'all_emails_classification': all_emails_class_str,
        'email_source_url': seed.get('email_source_url', clean_website_url),
        'primary_phone': primary_phone,
        'e164_phone': seed.get('e164_phone') or (re.sub(r'[\s\-()]', '', primary_phone) if primary_phone else None),
        'phone_availability': 'public' if primary_phone else 'not_public',
        'phone_source_url': seed.get('phone_source_url', clean_website_url),
        'decision_maker_name': dm_name,
        'decision_maker_role': dm_role,
        'decision_maker_source_url': dm_src,
        'decision_maker_source_type': dm_src_type,
        'decision_makers_found': dms_found_str,
        'decision_makers_json': dms_json_str,
        'decision_maker_linkedin_url': seed.get('decision_maker_linkedin_url'),
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
        'detected_technologies': seed.get('detected_technologies'),
        'all_emails': seed.get('all_emails', best_email),
        'all_phones': seed.get('all_phones', primary_phone),
        'last_checked_at': verified_at
    }
