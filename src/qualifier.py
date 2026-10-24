import re
from .config import (
    KNOWN_MARKETPLACE_DOMAINS,
    MARKETPLACE_TEXT_MARKERS,
    compute_snapshot_age_days,
    truncate_error_msg,
)
from .contacts import (
    classify_dm_source_type,
    classify_email_type,
    verify_person_email_match,
    verify_person_linkedin_match,
)


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
    text = f'{domain} {page_title} {meta_desc}'.lower()
    html_low = html_sample[:15000].lower()

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
        'agência digital', 'agência de marketing', 'webbyrå', 'reklambyrå', 'kommunikationsbyrå', 'mediebyrå'
    )
    if any(k in text for k in agency_keywords):
        return 'B2B Agency / Marketing Media', 'high'

    ecom_keywords = (
        'інтернет-магазин', 'интернет-магазин', 'онлайн магазин', 'online store',
        'shop', 'купити', 'купить', 'купуй', 'доставка по', 'колекція', 'бренд одягу',
        'бренд взуття', 'жіночого одягу', 'женского белья', 'каталог товарів',
        'checkout', 'add to cart', 'кошик', 'shoes', 'apparel', 'clothing',
        'млн товарів', 'знижки до', 'кешбек', 'доставка ліків', 'замовити ліки',
        'onlineshop', 'online-shop', 'warenkorb', 'versandkostenfrei', 'jetzt kaufen', 'bestellen',
        'boutique en ligne', 'livraison gratuite', 'panier', 'acheter en ligne', 'magasin en ligne',
        'tienda online', 'carrito', 'envío gratis', 'comprar online', 'tienda en línea',
        'negozio online', 'carrello', 'spedizione gratuita', 'acquista online', 'shopping online',
        'webwinkel', 'webshop', 'winkelwagen', 'gratis verzending', 'bestel online',
        'sklep internetowy', 'koszyk', 'darmowa dostawa', 'kup teraz', 'zakupy online',
        'loja online', 'frete grátis', 'carrinho', 'comprar agora',
        'webbutik', 'varukorg', 'fri frakt', 'handla online', 'nettbutikk', 'handlekurv',
        'fashion', 'fashion online', 'accessories', 'footwear', 'sportswear', 'streetwear',
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
        domain.lower() in KNOWN_MARKETPLACE_DOMAINS
        or any(cms in detected_tech for cms in ('Shopify', 'WooCommerce'))
        or has_product_schema
        or any(k in text for k in ecom_keywords)
    ):
        return 'E-commerce / Retail Brand', 'high'

    saas_keywords = (
        'saas', 'cloud platform', 'crm', 'api', 'b2b software', 'automation platform',
        'майданчик', 'тендер', 'prozorro', 'прозорро', 'закупівлі', 'mobility app',
        'call tracking', 'колтрекінг', 'business phone', 'virtual pbx', 'telephony',
        'end-to-end analytics', 'наскрізна аналітика', 'marketing performance platform',
        'email service', 'automation service', 'chatbot', 'cloud-lösung', 'softwarelösung',
        'logiciel saas', 'plateforme cloud', 'software de gestión', 'piattaforma cloud',
        'oprogramowanie dla firm', 'system crm', 'ringostat', 'sendpulse', 'macpaw', 'readdle', 'grammarly'
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
        domain.endswith(('.edu', '.edu.ua', '.ac.uk', '.gov', '.gov.ua', '.org', '.org.ua', '.gob.es', '.gouv.fr'))
        or any(
            phrase in text for phrase in (
                'благодійний фонд', 'charitable foundation', 'громадська організація',
                'gemeinnützige', 'eingetragener verein', 'association loi 1901',
                'fundación sin ánimo de lucro', 'fondazione onlus', 'stichting',
                'fundacja', 'stowarzyszenie', 'allmännyttig stiftelse'
            )
        )
    )

    # Проблема 2 Fix: Використовуємо \b...\b word-boundary, щоб 'ngo' не спрацьовувало на 'ringostat.com'
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
    pw_status_str: str = 'not_needed'
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
    detected_cms = tech_info.get('detected_cms_list', [])
    has_cookie_banner = tech_info.get('has_cookie_banner', False)
    scan_comp = tech_info.get('tech_scan_completeness', 'full')
    pw_blocked_by_waf = pw_status_str.startswith('launched_blocked')

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

    source_extra_note = ''
    if dm_source_is_legal and dm_source_type != 'impressum_page':
        source_extra_note = ' DM identified from legal/terms document — verify active operational role via LinkedIn before outbound.'
    elif dm_source_type in ('product_or_service_page', 'blog_or_press_page'):
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
            confidence_warning = f'Warning: Deep browser scan blocked by WAF ({pw_status_str}); retry with residential proxy or enrich via LinkedIn.'
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
    elif not all_signals:
        if dm_name:
            readiness_verdict = f'Tech-Unverified + DM Known ({dm_name} Found; Tracking Gated by Consent or Absent — Verify Manually)'
        else:
            readiness_verdict = 'Tech-Unverified (No Tracking Signals Detected in Static HTML — Manual Check Needed)'
    elif dm_name and is_same_person_email:
        readiness_verdict = 'Sales-Ready Tier 1 (Verified Decision-Maker + Matching Direct Email)'
    elif best_email_type == 'marketing_or_exec_role':
        readiness_verdict = 'Sales-Ready Tier 2 (Direct Marketing / Executive Role Inbox)'
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

    phone_note = f' or call {primary_phone}' if primary_phone else ' (no public phone listed)'
    has_real_signals = bool(all_signals)
    stack_ref_clause = (
        f' referencing detected stack ({detected_signals_str})'
        if has_real_signals
        else ' to initiate B2B discovery (verify tracking stack manually first)'
    )

    if is_agency:
        next_action = f"Route to Agency Partnership pipeline; reach out via {best_email or linkedin_url or 'LinkedIn'}{phone_note}"
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
            f"{stack_ref_clause}"
        )
    elif best_email_type in (
        'customer_support_inbox', 'pr_and_media_inbox', 'wholesale_or_sales_inbox',
        'regional_branch_inbox', 'admissions_or_department_inbox', 'legal_or_hr_inbox',
        'department_or_general_inbox', 'influencer_gifting_inbox'
    ):
        dm_hint = f" ({dm_name})" if dm_name else ""
        next_action = (
            f"DO NOT send cold marketing pitch to {best_email} ({best_email_type}); "
            f"locate Marketing Lead / DM{dm_hint} via decision_maker_search_query on LinkedIn{phone_note}"
        )
    elif best_email_type == 'b2b_partnerships':
        if dm_name:
            next_action = (
                f"Send partnership/referral inquiry to {best_email} asking for introduction to Head of Marketing/Analytics "
                f"(or contact {dm_name} [{dm_role}] via LinkedIn{phone_note})"
            )
        else:
            next_action = (
                f"Send partnership/referral inquiry to {best_email} asking for introduction to Head of Marketing/Analytics; "
                f"NO DM found on site — use decision_maker_search_query on LinkedIn to find CMO/Head of Marketing first{phone_note}"
            )
    elif best_email_type == 'marketing_or_exec_role':
        next_action = (
            f"Send tailored discovery audit offer to {best_email} ({best_email_type})"
            f"{stack_ref_clause}"
        )
    elif best_email_type in ('general_office_inbox', 'brand_webmail_general_inbox', 'brand_webmail_support_inbox'):
        dm_hint = f" ({dm_name})" if dm_name else ""
        next_action = (
            f"Locate CMO / Head of E-commerce{dm_hint} via decision_maker_search_query on LinkedIn first; "
            f"use {best_email} only for warm gatekeeper routing / referral request"
        )
    elif primary_phone:
        next_action = f"Use decision_maker_search_query on LinkedIn or call {primary_phone} for routing"
    else:
        next_action = (
            f"Run decision_maker_search_query in LinkedIn / Apollo to locate marketing decision-maker{phone_note}"
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
    dm_role = seed.get('decision_maker_role')
    dm_src = seed.get('decision_maker_source_url')
    dm_src_type = seed.get('decision_maker_source_type') or classify_dm_source_type(dm_src)
    li_url = seed.get('linkedin_url')

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
        'all_ga4_ids': seed.get('all_ga4_ids'),
        'ga4_detection_confidence': seed.get('ga4_detection_confidence', 'Verified (Manual Audit Seed)'),
        'detected_cms_list': [x.strip() for x in (seed.get('detected_cms') or '').split(';') if x.strip()],
        'detected_cms': seed.get('detected_cms'),
        'has_cookie_banner': bool(seed.get('consent_mode_likely', False)),
        'detected_technologies_list': seed_tech_list,
        'technology_evidence': seed.get('technology_evidence', 'Verified via manual_seed'),
        'technology_evidence_summary': seed.get('technology_evidence_summary', 'GTM, GA4, Meta Pixel (Manual Seed)'),
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
        'not_attempted_manual_seed'
    )

    deliv_str = seed.get(
        'email_deliverability_check',
        'domain_accepts_email (Google Workspace; MX_found; SPF_present; verified_manual_seed)'
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
        'sales_readiness_verdict': sales_readiness_verdict,
        'company_category': cat,
        'category_confidence': cat_conf,
        'marketplace_platform': bool(seed.get('marketplace_platform', canonical_domain in KNOWN_MARKETPLACE_DOMAINS)),
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
        'decision_makers_found': seed.get('decision_makers_found') or (
            f'{dm_name} ({dm_role}) [{dm_src}]' if dm_name else None
        ),
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
        'sales_opportunity': sales_opportunity,
        'next_best_action': next_best_action,
        'technology_evidence_summary': tech_info['technology_evidence_summary'],
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
        'all_ga4_ids': tech_info['all_ga4_ids'],
        'detected_technologies': seed.get('detected_technologies'),
        'all_emails': seed.get('all_emails', best_email),
        'all_phones': seed.get('all_phones', primary_phone),
        'last_checked_at': verified_at
    }
