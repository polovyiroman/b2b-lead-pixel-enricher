# B2B Lead, Email, Socials & Ad Pixel Enricher

A fast, low-memory Apify Actor engineered for **marketing agencies, B2B sales teams, and Clay/CRM workflows**. It enriches company domains with **prioritized decision-maker/sales emails, validated E.164 phone numbers, social media profiles, website metadata, CMS platforms, and advertising pixels** — without the high cost of a headless browser.

## Why Sales & Marketing Teams Use This Actor

1. **CRM & CSV Ready (Flat Fields):** Alongside full arrays, every record includes flat fields (`best_email`, `primary_phone`, `linkedin_url`, `instagram_url`, `facebook_url`, `page_title`, `meta_description`) ready for instant import into Instantly, Smartlead, HubSpot, or Clay.
2. **Smart B2B Email Ranking:** Automatically prioritizes high-value inboxes (`sales@`, `hello@`, `contact@`, and custom domain emails) while pushing compliance/legal addresses (`privacy@`, `legal@`, `datenschutz@`, `dpo@`, `jobs@`) to the bottom.
3. **GTM & Shopify Hidden Pixel Detection:** Inspects raw `GTM-XXXXXX` container scripts and Shopify `Trekkie` / Web Pixels Manager configs to accurately detect **Meta Pixel, TikTok Pixel, Google Ads, LinkedIn Insight Tag, Klaviyo, and GA4**.
4. **Cloudflare Email De-obfuscation:** Automatically decodes `[email protected]` (`data-cfemail`) hex-encoded emails.
5. **Google `libphonenumber` Validation:** Formats real numbers into standard `E.164` (`+14155552671`), eliminating false-positive dates, CSS values, and product IDs.

## Output Example

```json
{
  "input_domain": "example.com",
  "website_url": "[https://www.example.com/](https://www.example.com/)",
  "status": "success",
  "error_message": "",
  "page_title": "Example Corp | B2B SaaS & Marketing Automation",
  "meta_description": "We help e-commerce brands scale with automated workflows.",
  "best_email": "sales@example.com",
  "primary_phone": "+14155552671",
  "linkedin_url": "[https://www.linkedin.com/company/example](https://www.linkedin.com/company/example)",
  "instagram_url": "[https://www.instagram.com/example](https://www.instagram.com/example)",
  "facebook_url": null,
  "has_meta_pixel": true,
  "has_tiktok_pixel": false,
  "has_google_ads": true,
  "has_linkedin_pixel": true,
  "has_ga4": true,
  "has_gtm": true,
  "gtm_container_ids": ["GTM-ABC1234"],
  "detected_technologies": [
    "Google Tag Manager",
    "Google Analytics (GA4)",
    "Google Ads Conversion",
    "Meta Pixel (Facebook)",
    "LinkedIn Insight Tag",
    "HubSpot",
    "Webflow"
  ],
  "emails": [
    "sales@example.com",
    "hello@example.com",
    "privacy@example.com"
  ],
  "phones": [
    "+14155552671"
  ],
  "socials": {
    "linkedin": "[https://www.linkedin.com/company/example](https://www.linkedin.com/company/example)",
    "instagram": "[https://www.instagram.com/example](https://www.instagram.com/example)"
  }
}