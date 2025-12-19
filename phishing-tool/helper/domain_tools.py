from __future__ import annotations
import difflib
import re
import unicodedata
from typing import List
import idna
import tldextract

# Regex to pull domains from text/URLs
_DOMAIN_REGEX = re.compile(r"https?://([^/\s]+)")

# 100+ high‑value brands often impersonated in phishing [web:20]
TRUSTED_BRANDS: List[str] = [
    "paypal.com", "microsoft.com", "amazon.com", "apple.com", "google.com",
    "att.com", "dhl.com", "fedex.com", "ups.com", "usps.com",
    "netflix.com", "bankofamerica.com", "chase.com", "wellsfargo.com",
    "citibank.com", "outlook.com", "office.com", "dropbox.com", "zoom.us",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "ebay.com", "yahoo.com", "gmail.com", "icloud.com",
    "spotify.com", "adobe.com", "docusign.com", "steamcommunity.com",
    "verizon.com", "tmobile.com", "comcast.com",
    "walmart.com", "target.com", "costco.com", "homedepot.com",
    "bestbuy.com", "lowes.com", "macys.com", "nordstrom.com",
    "americanexpress.com", "visa.com", "mastercard.com",
    "capitalone.com", "discover.com", "usbank.com", "pnc.com",
    "td.com", "tdbank.com", "truist.com", "regions.com",
    "huntington.com", "53.com", "key.com",
    "zellepay.com", "venmo.com", "cash.app", "squareup.com",
    "stripe.com", "shopify.com", "etsy.com", "airbnb.com",
    "uber.com", "lyft.com", "doordash.com", "ubereats.com",
    "instacart.com", "grubhub.com", "postmates.com",
    "amazonaws.com", "aws.amazon.com", "azure.com", "cloudflare.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "slack.com", "discord.com", "teams.microsoft.com",
    "salesforce.com", "zendesk.com", "hubspot.com",
    "mailchimp.com", "constantcontact.com",
    "intuit.com", "quickbooks.intuit.com", "xero.com",
    "box.com", "onedrive.live.com",
    "okta.com", "onelogin.com", "duosecurity.com",
    "oracle.com", "sap.com", "servicenow.com",
    "adp.com", "workday.com",
    "royalmail.com", "hermesworld.com", "yodel.co.uk",
]


def extract_domains(text: str) -> List[str]:

    return _DOMAIN_REGEX.findall(text or "")


def _normalize_domain(domain: str) -> str:

    domain = (domain or "").strip().lower().rstrip(".")
    extracted = tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        domain = f"{extracted.domain}.{extracted.suffix}"
    try:
        return idna.encode(domain).decode("ascii")
    except Exception:
        return domain


def has_punycode(text: str) -> bool:
    return "xn--" in (text or "").lower()


def detect_confusable_basic(domain_text: str) -> str:

    domain_text = domain_text or ""
    # Decompose characters (NFKD) then drop all combining marks.
    normalized = unicodedata.normalize("NFKD", domain_text)
    skeleton_chars = []
    for ch in normalized:
        # Drop diacritics / combining marks
        if unicodedata.category(ch) == "Mn":
            continue
        skeleton_chars.append(ch)
    skeleton = "".join(skeleton_chars).lower().rstrip(".")
    return skeleton


def is_lookalike_domain(test_domain: str, brand: str, threshold: float = 0.85) -> bool:

    if not test_domain or not brand:
        return False

    norm_test = _normalize_domain(test_domain)
    norm_brand = _normalize_domain(brand)

    # Confusable skeletons
    skel_test = detect_confusable_basic(norm_test)
    skel_brand = detect_confusable_basic(norm_brand)

    # Compare both raw normalized and skeleton
    raw_ratio = difflib.SequenceMatcher(None, norm_test, norm_brand).ratio()
    skel_ratio = difflib.SequenceMatcher(None, skel_test, skel_brand).ratio()

    return max(raw_ratio, skel_ratio) >= threshold


def domain_mismatch(sender: str, body_text: str, trusted_brands: List[str] | None = None) -> bool:

    if trusted_brands is None:
        trusted_brands = TRUSTED_BRANDS

    sender_norm = _normalize_domain(sender)
    body_domains = extract_domains(body_text)

    mismatch_flag = False
    lookalike_flag = False

    for d in body_domains:
        d_norm = _normalize_domain(d)
        if d_norm and sender_norm and d_norm != sender_norm:
            mismatch_flag = True

        # Lookalike / confusable check vs brand list
        for brand in trusted_brands:
            if is_lookalike_domain(d_norm, brand):
                lookalike_flag = True
                break
        if lookalike_flag:
            break

    return mismatch_flag or lookalike_flag
