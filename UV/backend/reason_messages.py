# reason_messages.py
"""
Central mapping from internal reason codes to user-facing display text.
The mobile app and browser extension both pull from this via `display_reasons` field.
"""
from typing import List

REASON_MESSAGES = {
    "known_trusted_domain": "This is a well-known, trusted website.",
    "lexical_pattern_match": "This website's address has patterns commonly seen in scam sites.",
    "newly_registered_domain": "This website was registered very recently — often a sign of a scam site set up quickly.",
    "hosted_on_shared_platform": "This site is hosted on a free platform, so we checked its content more closely.",
    "brand_name_in_subdomain": "This web address is trying to look like a bank or well-known company, but isn't their real site.",
    "urgency_keyword_in_subdomain": "This web address uses urgent language often used to pressure people into acting quickly.",
    "shortened_url_expanded": "This was a shortened link — we checked the real destination before showing this result.",
    "shortened_url_unresolvable": "We couldn't verify where this shortened link actually leads — proceed with caution.",
    "scan_error_failed_open": "We couldn't fully verify this — proceed with caution.",
    "reported_fraud_upi_id": "This payment ID has been reported as fraudulent by other users.",
    "suspicious_gateway_url": "The payment page this links to shows signs of being fake.",
    "upi_id_with_payment_request": "This message asks you to send money to a payment ID — a common scam pattern.",
    "fake_account_alert_with_payment_ask": "This message claims your account has an issue and asks for payment — this is a very common scam pattern.",
    "high_risk_tld": "Uses an obscure or high-risk domain extension commonly associated with phishing campaigns.",
    "insecure_connection": "Insecure connection protocol (No HTTPS encryption).",
    "brand_impersonation": "Contains brand keywords on an unverified domain.",
    "homoglyph_obfuscation": "Uses lookalike characters or high hyphenation to deceive users.",
    "suspicious_keywords": "Contains banking or credential-harvesting keywords.",
    "cross_channel_lure": "Previously observed in a suspicious message or payment request.",
    "vpa_authority_impersonation": "Personal UPI ID impersonates bank customer support or verification desks.",
    "unverified_sender": "Sent from an unverified personal mobile number rather than an official bank header.",
    "urgency_panic_language": "Uses urgent panic phrasing attempting to rush unauthorized action."
}

def get_display_message(reason_code: str) -> str:
    """Translates a single reason code into a clean, human-readable sentence."""
    if reason_code in REASON_MESSAGES:
        return REASON_MESSAGES[reason_code]

    # Handle dynamic brand impersonation patterns (e.g. "impersonates_sbi")
    if reason_code.startswith("impersonates_"):
        brand = reason_code.replace("impersonates_", "").upper()
        return f"This site appears to be impersonating {brand}."

    # Handle dynamic domain age patterns (e.g. "domain_age_3_days")
    if reason_code.startswith("domain_age_"):
        parts = reason_code.replace("domain_age_", "").replace("_days", "")
        return f"This website is only {parts} days old."

    # If the reason is already a human sentence (starts with capital letter or contains spaces), return as is
    if " " in reason_code and not reason_code.islower():
        return reason_code

    # Fallback for any unmapped snake_case code — never show raw snake_case to the user
    clean_text = reason_code.replace("_", " ").capitalize()
    return f"{clean_text} detected."

def get_display_messages(reasons: List[str]) -> List[str]:
    """Convert a full reasons list into user-facing strings, in order without duplicates."""
    seen = set()
    result = []
    for r in reasons:
        msg = get_display_message(r)
        if msg not in seen:
            seen.add(msg)
            result.append(msg)
    return result
