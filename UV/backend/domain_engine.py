# domain_engine.py
"""
Domain Heuristics, Subdomain Brand Impersonation, and Machine Learning Phishing Detection Engine.
"""
# Auto-reloaded with updated trusted domains allowlist
import os
import re
import math
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
import tldextract
import requests
import pandas as pd
from datetime import datetime, timezone

from config import (
    FRAUD_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    WHOIS_TIMEOUT,
    SHORTENED_URL_TIMEOUT,
    NEW_DOMAIN_DAYS_THRESHOLD,
    NEW_DOMAIN_BOOST,
    SHARED_HOSTING_IMPERSONATION_BOOST
)
from schemas import ScanVerdictResponse
from cross_channel_memory import threat_memory
from reason_messages import get_display_messages

logger = logging.getLogger(__name__)

# --- 1. Trusted Domains Allowlist ---

def _load_trusted_domains(path: str = "data/trusted_domains.txt") -> Set[str]:
    """
    Loads trusted domains set once at startup.
    Resolves relative to backend root directory.
    """
    resolved_path = Path(__file__).parent / path
    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            domains = set(line.strip().lower() for line in f if line.strip() and not line.startswith("#"))
            logger.info(f"Loaded {len(domains)} trusted domains from {resolved_path}")
            return domains
    except FileNotFoundError:
        logger.warning(f"trusted_domains.txt not found at {resolved_path} — allowlist will be empty")
        return set()

TRUSTED_DOMAINS: Set[str] = _load_trusted_domains()

def check_trusted_domain(registered_domain: str) -> bool:
    """Checks if a registered domain is in the pre-loaded trusted allowlist."""
    return registered_domain.lower() in TRUSTED_DOMAINS

# --- 2. Subdomain Brand Impersonation Definitions ---

BRAND_OFFICIAL_DOMAINS: Dict[str, str] = {
    # Global brands
    "google": "google.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "chase": "chase.com",
    "pinterest": "pinterest.com",
    "twitter": "twitter.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "whatsapp": "whatsapp.com",

    # India-specific — highest relevance to threat model
    "sbi": "sbi.co.in",
    "onlinesbi": "onlinesbi.sbi",
    "hdfc": "hdfcbank.com",
    "hdfcbank": "hdfcbank.com",
    "icici": "icicibank.com",
    "icicibank": "icicibank.com",
    "axis": "axisbank.com",
    "axisbank": "axisbank.com",
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "googlepay": "pay.google.com",
    "gpay": "pay.google.com",
    "kotak": "kotak.com",
    "pnb": "pnbindia.in",
    "bob": "bankofbaroda.in",
    "irctc": "irctc.co.in",
    "uidai": "uidai.gov.in",
    "incometax": "incometax.gov.in"
}

URGENCY_KEYWORDS_SUBDOMAIN: Set[str] = {
    "verify", "secure", "update", "kyc", "login", "confirm",
    "account", "alert", "suspended", "reactivate", "unlock",
    "auth", "recover", "dispute", "support", "portal", "rewards", "claim"
}

def check_subdomain_for_brand_impersonation(subdomain: str, registered_domain: str) -> List[str]:
    """
    Checks whether a brand name appears in the SUBDOMAIN or registered domain,
    while the actual registered domain does NOT belong to that brand.
    """
    flags = []
    sub_lower = subdomain.lower()
    combined_target = f"{subdomain} {registered_domain}".lower().replace("-", " ").replace(".", " ")

    matched_brand = None
    for brand, official_domain in BRAND_OFFICIAL_DOMAINS.items():
        if (subdomain and brand in sub_lower) or brand in combined_target.split():
            if registered_domain != official_domain and not registered_domain.endswith(f".{official_domain}"):
                matched_brand = brand
                flags.append("brand_name_in_subdomain")
                break

    has_urgency = any(kw in f"{subdomain} {registered_domain}".lower() for kw in URGENCY_KEYWORDS_SUBDOMAIN)
    if has_urgency:
        flags.append("urgency_keyword_in_subdomain")

    # Combined signal
    if matched_brand and has_urgency:
        flags.append(f"impersonates_{matched_brand}")
    elif matched_brand:
        flags.append(f"impersonates_{matched_brand}")

    return list(dict.fromkeys(flags))

# --- 3. Sets & Heuristics Constants ---

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "rest", "buzz", "site", "online",
    "work", "tech", "icu", "club", "info", "tk", "cf", "gq",
    "shop", "live", "link", "guru", "pw", "cc"
}

SUSPICIOUS_KEYWORDS = {
    "secure", "login", "verify", "update", "banking", "kyc",
    "account", "auth", "confirm", "wallet", "suspend", "portal",
    "signin", "support", "recover", "dispute", "alert", "service",
    "pan", "aadhaar", "ebanking", "netbanking", "billpay", "rewards"
}

TARGET_BRANDS = set(BRAND_OFFICIAL_DOMAINS.keys())

SHARED_HOSTING_SUFFIXES = {
    "vercel.app", "netlify.app", "github.io", "web.app", "firebaseapp.com",
    "pages.dev", "herokuapp.com", "000webhostapp.com", "weebly.com",
    "wixsite.com", "blogspot.com", "glitch.me", "repl.co", "surge.sh",
    "workers.dev", "ngrok-free.app", "render.com"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly", "rb.gy", "tiny.cc"
}

WHOIS_CACHE: Dict[str, Dict[str, Any]] = {}

# --- 4. Utility Functions & Feature Extraction ---

def shannon_entropy(string: str) -> float:
    if not string:
        return 0.0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(string)]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def is_shared_hosting(domain: str, subdomain: str) -> bool:
    """Checks if the registered or full domain resolves to a known shared platform."""
    registered = domain.lower() if domain else ""
    return any(registered.endswith(suffix) for suffix in SHARED_HOSTING_SUFFIXES)

def is_shortened_url(domain: str) -> bool:
    """Checks if the domain is a known URL shortener."""
    domain_clean = str(domain).lower().strip()
    return domain_clean in KNOWN_SHORTENERS

def expand_shortened_url(url: str, timeout: float = SHORTENED_URL_TIMEOUT) -> Dict[str, Any]:
    """
    Resolves multi-hop shortened links with explicit timeout.
    Uses stream=True GET with standard browser headers to handle shorteners (like Bitly)
    that reject HTTP HEAD requests with 405 Method Not Allowed.
    """
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str
    try:
        session = requests.Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        resp = session.get(url_str, stream=True, allow_redirects=True, timeout=timeout, headers=headers)
        final_url = resp.url
        resp.close()
        return {"resolved": True, "final_url": final_url}
    except Exception as e:
        logger.debug(f"Failed expanding shortened URL {url_str}: {e}")
        return {"resolved": False, "final_url": url_str, "error": str(e)}

def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extracts exactly 16 numeric features in identical order/definition to training time.
    Fails open to all zeros on malformed/empty/None input without raising.
    """
    default_zeros = {
        "url_length": 0, "domain_length": 0, "has_ip": 0, "is_suspicious_tld": 0,
        "hyphen_count": 0, "dot_count": 0, "digit_count": 0, "special_char_count": 0,
        "shannon_entropy": 0.0, "has_punycode": 0, "has_port": 0, "keyword_match_count": 0,
        "brand_match_count": 0, "subdomain_count": 0, "path_depth": 0, "domain_hyphens": 0
    }
    if not url or not isinstance(url, str):
        return default_zeros

    try:
        url_clean = url.strip()
        extracted = tldextract.extract(url_clean)
        registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

        has_ip = 1 if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", extracted.domain) else 0
        is_susp_tld = 1 if extracted.suffix.lower() in SUSPICIOUS_TLDS else 0
        has_puny = 1 if "xn--" in url_clean.lower() else 0
        has_port = 1 if re.search(r":\d{2,5}(/|$)", url_clean) else 0

        kw_matches = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_clean.lower())
        brand_matches = sum(1 for brand in TARGET_BRANDS if brand in url_clean.lower())
        sub_count = len(extracted.subdomain.split(".")) if extracted.subdomain else 0

        path_part = url_clean.split("/", 3)[-1] if "/" in url_clean.replace("://", "") else ""
        path_depth = len([p for p in path_part.split("?")[0].split("/") if p])

        domain_hyphens = extracted.domain.count("-")
        special_chars = sum(1 for c in url_clean if c in "-_?=&%#@!+~")

        return {
            "url_length": len(url_clean),
            "domain_length": len(registered_domain),
            "has_ip": has_ip,
            "is_suspicious_tld": is_susp_tld,
            "hyphen_count": url_clean.count("-"),
            "dot_count": url_clean.count("."),
            "digit_count": sum(1 for c in url_clean if c.isdigit()),
            "special_char_count": special_chars,
            "shannon_entropy": round(shannon_entropy(url_clean), 4),
            "has_punycode": has_puny,
            "has_port": has_port,
            "keyword_match_count": kw_matches,
            "brand_match_count": brand_matches,
            "subdomain_count": sub_count,
            "path_depth": path_depth,
            "domain_hyphens": domain_hyphens
        }
    except Exception as e:
        logger.warning(f"Error extracting features for {url}: {e}")
        return default_zeros

def check_domain_age(url: str) -> Dict[str, Any]:
    """
    Queries domain creation date via WHOIS with timeout and in-memory caching.
    Fails open safely to not penalize connection issues or shared platforms.
    """
    default_fail_open = {
        "age_days": 9999,
        "is_new": False,
        "trust_age_signal": False,
        "shared_hosting": False
    }

    try:
        extracted = tldextract.extract(url)
        registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()

        if is_shared_hosting(registered_domain, extracted.subdomain):
            return {
                "age_days": 9999,
                "is_new": False,
                "trust_age_signal": False,
                "shared_hosting": True
            }

        if registered_domain in WHOIS_CACHE:
            return WHOIS_CACHE[registered_domain]

        import whois
        w = whois.whois(registered_domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and isinstance(creation_date, datetime):
            now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.now()
            age_days = (now - creation_date).days
            is_new = age_days < NEW_DOMAIN_DAYS_THRESHOLD
            result = {
                "age_days": age_days,
                "is_new": is_new,
                "trust_age_signal": not is_new,
                "shared_hosting": False
            }
            WHOIS_CACHE[registered_domain] = result
            return result
    except Exception as e:
        logger.debug(f"WHOIS check failed for {url}: {e}")

    return default_fail_open

# --- 5. Main Orchestration Engine ---

def get_domain_verdict(url: str, model: Any) -> ScanVerdictResponse:
    """
    Main orchestration function for domain inspection.
    Step 1: Checks Trusted Domain Allowlist (instant O(1) short-circuit).
    Step 2: Subdomain Brand Impersonation & Shared Hosting Check.
    Step 3: ML Model Inference & Lexical Tags.
    Step 4: Central Reason-to-Display Mapping.
    """
    try:
        if not url or not isinstance(url, str):
            reasons = ["scan_error_failed_open"]
            return ScanVerdictResponse(
                verdict="SAFE",
                confidence=0.0,
                reasons=reasons,
                display_reasons=get_display_messages(reasons),
                detail="Empty or malformed URL passed",
                source="domain",
                status_code=200
            )

        target_url = url.strip()
        ext = tldextract.extract(target_url)
        domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        registered_domain = f"{domain}.{ext.suffix}".lower() if ext.suffix else domain

        # =========================================================================
        # STEP 1: Instant Trusted Domain Allowlist Check
        # =========================================================================
        if check_trusted_domain(registered_domain):
            reasons = ["known_trusted_domain"]
            return ScanVerdictResponse(
                verdict="SAFE",
                confidence=0.02,
                reasons=reasons,
                display_reasons=get_display_messages(reasons),
                detail="Known verified trusted website",
                source="domain",
                status_code=200
            )

        reasons: List[str] = []
        confidence = 0.0

        # Cross-Channel Check: Active SMS smishing campaign linkage
        in_smish_campaign, campaign_note = threat_memory.check_url_in_sms_campaign(target_url)
        if in_smish_campaign and campaign_note:
            reasons.append("cross_channel_lure")

        # Step 1b: Expand URL Shorteners
        if is_shortened_url(registered_domain):
            expanded = expand_shortened_url(target_url)
            if expanded["resolved"]:
                target_url = expanded["final_url"]
                reasons.append("shortened_url_expanded")
                ext = tldextract.extract(target_url)
                domain = ext.domain.lower()
                subdomain = ext.subdomain.lower()
                registered_domain = f"{domain}.{ext.suffix}".lower() if ext.suffix else domain
                if check_trusted_domain(registered_domain):
                    return ScanVerdictResponse(
                        verdict="SAFE",
                        confidence=0.02,
                        reasons=["known_trusted_domain"],
                        display_reasons=get_display_messages(["known_trusted_domain"]),
                        detail="Known verified trusted website",
                        source="domain",
                        status_code=200
                    )
            else:
                reasons.append("shortened_url_unresolvable")
                return ScanVerdictResponse(
                    verdict="SUSPICIOUS",
                    confidence=0.65,
                    reasons=reasons,
                    display_reasons=get_display_messages(reasons),
                    detail="Shortened URL with unresolvable destination",
                    source="domain",
                    status_code=200
                )

        # Step 2: Feature Extraction & ML Model Scoring
        features_dict = extract_url_features(target_url)
        df_features = pd.DataFrame([features_dict])

        if model is not None:
            if hasattr(model, "feature_names_in_"):
                df_features = df_features.reindex(columns=model.feature_names_in_, fill_value=0)
            confidence = float(model.predict_proba(df_features)[0][1])

        # Step 3: Domain Age / Shared Hosting & Subdomain Brand Impersonation
        age_info = check_domain_age(target_url)

        if age_info.get("shared_hosting"):
            impersonation_flags = check_subdomain_for_brand_impersonation(subdomain, registered_domain)
            if impersonation_flags:
                confidence = min(confidence + SHARED_HOSTING_IMPERSONATION_BOOST, 1.0)
                reasons.extend(impersonation_flags)
            else:
                reasons.append("hosted_on_shared_platform")
        elif age_info.get("is_new"):
            confidence = min(confidence + NEW_DOMAIN_BOOST, 1.0)
            age_days = age_info.get("age_days", 0)
            reasons.append("newly_registered_domain")
            reasons.append(f"domain_age_{age_days}_days")
        else:
            impersonation_flags = check_subdomain_for_brand_impersonation(subdomain, registered_domain)
            if impersonation_flags:
                confidence = min(confidence + 0.35, 1.0)
                reasons.extend(impersonation_flags)

        # Step 4: Lexical Rule Flags
        if features_dict.get("is_suspicious_tld"):
            reasons.append("high_risk_tld")
            confidence = min(confidence + 0.30, 1.0)
        if features_dict.get("has_ip"):
            reasons.append("Direct IP host with no registered domain name")
            confidence = min(confidence + 0.40, 1.0)
        if features_dict.get("has_punycode"):
            reasons.append("homoglyph_obfuscation")
            confidence = min(confidence + 0.35, 1.0)
        if features_dict.get("domain_hyphens", 0) >= 2:
            reasons.append("homoglyph_obfuscation")
            confidence = min(confidence + 0.20, 1.0)
        if features_dict.get("keyword_match_count", 0) > 0 and not any("urgency" in r for r in reasons):
            reasons.append("suspicious_keywords")
            confidence = min(confidence + 0.20, 1.0)
        if features_dict.get("brand_match_count", 0) > 0 and not any("impersonat" in r for r in reasons):
            matched = [b.lower() for b in TARGET_BRANDS if b in target_url.lower()]
            if matched and registered_domain != BRAND_OFFICIAL_DOMAINS.get(matched[0]):
                reasons.append(f"impersonates_{matched[0]}")
                confidence = min(confidence + 0.35, 1.0)
        if not target_url.lower().startswith("https://"):
            reasons.append("insecure_connection")

        if in_smish_campaign:
            confidence = max(confidence, 0.92)

        # Step 5: Final Verdict Categorization
        confidence = round(float(confidence), 2)
        if confidence > FRAUD_THRESHOLD:
            verdict = "FRAUD"
            detail = "High-risk credential harvesting or malicious domain detected"
        elif confidence > SUSPICIOUS_THRESHOLD:
            verdict = "SUSPICIOUS"
            detail = "Suspicious domain signals detected"
        else:
            verdict = "SAFE"
            detail = "Domain analyzed successfully - verified clean"

        unique_reasons = list(dict.fromkeys(reasons))
        display_reasons = get_display_messages(unique_reasons)

        return ScanVerdictResponse(
            verdict=verdict,
            confidence=confidence,
            reasons=unique_reasons,
            display_reasons=display_reasons,
            detail=detail,
            source="domain",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Unexpected error in get_domain_verdict for {url}: {e}", exc_info=True)
        fallback_reasons = ["scan_error_failed_open"]
        return ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=fallback_reasons,
            display_reasons=get_display_messages(fallback_reasons),
            detail="Scan completed with fail-open fallback",
            source="domain",
            status_code=200
        )

# Backward compatibility alias
predict_url = get_domain_verdict
scan_domain = get_domain_verdict
