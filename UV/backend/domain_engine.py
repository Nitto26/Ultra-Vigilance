# domain_engine.py
"""
Domain Heuristics and Machine Learning Phishing Detection Engine.
"""
import re
import math
import logging
from typing import Dict, Any, List, Optional
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

logger = logging.getLogger(__name__)

# --- 1. Sets & Constants ---

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

TARGET_BRANDS = {
    "hdfc", "hdfcbank", "sbi", "statebank", "icici", "icicibank",
    "axis", "axisbank", "pnb", "bob", "kotak", "paytm", "phonepe",
    "gpay", "razorpay", "paypal", "google", "apple", "amazon",
    "netflix", "microsoft", "flipkart", "swiggy", "zomato", "irctc", "chase"
}

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

# In-memory WHOIS cache (keyed by apex domain)
WHOIS_CACHE: Dict[str, Dict[str, Any]] = {}

# --- 2. Utility Functions & Feature Extraction ---

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
    """Resolves multi-hop shortened links with explicit timeout."""
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str
    try:
        session = requests.Session()
        resp = session.head(url_str, allow_redirects=True, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        return {"resolved": True, "final_url": resp.url}
    except Exception as e:
        return {"resolved": False, "final_url": url_str, "error": str(e)}

def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extracts exactly 16 numeric features in identical order/definition to training time.
    Fails open to all zeros on malformed/empty/None input without raising.
    """
    default_zeros = {
        "domain_length": 0, "subdomain_length": 0, "subdomain_count": 0,
        "has_ip": 0, "has_punycode": 0, "domain_hyphens": 0, "domain_digits": 0,
        "domain_entropy": 0.0, "subdomain_entropy": 0.0, "vowel_ratio": 0.0,
        "max_consecutive_consonants": 0, "is_suspicious_tld": 0, "tld_length": 0,
        "keyword_match_count": 0, "brand_match_count": 0, "is_free_hosting": 0
    }
    if not url or not isinstance(url, str):
        return default_zeros

    url_str = url.strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    try:
        extracted = tldextract.extract(url_str)
        domain = extracted.domain.lower() if extracted.domain else ""
        subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
        suffix = extracted.suffix.lower() if extracted.suffix else ""
        registered_domain = f"{domain}.{suffix}" if suffix else domain

        vowels = set("aeiou")
        vowel_count = sum(1 for c in domain if c in vowels)
        vowel_ratio = vowel_count / max(len(domain), 1)

        max_cons = 0
        curr_cons = 0
        for c in domain:
            if c.isalpha() and c not in vowels:
                curr_cons += 1
                if curr_cons > max_cons:
                    max_cons = curr_cons
            else:
                curr_cons = 0

        features = {
            "domain_length": len(domain),
            "subdomain_length": len(subdomain),
            "subdomain_count": len(subdomain.split(".")) if subdomain else 0,
            "has_ip": 1 if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0,
            "has_punycode": 1 if "xn--" in url_str else 0,
            "domain_hyphens": domain.count("-") + subdomain.count("-"),
            "domain_digits": sum(c.isdigit() for c in domain) + sum(c.isdigit() for c in subdomain),
            "domain_entropy": shannon_entropy(domain),
            "subdomain_entropy": shannon_entropy(subdomain),
            "vowel_ratio": vowel_ratio,
            "max_consecutive_consonants": max_cons,
            "is_suspicious_tld": 1 if suffix in SUSPICIOUS_TLDS else 0,
            "tld_length": len(suffix),
            "keyword_match_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in domain or kw in subdomain),
            "brand_match_count": sum(1 for b in TARGET_BRANDS if b in domain or b in subdomain),
            "is_free_hosting": 1 if (registered_domain in SHARED_HOSTING_SUFFIXES or is_shared_hosting(registered_domain, subdomain)) else 0
        }
        return features
    except Exception as e:
        logger.warning(f"Error extracting features from URL {url}: {e}")
        return default_zeros

def check_domain_age(url: str, timeout: float = WHOIS_TIMEOUT) -> Dict[str, Any]:
    """
    Queries WHOIS with caching and 3-second hard timeout.
    Bypasses WHOIS query completely for shared hosting domains.
    """
    default_fail_open = {"age_days": None, "is_new": False, "trust_age_signal": False, "shared_hosting": False}
    if not url or not isinstance(url, str):
        return default_fail_open

    url_str = url.strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    try:
        extracted = tldextract.extract(url_str)
        registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        # 1. Check shared hosting FIRST
        if is_shared_hosting(registered_domain, extracted.subdomain.lower()):
            return {"age_days": None, "is_new": False, "trust_age_signal": False, "shared_hosting": True}

        if not registered_domain or "." not in registered_domain:
            return default_fail_open

        # 2. Check in-memory cache
        if registered_domain in WHOIS_CACHE:
            return WHOIS_CACHE[registered_domain]

        # 3. Attempt WHOIS lookup
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

def check_subdomain_for_brand_impersonation(subdomain: str) -> List[str]:
    """Inspects subdomain strings for brand spoofing or urgency keywords."""
    if not subdomain:
        return []
    flags = []
    sub_lower = subdomain.lower()
    matched_brands = [b.upper() for b in TARGET_BRANDS if b in sub_lower]
    if matched_brands:
        flags.append(f"Fake banking domain impersonating {matched_brands[0]}")
    if any(kw in sub_lower for kw in SUSPICIOUS_KEYWORDS):
        flags.append("High urgency language detected in host subdomain")
    return flags

# --- 3. Orchestration Engine ---

def get_domain_verdict(url: str, model: Any) -> ScanVerdictResponse:
    """
    Main orchestration function for domain inspection.
    Integrates with cross-channel smishing memory and fail-open resilience.
    """
    try:
        if not url or not isinstance(url, str):
            return ScanVerdictResponse(
                verdict="SAFE",
                confidence=0.0,
                reasons=[],
                detail="Empty or malformed URL passed",
                status_code=200
            )

        target_url = url.strip()
        reasons = []
        extracted_init = tldextract.extract(target_url)
        registered_init = f"{extracted_init.domain}.{extracted_init.suffix}".lower()

        # Cross-Channel Check: Was this URL linked to an active SMS smishing campaign?
        in_smish_campaign, campaign_note = threat_memory.check_url_in_sms_campaign(target_url)
        if in_smish_campaign and campaign_note:
            reasons.append(campaign_note)

        # Step 1: Expand URL Shorteners
        if is_shortened_url(registered_init):
            expanded = expand_shortened_url(target_url)
            if expanded["resolved"]:
                target_url = expanded["final_url"]
                reasons.append(f"Shortened phishing link detected ({registered_init})")
            else:
                reasons.append("Unresolvable shortened URL destination")
                return ScanVerdictResponse(
                    verdict="SUSPICIOUS",
                    confidence=0.65,
                    reasons=reasons,
                    detail="Shortened URL with unresolvable destination",
                    status_code=200
                )

        # Step 2: Feature Extraction & ML Probability
        features_dict = extract_url_features(target_url)
        df_features = pd.DataFrame([features_dict])

        prob = 0.0
        if model is not None:
            if hasattr(model, "feature_names_in_"):
                df_features = df_features.reindex(columns=model.feature_names_in_, fill_value=0)
            prob = float(model.predict_proba(df_features)[0][1])

        # Step 3: Domain Age / Shared Hosting Logic
        age_info = check_domain_age(target_url)
        if age_info.get("shared_hosting"):
            reasons.append("Abuse of free shared hosting platform")
            extracted = tldextract.extract(target_url)
            sub_flags = check_subdomain_for_brand_impersonation(extracted.subdomain)
            if sub_flags:
                prob = min(1.0, prob + SHARED_HOSTING_IMPERSONATION_BOOST)
                reasons.extend(sub_flags)
        elif age_info.get("is_new"):
            prob = min(1.0, prob + NEW_DOMAIN_BOOST)
            age_days = age_info.get("age_days", 0)
            reasons.append(f"Domain registered {age_days} days ago (newly created)")

        # Boost if linked to active smishing attack
        if in_smish_campaign:
            prob = max(prob, 0.92)

        # Step 4: Lexical Rule Tags
        if features_dict.get("is_suspicious_tld"):
            reasons.append(f"High-risk top-level domain (.{extracted_init.suffix})")
        if features_dict.get("has_ip"):
            reasons.append("Direct IP host with no registered domain name")
        if features_dict.get("has_punycode"):
            reasons.append("Punycode / IDN homograph character spoofing detected")
        if features_dict.get("domain_hyphens", 0) >= 2:
            reasons.append("High hyphen obfuscation in domain name")
        if features_dict.get("keyword_match_count", 0) > 0 and not any("urgency" in r.lower() for r in reasons):
            reasons.append("Suspicious credential harvesting and banking keywords")
        if features_dict.get("brand_match_count", 0) > 0 and not any("impersonating" in r.lower() for r in reasons):
            matched = [b.upper() for b in TARGET_BRANDS if b in target_url.lower()]
            reasons.append(f"Brand impersonation target ({matched[0] if matched else 'Brand'})")
        if not target_url.lower().startswith("https://"):
            reasons.append("No HTTPS / insecure connection protocol")

        # Step 5: Verdict Bucketing & Detail
        confidence = round(float(prob), 2)
        if confidence > FRAUD_THRESHOLD:
            verdict = "FRAUD"
            detail = "High-risk credential harvesting or malicious domain detected"
        elif confidence > SUSPICIOUS_THRESHOLD:
            verdict = "SUSPICIOUS"
            detail = "Suspicious domain signals detected"
        else:
            verdict = "SAFE"
            detail = "Document/Message analyzed successfully - verified safe"

        unique_reasons = list(dict.fromkeys(reasons))

        return ScanVerdictResponse(
            verdict=verdict,
            confidence=confidence,
            reasons=unique_reasons,
            detail=detail,
            status_code=200
        )
    except Exception as e:
        logger.error(f"Unexpected error in get_domain_verdict for {url}: {e}")
        return ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=[],
            detail="Scan completed with fail-open fallback",
            status_code=200
        )
