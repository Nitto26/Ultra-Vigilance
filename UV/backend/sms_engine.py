# sms_engine.py
"""
SMS Pattern Analysis and Cross-Channel Domain Correlation Engine.
"""
import re
import logging
from typing import Dict, Any, List, Optional

from config import (
    FRAUD_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    RAW_PHONE_SENDER_BOOST,
    KNOWN_SHORTENER_BOOST,
    URGENCY_FINANCIAL_BOOST
)
from schemas import ScanVerdictResponse
from cross_channel_memory import threat_memory
from reason_messages import get_display_messages
import domain_engine

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"(https?://[^\s]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|site|online|club|app|dev|in|co|us|sh|ly|me|cc)(?:/[^\s]*)?)", re.IGNORECASE)
RAW_PHONE_PATTERN = re.compile(r"^(\+?\d{10,13}|\d{10})$")

URGENCY_KEYWORDS = {"urgent", "immediately", "blocked", "suspended", "terminate", "expire", "disconnected", "warning", "action required", "within 24 hours"}
FINANCIAL_KEYWORDS = {"bank", "kyc", "pan", "aadhaar", "otp", "debit", "credit", "account", "refund", "bill", "power cut", "reward", "cashback", "loan", "fine", "challan"}

def extract_embedded_url(text: str) -> Optional[str]:
    """Extracts the first HTTP(S) or bare domain URL found in the SMS text."""
    if not text or not isinstance(text, str):
        return None
    matches = URL_PATTERN.findall(text)
    if matches:
        raw_url = matches[0].strip().rstrip(".,;:!)")
        return raw_url
    return None

def score_sms(text: str, sender: str, sms_bundle: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes baseline SMS score using TF-IDF + LogisticRegression bundle and rule-based heuristics."""
    reasons = []
    text_clean = str(text or "").strip()
    sender_clean = str(sender or "").strip()

    prob = 0.0
    if sms_bundle is not None:
        try:
            vectorizer = sms_bundle.get("vectorizer")
            clf = sms_bundle.get("model") or sms_bundle.get("classifier")
            if vectorizer and clf and text_clean:
                X_vec = vectorizer.transform([text_clean])
                prob = float(clf.predict_proba(X_vec)[0][1])
        except Exception as e:
            logger.warning(f"Error evaluating ML model on SMS text: {e}")

    # Rule 1: Raw Phone Number Sender
    if sender_clean and RAW_PHONE_PATTERN.match(sender_clean.replace(" ", "").replace("-", "")):
        prob = min(1.0, prob + RAW_PHONE_SENDER_BOOST)
        reasons.append(f"Unverified sender asking for sensitive action ({sender_clean})")

    # Rule 2: Shortened URL presence
    embedded_u = extract_embedded_url(text_clean)
    if embedded_u:
        for shortener in domain_engine.KNOWN_SHORTENERS:
            if shortener in embedded_u.lower():
                prob = min(1.0, prob + KNOWN_SHORTENER_BOOST)
                reasons.append(f"Shortened link with masked destination ({shortener})")
                break

    # Rule 3: Urgency + Financial Keyword Co-occurrence
    text_lower = text_clean.lower()
    has_urgency = any(uk in text_lower for uk in URGENCY_KEYWORDS)
    has_financial = any(fk in text_lower for fk in FINANCIAL_KEYWORDS)
    if has_urgency and has_financial:
        prob = min(1.0, prob + URGENCY_FINANCIAL_BOOST)
        reasons.append("High urgency panic language requesting immediate banking action")

    return {
        "probability": round(float(prob), 4),
        "reasons": reasons,
        "embedded_url": embedded_u
    }

def get_sms_verdict(
    text: str,
    sender: str,
    sms_bundle: Optional[Dict[str, Any]],
    domain_model: Any
) -> ScanVerdictResponse:
    """Cross-vector correlation engine: combines SMS NLP + lexical rules with embedded domain scanning."""
    try:
        if not text or not isinstance(text, str):
            return ScanVerdictResponse(
                verdict="SAFE",
                confidence=0.0,
                reasons=[],
                detail="Empty SMS message passed",
                status_code=200
            )

        sms_res = score_sms(text, sender, sms_bundle)
        final_prob = sms_res["probability"]
        all_reasons = list(sms_res["reasons"])

        # Cross-Channel Domain Inspection
        url_found = sms_res.get("embedded_url")
        if url_found:
            domain_verdict_obj = domain_engine.get_domain_verdict(url_found, domain_model)
            final_prob = max(final_prob, domain_verdict_obj.confidence)
            all_reasons.append(f"Contains deceptive URL: {url_found}")
            for r in domain_verdict_obj.reasons:
                if r not in all_reasons:
                    all_reasons.append(r)

        confidence = round(float(final_prob), 2)
        if confidence > FRAUD_THRESHOLD:
            verdict = "FRAUD"
            detail = "High-risk credential harvesting smishing message detected"
        elif confidence > SUSPICIOUS_THRESHOLD:
            verdict = "SUSPICIOUS"
            detail = "Suspicious unverified sender or link pattern detected"
        else:
            verdict = "SAFE"
        unique_reasons = list(dict.fromkeys(all_reasons)) if confidence > SUSPICIOUS_THRESHOLD else []
        display_reasons = get_display_messages(unique_reasons)

        # Cross-Channel Broadcast: Record threat into shared memory so Domain & Payment APIs know!
        if confidence > SUSPICIOUS_THRESHOLD:
            threat_memory.record_sms_threat(
                sender=sender,
                message=text,
                url=url_found,
                confidence=confidence
            )

        return ScanVerdictResponse(
            verdict=verdict,
            confidence=confidence,
            reasons=unique_reasons,
            display_reasons=display_reasons,
            detail=detail,
            source="sms",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Unexpected error in get_sms_verdict: {e}")
        fallback_reasons = ["scan_error_failed_open"]
        return ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=fallback_reasons,
            display_reasons=get_display_messages(fallback_reasons),
            detail="Scan completed with fail-open fallback",
            source="sms",
            status_code=200
        )
