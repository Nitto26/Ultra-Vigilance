# payment_engine.py
"""
Payment Gateway and UPI Fraud Interception Engine.
Performs cross-channel checks against SMS and Domain threat intelligence.
"""
import re
import logging
from typing import Set, Any, List, Optional
from schemas import ScanVerdictResponse
from cross_channel_memory import threat_memory
from reason_messages import get_display_messages
import domain_engine

logger = logging.getLogger(__name__)

# Hackathon-seeded placeholder database of reported malicious UPI IDs
KNOWN_FRAUD_UPI_IDS: Set[str] = {
    "fraudster123@upi",
    "scamvictim@ybl",
    "fakekyc@okaxis",
    "lotterywinner@paytm",
    "urgentrefund@ibl",
    "mseb-billpay@ybl",
    "sbi-yono-support@paytm"
}

LEGIT_BANK_HANDLES = {"@hdfcbank", "@icici", "@okaxis", "@oksbi", "@okicici", "@paytm", "@ybl", "@ibl", "@axl"}
TARGET_BRANDS_LOWER = {"hdfc", "sbi", "icici", "axis", "kotak", "pnb", "bob", "paytm", "phonepe", "gpay", "amazon", "flipkart", "support", "kyc", "refund"}

def check_payment_gateway(
    upi_id: str,
    gateway_url: str,
    domain_model: Any,
    upi_uri: Optional[str] = None,
    pa: Optional[str] = None,
    pn: Optional[str] = None,
    am: Optional[str] = None,
    tn: Optional[str] = None
) -> ScanVerdictResponse:
    """
    Evaluates UPI identifiers, transaction parameters, and checkout gateway URLs.
    Cross-checks with active SMS smishing and Domain threat memory.
    """
    try:
        target_vpa = (pa or upi_id or "").strip().lower()
        gateway_clean = str(gateway_url or "").strip()
        reasons: List[str] = []
        confidence = 0.0
        verdict = "SAFE"
        detail = "Payment gateway and recipient verified clean"

        # Signal 1: Reported Malicious UPI ID Lookup
        if target_vpa and target_vpa in KNOWN_FRAUD_UPI_IDS:
            reasons.append(f"Reported malicious recipient UPI ID ({target_vpa})")
            confidence = 1.0
            verdict = "FRAUD"
            detail = "Direct transfer to blacklisted fraudulent UPI VPA"

        # Signal 2: Fake Brand VPA Impersonation Heuristic
        # e.g. "hdfc-support99@ybl" or "sbi-kyc-verify@paytm" (Personal VPA impersonating bank authority)
        if target_vpa and "@" in target_vpa:
            user_part, handle_part = target_vpa.split("@", 1)
            handle_full = f"@{handle_part}"
            if any(b in user_part for b in ["support", "kyc", "refund", "customercare", "helpdesk", "officer"]):
                confidence = max(confidence, 0.88)
                reasons.append(f"Impersonated authority keyword in personal UPI ID ({target_vpa})")
            if any(b in user_part for b in TARGET_BRANDS_LOWER) and handle_full not in ["@hdfcbank", "@icici"]:
                confidence = max(confidence, 0.82)
                reasons.append(f"Brand impersonation in unverified personal UPI handle ({target_vpa})")

        # Signal 3: Cross-Channel Threat Memory Linkage (SMS smishing campaign)
        memory_penalty, memory_reasons = threat_memory.check_payment_threat_linkage(
            upi_vpa=target_vpa,
            gateway_url=gateway_clean,
            transaction_note=tn
        )
        if memory_penalty > 0:
            confidence = max(confidence, memory_penalty)
            reasons.extend(memory_reasons)

        # Signal 4: Gateway URL Domain Heuristics & ML
        if gateway_clean:
            gateway_verdict = domain_engine.get_domain_verdict(gateway_clean, domain_model)
            if gateway_verdict.confidence > confidence:
                confidence = gateway_verdict.confidence
                verdict = gateway_verdict.verdict
                detail = f"High-risk checkout gateway ({gateway_verdict.detail})"
            for r in gateway_verdict.reasons:
                reasons.append(f"Gateway host: {r}")

        # Final Verdict Bucketing
        confidence = round(float(confidence), 2)
        if confidence > 0.70:
            verdict = "FRAUD"
            if detail == "Payment gateway and recipient verified clean":
                detail = "High-risk fraudulent payment or impersonated UPI ID detected"
        elif confidence > 0.40:
            verdict = "SUSPICIOUS"
            detail = "Suspicious payment recipient or gateway signals detected"
        else:
            verdict = "SAFE"
        unique_reasons = list(dict.fromkeys(reasons)) if confidence > 0.40 else []
        display_reasons = get_display_messages(unique_reasons)

        return ScanVerdictResponse(
            verdict=verdict,
            confidence=confidence,
            reasons=unique_reasons,
            display_reasons=display_reasons,
            detail=detail,
            source="payment",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Unexpected error in check_payment_gateway: {e}")
        fallback_reasons = ["scan_error_failed_open"]
        return ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=fallback_reasons,
            display_reasons=get_display_messages(fallback_reasons),
            detail="Scan completed with fail-open fallback",
            source="payment",
            status_code=200
        )
