# cross_channel_memory.py
"""
Cross-Channel Real-Time Threat Intelligence & Memory.
Enables active communication between:
1. SMS Smishing Engine (/scan-sms)
2. Domain & Phishing Heuristics (/scan-document, /scan-domain)
3. Payment Gateway & UPI Interceptor (/scan-payment)
"""
import time
import tldextract
from typing import Dict, Any, List, Optional, Tuple

class CrossChannelMemory:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        # Maps apex domain / URL -> smishing context
        self.flagged_domains: Dict[str, Dict[str, Any]] = {}
        # List of recent smishing campaign events
        self.recent_smish_events: List[Dict[str, Any]] = []

    def record_sms_threat(self, sender: str, message: str, url: Optional[str], confidence: float):
        """Records a flagged SMS smishing event and indexes any contained URLs/domains."""
        now = time.time()
        event = {
            "sender": sender,
            "message": message,
            "url": url,
            "confidence": confidence,
            "timestamp": now
        }
        self.recent_smish_events.append(event)
        
        # Keep only recent events within TTL
        self.recent_smish_events = [
            e for e in self.recent_smish_events if now - e["timestamp"] < self.ttl_seconds
        ]

        if url:
            url_clean = url.strip().lower()
            self.flagged_domains[url_clean] = event
            extracted = tldextract.extract(url_clean)
            if extracted.domain and extracted.suffix:
                apex = f"{extracted.domain}.{extracted.suffix}".lower()
                self.flagged_domains[apex] = event

    def check_url_in_sms_campaign(self, url: str) -> Tuple[bool, Optional[str]]:
        """Checks if an inspected domain/document URL was distributed in a recent SMS attack."""
        if not url:
            return False, None
        now = time.time()
        url_clean = url.strip().lower()
        extracted = tldextract.extract(url_clean)
        apex = f"{extracted.domain}.{extracted.suffix}".lower() if (extracted.domain and extracted.suffix) else ""

        for key in [url_clean, apex]:
            if key and key in self.flagged_domains:
                ctx = self.flagged_domains[key]
                if now - ctx["timestamp"] < self.ttl_seconds:
                    sender = ctx.get("sender", "Unknown")
                    return True, f"Chained Threat: URL was distributed via recent SMS smishing campaign (Sender: {sender})"
        return False, None

    def check_payment_threat_linkage(
        self,
        upi_vpa: str,
        gateway_url: str,
        transaction_note: Optional[str]
    ) -> Tuple[float, List[str]]:
        """
        Cross-checks payment checkout against active SMS and Domain intelligence.
        """
        penalty = 0.0
        reasons = []

        # 1. Gateway URL linked to SMS Smishing Lure
        if gateway_url:
            is_linked, note = self.check_url_in_sms_campaign(gateway_url)
            if is_linked and note:
                penalty += 0.85
                reasons.append(note)

        # 2. Transaction Note (tn) contains panic/fraud lures
        if transaction_note:
            tn_lower = transaction_note.lower()
            smish_phrases = ["electricity", "power cut", "kyc", "pan block", "unblock account", "fine", "challan", "loan apk", "reward claim"]
            matched_lures = [p for p in smish_phrases if p in tn_lower]
            if matched_lures:
                penalty += 0.40
                reasons.append(f"Chained Threat: Transaction note contains smishing trigger keywords ({', '.join(matched_lures)})")

        return penalty, reasons

# Global singleton memory instance
threat_memory = CrossChannelMemory()
