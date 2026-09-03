# tests/test_allowlist_and_impersonation.py
"""
Test suite verifying Trusted Domain Allowlist, Subdomain Brand Impersonation,
and Reason-to-Display mappings.
"""
import pytest
import domain_engine
from reason_messages import get_display_message, get_display_messages

def test_trusted_domain_short_circuits():
    result = domain_engine.get_domain_verdict("https://docs.google.com/document/d/xyz", None)
    assert result.verdict == "SAFE"
    assert "known_trusted_domain" in result.reasons
    assert any("well-known, trusted website" in msg.lower() for msg in result.display_reasons)

def test_pinterest_not_flagged():
    result = domain_engine.get_domain_verdict("https://pinterest.com/pin/12345", None)
    assert result.verdict == "SAFE"
    assert "known_trusted_domain" in result.reasons

def test_brand_impersonation_on_shared_hosting():
    result = domain_engine.get_domain_verdict("https://sbi-kyc-verify-secure.vercel.app", None)
    assert result.verdict in ("SUSPICIOUS", "FRAUD")
    assert any("impersonates_sbi" in r for r in result.reasons)
    assert any("SBI" in msg for msg in result.display_reasons)

def test_brand_buried_in_longer_domain():
    result = domain_engine.get_domain_verdict("https://accounts-sbi-verify-login.tk", None)
    assert result.verdict in ("SUSPICIOUS", "FRAUD")
    assert any("impersonates_sbi" in r or "brand_name_in_subdomain" in r for r in result.reasons)

def test_display_messages_never_show_raw_codes():
    for reason_code in ["newly_registered_domain", "impersonates_hdfc", "domain_age_3_days", "totally_unknown_code_xyz"]:
        msg = get_display_message(reason_code)
        assert "_" not in msg  # No raw snake_case leaking into user-facing text
