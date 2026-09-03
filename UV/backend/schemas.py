# schemas.py
"""
Pydantic Request and Response Schemas for UV- Ultra Vigilance.
Matches the exact schema expected by UltraVigilance Android App & Chrome Extension.
Supports polymorphic field aliases (e.g. url/link/target_url, message/text/body).
"""
from typing import List, Optional
from pydantic import BaseModel, Field

# Unified Response Model
class ScanVerdictResponse(BaseModel):
    verdict: str = Field(..., description="'FRAUD' | 'SUSPICIOUS' | 'SAFE' | 'UNKNOWN' (exact uppercase)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Risk level float from 0.0 to 1.0")
    reasons: List[str] = Field(default_factory=list, description="List of explanatory bullet strings")
    display_reasons: List[str] = Field(default_factory=list, description="List of user-facing human readable reasons")
    detail: Optional[str] = Field(default=None, description="Summary description string")
    source: Optional[str] = Field(default="domain", description="Detection origin channel")
    status_code: Optional[int] = Field(default=200, description="HTTP status code indicator")

# Alias for backwards compatibility
VerdictResponse = ScanVerdictResponse

# Request Models
class ScanDocumentRequest(BaseModel):
    url: Optional[str] = Field(default="", description="Target document or domain URL to inspect")
    link: Optional[str] = Field(default=None, description="Alternative field for link URL")
    target_url: Optional[str] = Field(default=None, description="Alternative field for target URL")

    def get_url(self) -> str:
        return (self.url or self.link or self.target_url or "").strip()

class URLRequest(ScanDocumentRequest):
    pass

class ScanSmsRequest(BaseModel):
    sender: Optional[str] = Field(default="", description="Sender header or phone number")
    message: Optional[str] = Field(default=None, description="SMS message body")
    text: Optional[str] = Field(default=None, description="Alternative field for SMS text")
    body: Optional[str] = Field(default=None, description="Alternative field for SMS body (Android native)")

    def get_text(self) -> str:
        return (self.message or self.text or self.body or "").strip()

class SMSRequest(ScanSmsRequest):
    pass

class ScanPaymentRequest(BaseModel):
    upi_id: Optional[str] = Field(default="", description="Target UPI VPA identifier")
    gateway_url: Optional[str] = Field(default="", description="Payment checkout or gateway URL")
    upi_uri: Optional[str] = Field(default="", description="Full UPI Intent URI string (upi://pay?...)")
    pa: Optional[str] = Field(default=None, description="Payee VPA address (e.g. merchant@upi)")
    pn: Optional[str] = Field(default=None, description="Payee display name")
    am: Optional[str] = Field(default=None, description="Transaction amount")
    cu: Optional[str] = Field(default=None, description="Currency code (e.g. INR)")
    tn: Optional[str] = Field(default=None, description="Transaction note")

    def get_vpa(self) -> str:
        return (self.pa or self.upi_id or "").strip()

class PaymentRequest(ScanPaymentRequest):
    pass
