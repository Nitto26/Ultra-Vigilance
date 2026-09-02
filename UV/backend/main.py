# main.py
"""
FastAPI Backend for UV- Ultra Vigilance.
Exposes real-time endpoints for Domain Heuristics, SMS Pattern Analysis, and Payment Checks
with cross-channel real-time threat communication and terminal logging.
"""
import os
import logging
from typing import Optional, Dict, Any
import joblib
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import DOMAIN_MODEL_PATH, SMS_MODEL_PATH
from schemas import (
    ScanVerdictResponse,
    ScanDocumentRequest,
    ScanSmsRequest,
    ScanPaymentRequest
)
from cross_channel_memory import threat_memory
import domain_engine
import sms_engine
import payment_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("uv.backend")

# --- Model Loading (Loaded ONCE at module level) ---
domain_model: Optional[Any] = None
sms_bundle: Optional[Dict[str, Any]] = None

try:
    if os.path.exists(DOMAIN_MODEL_PATH):
        domain_model = joblib.load(DOMAIN_MODEL_PATH)
        logger.info(f"Successfully loaded Domain XGBoost model from {DOMAIN_MODEL_PATH}")
    else:
        logger.warning(f"Domain model file not found at {DOMAIN_MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load domain model: {e}")
    domain_model = None

try:
    if os.path.exists(SMS_MODEL_PATH):
        sms_bundle = joblib.load(SMS_MODEL_PATH)
        logger.info(f"Successfully loaded SMS Smishing bundle from {SMS_MODEL_PATH}")
    else:
        logger.warning(f"SMS model file not found at {SMS_MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load SMS model bundle: {e}")
    sms_bundle = None

app = FastAPI(
    title="UV - Ultra Vigilance API",
    description="Cross-Channel Cyber Fraud, Smishing & Payment Interception Engine",
    version="1.0.0"
)

# Enable CORS for external extensions and Android app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception caught on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=200,
        content={
            "verdict": "SAFE",
            "confidence": 0.0,
            "reasons": [],
            "detail": "Scan completed with fail-open fallback",
            "status_code": 200
        }
    )

# --- Helper for Terminal Inspection Logs (ASCII-safe for Windows cp1252) ---
def log_transaction(endpoint: str, req_info: Dict[str, Any], res: ScanVerdictResponse):
    try:
        print("\n" + "=" * 78)
        print(f">> INCOMING REQUEST: {endpoint}")
        for k, v in req_info.items():
            if v:
                print(f" * {k:<18}: {v}")
        print("-" * 78)
        verdict_badge = f"[{res.verdict}]"
        print(f">> ENGINE RESPONSE:")
        print(f" * Verdict / Result  : {verdict_badge}")
        print(f" * Confidence        : {res.confidence:.2f} ({res.confidence * 100:.1f}%)")
        if res.reasons:
            print(f" * Reasons           : {'; '.join(res.reasons)}")
        if res.detail:
            print(f" * Detail            : {res.detail}")
        print("=" * 78 + "\n")
    except Exception as e:
        logger.debug(f"Log printing skipped: {e}")

# --- Endpoints ---

@app.get("/health")
def health_check():
    """Sanity check endpoint reporting system status, models, and threat memory."""
    return {
        "status": "ok",
        "domain_model_loaded": domain_model is not None,
        "sms_model_loaded": sms_bundle is not None,
        "active_threat_campaigns": len(threat_memory.recent_smish_events)
    }

# Endpoint 1: Document & Domain Scanning
@app.post("/scan-document", response_model=ScanVerdictResponse)
@app.post("/scan-domain", response_model=ScanVerdictResponse)
def scan_document(req: ScanDocumentRequest):
    """Evaluates a URL against lexical heuristics, WHOIS recency, and cross-channel SMS smishing memory."""
    if domain_model is None:
        res = ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=[],
            detail="Domain model unavailable",
            status_code=200
        )
    else:
        res = domain_engine.get_domain_verdict(req.url, domain_model)

    log_transaction(
        endpoint="POST /scan-document",
        req_info={"Target URL": req.url},
        res=res
    )
    return res

# Endpoint 2: SMS Scanning
@app.post("/scan-sms", response_model=ScanVerdictResponse)
def scan_sms(req: ScanSmsRequest):
    """Evaluates SMS text for smishing triggers, phone headers, and cross-channel links."""
    text = req.get_text()
    sender = req.sender or "UNKNOWN"

    if sms_bundle is None:
        res = ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=[],
            detail="SMS model bundle unavailable",
            status_code=200
        )
    else:
        res = sms_engine.get_sms_verdict(
            text=text,
            sender=sender,
            sms_bundle=sms_bundle,
            domain_model=domain_model
        )

    log_transaction(
        endpoint="POST /scan-sms",
        req_info={"Sender / User": sender, "Message Content": text},
        res=res
    )
    return res

# Endpoint 3: Payment Gateway & UPI Scanning (Direct Android UPI Intercept)
@app.post("/scan-payment", response_model=ScanVerdictResponse)
def scan_payment(req: ScanPaymentRequest):
    """Evaluates UPI VPA parameters, transaction notes, and checkout gateway URLs."""
    try:
        vpa = req.get_vpa()
        gateway = req.gateway_url or ""

        res = payment_engine.check_payment_gateway(
            upi_id=vpa,
            gateway_url=gateway,
            domain_model=domain_model,
            upi_uri=req.upi_uri,
            pa=req.pa,
            pn=req.pn,
            am=req.am,
            tn=req.tn
        )

        log_transaction(
            endpoint="POST /scan-payment",
            req_info={
                "Payee VPA (pa)": vpa or "(None)",
                "Payee Name (pn)": req.pn or "(None)",
                "Amount (am)": req.am or "(None)",
                "Note (tn)": req.tn or "(None)",
                "Gateway URL": gateway or "(None)"
            },
            res=res
        )
        return res
    except Exception as e:
        logger.error(f"Explicit error in scan_payment: {e}", exc_info=True)
        return ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=[],
            detail="Scan completed with fail-open fallback",
            status_code=200
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
