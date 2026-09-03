# 🛡️ UltraVigilance (UV) — Complete Threat Testing & Verdict Matrix

This document provides all the testing conditions, decision rules, heuristic weights, and concrete test payloads for the three core inspection engines:
1. **Domain & Document Scanner** (`POST /scan-document` or `/scan-domain`)
2. **SMS Smishing Scanner** (`POST /scan-sms`)
3. **Payment Gateway & UPI Interceptor** (`POST /scan-payment`)

---

## 📊 Central Verdict Thresholds

Classification is determined by a continuous confidence score $C \in [0.0, 1.0]$:

| Verdict Badge | Confidence Range | Action / User Impact |
| :--- | :--- | :--- |
| 🟢 **SAFE** | $0.00 \le C \le 0.40$ | Navigation allowed, no blocking banner, green safety badge. |
| 🟡 **SUSPICIOUS (SUS)** | $0.41 \le C \le 0.70$ | Caution warning banner displayed, yellow toolbar badge alert. |
| 🔴 **FRAUD** | $0.71 \le C \le 1.00$ | Immediate full-screen blocking overlay, critical alert notification. |

---

## 🌐 1. Domain & Document Scanning Test Conditions

Evaluated via [`domain_engine.py`](file:///c:/Users/Nitto/Desktop/astrahackthon/UV/backend/domain_engine.py).

### 🟢 Domain: SAFE Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Allowlisted Domain** | Registered domain is listed in `trusted_domains.txt` (e.g. `google.com`, `sbi.co.in`, `github.com`). Fast O(1) exit. | `SAFE` | $\approx 0.02$ | `{"url": "https://www.google.com"}`<br/>`{"url": "https://retail.onlinesbi.sbi/retail/login.htm"}` |
| **Shortener leading to Trusted Domain** | Shortened link (e.g., `bit.ly`) expands to a verified trusted destination. | `SAFE` | $\approx 0.02$ | `{"url": "https://bit.ly/3legit-link"}` *(expands to google.com)* |
| **Standard Clean Domain** | Established domain (>14 days), HTTPS enabled, zero brand impersonation, zero suspicious TLD. | `SAFE` | $< 0.40$ | `{"url": "https://wikipedia.org/wiki/Computer_security"}` |

---

### 🟡 Domain: SUSPICIOUS (SUS) Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Unresolvable URL Shortener** | Shortened URL (`bit.ly`, `tinyurl.com`, `t.co`, etc.) that cannot be expanded (connection drops/timeout). | `SUSPICIOUS` | $0.65$ | `{"url": "https://bit.ly/nonexistent-broken-xyz-9821"}` |
| **Shared Platform Host (No Brand)** | Hosted on `vercel.app`, `netlify.app`, `firebaseapp.com`, `github.io` without explicit bank/brand keyword impersonation. | `SUSPICIOUS` | $0.40 - 0.60$ | `{"url": "https://my-simple-portfolio.netlify.app"}` |
| **High-Risk TLD Alone** | Top-Level Domain in high-risk list (`.xyz`, `.top`, `.click`, `.buzz`, `.club`, `.icu`, `.work`) on an otherwise benign name. | `SUSPICIOUS` | $0.45 - 0.65$ | `{"url": "https://garden-tools-store.xyz"}` |
| **Insecure HTTP + Suspicious Keywords** | Non-HTTPS connection coupled with keywords like `update`, `portal`, `alert`. | `SUSPICIOUS` | $0.45 - 0.65$ | `{"url": "http://user-portal-login.com"}` |

---

### 🔴 Domain: FRAUD Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Subdomain Brand Impersonation** | Subdomain contains a targeted brand name (e.g., `sbi`, `hdfc`, `paytm`, `paypal`, `google`) but registered domain is not the official brand. | `FRAUD` | $0.75 - 0.95$ | `{"url": "https://sbi-kyc-verification.free-host.com/login"}`<br/>`{"url": "https://hdfcbank.security-update.net"}` |
| **Shared Hosting + Brand Spoofing** | Subdomain on `vercel.app`, `firebaseapp.com`, `ngrok-free.app` impersonating a financial entity (`+0.50` boost). | `FRAUD` | $0.85 - 1.00$ | `{"url": "https://sbi-rewards-claim.vercel.app"}`<br/>`{"url": "https://icici-verify-login.firebaseapp.com"}` |
| **Direct Raw IP Host** | Target URL uses raw IPv4 address without a registered domain (`+0.40` boost). | `FRAUD` | $0.75 - 0.90$ | `{"url": "http://192.168.1.100/banking/login.php"}` |
| **Lookalike / High Hyphenation + Suspicious TLD** | Domain contains 2+ hyphens, urgency words, and `.top` / `.xyz` TLD. | `FRAUD` | $0.80 - 0.95$ | `{"url": "https://sbi-netbanking-portal-secure.top"}` |
| **Homoglyph / Punycode Deception** | Uses Punycode prefix (`xn--`) to disguise visual lookalike characters. | `FRAUD` | $0.75 - 0.90$ | `{"url": "https://xn--gogle-pra.com/login"}` |
| **SMS-Linked Smishing Campaign** | Domain was previously logged in `CrossChannelMemory` from an incoming smishing SMS within 1 hour. | `FRAUD` | $\ge 0.92$ | `{"url": "http://electricity-mseb-update.org"}` *(after SMS scan)* |

---

## 📱 2. SMS Smishing Scanning Test Conditions

Evaluated via [`sms_engine.py`](file:///c:/Users/Nitto/Desktop/astrahackthon/UV/backend/sms_engine.py).

### 🟢 SMS: SAFE Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Legitimate Bank Transaction Alert** | Official sender header (e.g., `VM-HDFCBK`, `AX-SBIINB`), standard OTP/transaction language, no external deceptive links. | `SAFE` | $< 0.20$ | `{"sender": "VM-HDFCBK", "text": "Dear Customer, INR 5,000.00 debited from A/C **1234 on 02-Sep-26. UPI Ref 498219. If not you, call 180026640."}` |
| **Delivery / Service Update** | Standard OTP or tracking notification without urgency/banking lures. | `SAFE` | $< 0.15$ | `{"sender": "AM-AMZIND", "text": "Your Amazon package is out for delivery. Share OTP 7492 with your delivery agent."}` |
| **Personal Conversational Text** | Message from friend/contact without financial extortion or phishing links. | `SAFE` | $0.00$ | `{"sender": "+919876543210", "text": "Hey, are we still meeting for lunch today at 1 PM?"}` |

---

### 🟡 SMS: SUSPICIOUS (SUS) Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Unverified Phone Sender with Shortlink** | Sent from a personal 10-digit number containing a generic shortened link (`+0.15` + `+0.25` boost). | `SUSPICIOUS` | $0.45 - 0.65$ | `{"sender": "+919812345678", "text": "Check out these new season photos from our trip: https://bit.ly/trip-pics"}` |
| **General Financial Alert from Personal Number** | Personal phone number asking about bill status without strong panic/threat triggers. | `SUSPICIOUS` | $0.40 - 0.60$ | `{"sender": "9876543210", "text": "Reminder: Your monthly subscription fee is due tomorrow. Please clear your dues."}` |

---

### 🔴 SMS: FRAUD Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Urgency + Financial Panic Lure from Raw Phone** | Co-occurrence of Urgency keywords (`urgent`, `blocked`, `suspended`, `power cut`, `disconnected`) AND Financial keywords (`pan`, `kyc`, `bill`, `account`, `fine`) from a 10-digit phone number. | `FRAUD` | $0.75 - 0.95$ | `{"sender": "+919123456789", "text": "URGENT: Your Electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Update immediately: http://mseb-bill.top"}` |
| **Fake Bank Account / PAN Block Extortion** | Claims bank account or PAN card is blocked and prompts immediate unblocking. | `FRAUD` | $0.80 - 1.00$ | `{"sender": "+919988776655", "text": "Dear SBI User, your YONO account is suspended today due to pending PAN KYC. Click here to verify within 24 hours: https://sbi-kyc-update.com"}` |
| **Chained Deceptive URL in SMS** | SMS contains an embedded link that scores as high-risk in the domain scanner. The higher domain risk propagates to SMS. | `FRAUD` | $\ge 0.85$ | `{"sender": "BW-ALERTS", "text": "Claim your pre-approved cashback reward of Rs 2,500 now: http://sbi-rewards.vercel.app"}` |
| **Traffic Challan / Court Fine Scam** | Panic fine payment notice sent from unverified number. | `FRAUD` | $0.78 - 0.95$ | `{"sender": "+919876501234", "text": "Traffic Police Notice: Pending e-challan of Rs 1,000 for vehicle. Pay immediately to avoid court summons: http://echallan-pay.xyz"}` |

---

## 💳 3. Payment Gateway & UPI Scanning Test Conditions

Evaluated via [`payment_engine.py`](file:///c:/Users/Nitto/Desktop/astrahackthon/UV/backend/payment_engine.py).

### 🟢 Payment: SAFE Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Verified Merchant / Official Bank Handle** | Standard genuine payee VPA with official banking handle (`@hdfcbank`, `@icici`, `@okaxis`, `@oksbi`) and clean transaction note. | `SAFE` | $0.00$ | `{"pa": "merchant.flipkart@icici", "pn": "Flipkart Internet", "am": "1499.00", "tn": "Order 982138"}` |
| **Normal P2P Transfer** | Personal UPI handle without bank impersonation keywords and clean note. | `SAFE` | $0.00$ | `{"pa": "rahul.sharma@okaxis", "pn": "Rahul Sharma", "am": "500.00", "tn": "Dinner split"}` |
| **Clean Gateway Checkout** | Verified legitimate checkout gateway URL. | `SAFE` | $0.00$ | `{"gateway_url": "https://api.razorpay.com/v1/checkout", "pa": "zomato@hdfcbank"}` |

---

### 🟡 Payment: SUSPICIOUS (SUS) Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Generic Urgency Note on Personal VPA** | Transaction note contains mild urgency keywords with normal personal recipient VPA. | `SUSPICIOUS` | $0.40 - 0.60$ | `{"pa": "nitin98@paytm", "pn": "Nitin Kumar", "am": "2500.00", "tn": "urgent clearance fee"}` |
| **Suspicious Checkout Gateway Host** | Payment gateway URL hosted on high-risk TLD or unverified portal without blacklisted VPA. | `SUSPICIOUS` | $0.50 - 0.70$ | `{"gateway_url": "https://secure-checkout-billing.online/pay", "pa": "shop99@ybl"}` |

---

### 🔴 Payment: FRAUD Conditions
| Trigger Condition | Rule Rationale | Expected Verdict | Confidence | Sample Test Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Known Reported Blacklisted UPI VPA** | Recipient VPA matches reported malicious fraudster database (`KNOWN_FRAUD_UPI_IDS`). | `FRAUD` | $1.00$ | `{"pa": "fraudster123@upi", "pn": "Refund Desk", "am": "5000.00"}`<br/>`{"pa": "fakekyc@okaxis", "pn": "KYC Verification"}`<br/>`{"pa": "mseb-billpay@ybl", "pn": "Electricity Department"}` |
| **Authority Keyword in Personal VPA** | Personal VPA user part contains authority keywords (`support`, `kyc`, `refund`, `customercare`, `helpdesk`, `officer`). | `FRAUD` | $0.88$ | `{"pa": "sbi-customercare-officer@paytm", "pn": "SBI Support"}`<br/>`{"pa": "electricity-refund-helpdesk@ybl", "pn": "MSEB Refund"}` |
| **Brand Impersonation in Unverified Handle** | Personal VPA user part contains brand names (`hdfc`, `sbi`, `icici`, `paytm`, `phonepe`, etc.) on third-party handles (`@ybl`, `@paytm`, `@ibl`). | `FRAUD` | $0.82$ | `{"pa": "hdfc-bank-verification@ybl", "pn": "HDFC Verification Desk"}`<br/>`{"pa": "phonepe-rewards-claim@okaxis", "pn": "PhonePe Rewards"}` |
| **Cross-Channel Linked Gateway Threat** | Checkout gateway URL matches domain distributed in a recent SMS smishing campaign (`+0.85` penalty). | `FRAUD` | $\ge 0.85$ | `{"gateway_url": "http://mseb-bill.top/checkout.php", "pa": "collection@ybl"}` |
| **Panic / Smishing Lure in Transaction Note (`tn`)** | Transaction note contains smishing trigger keywords (`electricity`, `power cut`, `pan block`, `kyc`, `challan`, `loan apk`, `reward claim`). | `FRAUD` | $0.70 - 0.88$ | `{"pa": "quickpay99@ybl", "am": "10.00", "tn": "Electricity Power Cut Unblock Fee"}` |

---

## 🔗 4. Cross-Channel Chained Attack Simulation Matrix

Test these multi-step scenarios to verify end-to-end defense orchestration:

```
Scenario 1: Power Cut Smishing -> Fake Domain -> Fake UPI Payee
-----------------------------------------------------------------------------
Step 1 [SMS Scanner]:
  POST /scan-sms
  Payload: {"sender": "+919876543210", "text": "Urgent! Electricity power cut at 9:30PM. Update bill: http://mseb-urgent.top"}
  Expected: FRAUD (Confidence ~0.90), Domain "mseb-urgent.top" saved to Memory.

Step 2 [Domain Scanner]:
  POST /scan-document
  Payload: {"url": "http://mseb-urgent.top/pay"}
  Expected: FRAUD (Confidence >= 0.92) - Reason: "cross_channel_lure"

Step 3 [Payment Scanner]:
  POST /scan-payment
  Payload: {"pa": "mseb-support@ybl", "gateway_url": "http://mseb-urgent.top/checkout", "tn": "Electricity power cut fine"}
  Expected: FRAUD (Confidence >= 0.90) - Multiple Chained Threat Reasons.
```

---

## 🧪 5. Ready-to-Run cURL Test Commands

### Test 1: Scan Legit Domain (SAFE)
```bash
curl -X POST "http://127.0.0.1:8000/scan-document" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://www.onlinesbi.sbi"}'
```

### Test 2: Scan Phishing Domain with Subdomain Spoofing (FRAUD)
```bash
curl -X POST "http://127.0.0.1:8000/scan-document" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://sbi-login.vercel.app"}'
```

### Test 3: Scan Smishing SMS (FRAUD)
```bash
curl -X POST "http://127.0.0.1:8000/scan-sms" \
     -H "Content-Type: application/json" \
     -d '{"sender": "+919999988888", "text": "Your HDFC NetBanking is suspended. Update KYC immediately: http://hdfc-kyc.top"}'
```

### Test 4: Scan Spoofed Bank VPA (FRAUD)
```bash
curl -X POST "http://127.0.0.1:8000/scan-payment" \
     -H "Content-Type: application/json" \
     -d '{"pa": "hdfc-support-desk@ybl", "pn": "Customer Care", "am": "1.00", "tn": "KYC Verification"}'
```

### Test 5: Scan Legitimate UPI Payment (SAFE)
```bash
curl -X POST "http://127.0.0.1:8000/scan-payment" \
     -H "Content-Type: application/json" \
     -d '{"pa": "zomato@hdfcbank", "pn": "Zomato Ltd", "am": "350.00", "tn": "Lunch order #4810"}'
```
