# Code Migration Map

This document outlines how legacy code was refactored or replaced to become part of the new VAULT-Aegis architecture.

---

## API Gateway

| Old Component | New Module | Notes |
|---------------|------------|-------|
| gateway_v1.py | `api_gateway/middleware.py` | Split into separate middleware flows |
| inline auth logic | `api_gateway/auth.py` | Centralized auth, improved policy checks |
| manual routing | `api_gateway/router.py` | FastAPI routers with policy injection |

---

## Threat Engine

| Old Component | New Module |
|---------------|------------|
| threat_detector.py | `threat_engine/detector.py` |
| risk_scoring_legacy.py | `threat_engine/risk_scoring.py` |
| basic filters | `policy_manager.py` |

---

## PII Sanitizer (NEW)

| Legacy Logic | New Module |
|--------------|------------|
| none | `pii_sanitizer/*` | Entirely new stand-alone sensitive data filter |

---

## AI Guardrails

| Before | Now |
|--------|-----|
| inline LLM calls | `ai_guardrails/model_wrapper.py` |
| basic pre/post filters | `input_filter.py`, `output_filter.py` |

---

## Vault Scanner

| Legacy Script | New Module |
|---------------|------------|
| scanner.py | `vault_scanner/file_scanner.py` |
| docscan.py | `vault_scanner/document_analyzer.py` |

---

## Logging

| Before | Now |
|--------|-----|
| unstructured logs | `logging/audit_logger.py` |
| mixed logs | `logging/secure_logger.py` |

---

## Dashboard

| Legacy UI | Now |
|------------|-----|
| no UI | `dashboard/streamlit_app.py` |

---

## Notes

All modules were refactored for:
- Security enforcement
- Modularity
- Testability
- Compliance with OWASP and AI threat models

---

End of Code Migration Map
