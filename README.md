# ScamShield AI — Detect. Understand. Protect.

Functional defensive cybersecurity hackathon MVP built from the supplied specification.

## What works
- React + Vite responsive cybersecurity SaaS UI
- FastAPI REST backend
- PostgreSQL via Docker; SQLite fallback for quick local development
- Explainable rule-based message/email threat analysis
- Transparent 0–100 risk scoring and LOW/MODERATE/HIGH/CRITICAL bands
- Safe URL structure analysis without opening URLs
- Screenshot OCR pipeline using Tesseract when installed
- QR destination extraction using OpenCV when available
- Defensive incident-response checklists
- Dashboard, history-ready data model, feedback endpoint
- Demo examples
- Privacy guardrails and upload validation
- Safe fallback behavior if OCR/optional intelligence is unavailable

## Run with Docker
Requirements: Docker Desktop.

```bash
docker compose up --build
```

Open:
- Frontend: http://localhost:5173
- API: http://localhost:8000
- API docs: http://localhost:8000/docs

## Run locally without Docker
### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The backend defaults to SQLite if `DATABASE_URL` is not set. For PostgreSQL, set:
`postgresql+psycopg://USER:PASSWORD@HOST:5432/scamshield`

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## API endpoints
- `POST /api/analyze/message` — text analysis
- `POST /api/analyze/url` — URL structural analysis
- `POST /api/analyze/email` — email/social-engineering analysis
- `POST /api/analyze/screenshot` — OCR + text analysis
- `POST /api/analyze/qr` — QR decode + URL analysis
- `POST /api/incident-response` — recovery checklist
- `GET /api/history` — recent analysis records
- `GET /api/dashboard` — dashboard aggregates
- `POST /api/feedback` — anonymous-style helpfulness feedback
- `GET /health` — service health

## Demo flow (3–5 minutes)
1. Open Dashboard.
2. Click **Try Demo**.
3. Analyze the preloaded fake prize/job-style message.
4. Show the risk score, threat type, indicators, and safe actions.
5. Open URL Analyzer and load the demo URL.
6. Try Screenshot Analyzer or QR Safety with a safe sample image.
7. Open **I Already Clicked It** and select **I entered my password**.
8. Show the recovery checklist.
9. Return to Dashboard to show scan counts and recent activity.
10. Use Cyber Safety Center for the multilingual/education story.

## Security and privacy notes
- The application does **not** ask for passwords, OTPs, PINs, CVVs, recovery codes, or banking credentials.
- Submitted URLs are analyzed as strings; the prototype does not automatically browse to them.
- Uploads are type/size checked and never executed.
- API secrets belong in environment variables, not frontend code.
- Production deployment should add authentication, CSRF/session strategy where relevant, stronger rate limiting, object-storage lifecycle controls, centralized audit logging, CSP/security headers, dependency scanning, and a managed threat-intelligence provider.

## AI architecture
The prototype uses a hybrid-ready architecture:
`Input → preprocessing → deterministic security checks → feature extraction → optional threat intelligence → AI/classification layer → risk scoring → explanation → action/recovery`.

The current MVP keeps deterministic checks local and explainable so the product remains useful even when external AI or reputation services are unavailable. An external LLM/threat-intelligence adapter can be added under `backend/app/ai/` and `backend/app/services/` without changing the frontend contract.

## Risk scoring
The score is intentionally heuristic, not a proof of maliciousness. Indicators contribute weighted points and are normalized to 0–100. Results always display the limitation that false positives and false negatives are possible.

## Limitations
- New or highly targeted scams may not be recognized.
- URL reputation/domain-age intelligence is not connected by default.
- OCR can make recognition errors.
- Structural URL signals do not prove maliciousness.
- The score is an educational risk indicator, not a guarantee of security.
- The tool cannot replace banks, law enforcement, endpoint security, or professional incident-response teams.

## Suggested hackathon architecture slide
`React/Vite → FastAPI → Analysis Services → PostgreSQL`
with optional `Threat Intelligence` and `AI Explanation` services behind the backend.

## Suggested innovation slide
**DETECT → EXPLAIN → PROTECT → RECOVER → LEARN**

The differentiator is not merely classification: the prototype explains the observed signals, recommends a safe next action, provides post-incident recovery guidance, and teaches users how to recognize the same pattern later.
