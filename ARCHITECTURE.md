# ScamShield AI — Architecture

```text
                         ┌───────────────────────────┐
                         │       React / Vite        │
                         │ Dashboard • Analyzers     │
                         │ Recovery • Education     │
                         └─────────────┬─────────────┘
                                       │ REST / JSON
                         ┌─────────────▼─────────────┐
                         │        FastAPI API        │
                         │ validation • CORS • APIs  │
                         └─────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
┌─────────▼─────────┐       ┌──────────▼──────────┐      ┌──────────▼─────────┐
│ Rule/Risk Engine  │       │ OCR / QR Services   │      │ Incident Guidance  │
│ indicators        │       │ Tesseract / OpenCV  │      │ safe checklists     │
│ explainability    │       │ never opens URLs    │      │ no secret inputs    │
└─────────┬─────────┘       └──────────┬──────────┘      └────────────────────┘
          │                            │
          └──────────────┬─────────────┘
                         ▼
                ┌─────────────────┐
                │ PostgreSQL      │
                │ minimal records │
                └─────────────────┘

 Optional production adapters:
 [Threat Intelligence] → reputation / domain age / known URL signals
 [AI Explanation]      → classification + natural-language explanation

 Safety boundary:
 User secrets are never requested or stored; submitted URLs are treated as data.
```
