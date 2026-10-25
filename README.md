# Scam Saathi 🛡️

**Pause. Check. Stay Safe.**

AI-powered multilingual scam detection for Indian users. Paste a suspicious SMS, WhatsApp, or email message and instantly receive a structured risk assessment, evidenced warning signs, and practical safety advice — in your preferred Indian language.

---

## What Scam Saathi Does

- **Detects scam patterns** in messages: banking OTP fraud, fake parcel fees, job scams, government impersonation, UPI fraud, and more.
- **Supports 10 Indian languages** as output: English, हिन्दी, বাংলা, தமிழ், తెలుగు, मराठी, ગુજરાતી, ಕನ್ನಡ, മലയാളം, ਪੰਜਾਬੀ.
- **Handles Hinglish** and transliterated Hindi input naturally.
- **Provides calibrated risk ratings**: High, Medium, Low, or Uncertain — always evidence-based.
- **Gives emergency recovery advice** when the user may have already responded to a scam.
- **Works without any API key** in Demo Mode (rule-based analysis).
- **Never stores messages**, requires login, or exposes API keys to the browser.

---

## Technical Architecture

| Layer | Technology |
|-------|------------|
| Backend API | Python + FastAPI |
| AI Integration | Google Gemini API (`google-generativeai`) |
| Frontend | Vanilla HTML + CSS + JavaScript |
| Static Serving | FastAPI StaticFiles |
| Config | python-dotenv (`.env` file) |

### Agent Pipeline

Four agents with distinct responsibilities, running sequentially:

1. **Bhasha Agent** — Detects message language (Hindi, Hinglish, English, other Indian scripts). Preserves original text for evidence extraction.
2. **Risk Analyst** — Identifies scam indicators: OTP/PIN requests, urgent threats, payment demands, impersonation, suspicious links. Returns structured evidence tied to the original message.
3. **Safety Advisor** — Recommends proportionate, practical protective actions. Includes emergency recovery checklist for financial cyber fraud (with Indian helpline 1930).
4. **Bhasha Explainer** — Presents findings in the user's selected output language with plain, accessible explanations.

In **AI Mode**: these agents are coordinated through a single structured Gemini model call with a carefully engineered prompt that enforces each agent's responsibilities and output schema.

In **Demo Mode**: each agent is implemented as a deterministic, rule-based Python function with no external dependencies.

---

## Prerequisites

- Python 3.10+ (Python 3.14 tested)
- pip

---

## Installation

```bash
# 1. Clone / open the project
cd scam_saathi

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy environment template
copy .env.example .env
```

---

## Configuring the Gemini API Key (Optional)

Edit `.env`:

```
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-1.5-flash
```

Get a free key at: https://aistudio.google.com/app/apikey

> **Security note**: The API key is read only on the server side. It is never sent to the browser or included in any client-side code, bundle, or URL.

Leave `GEMINI_API_KEY` empty to run in Demo Mode.

---

## Running Locally

```bash
# From the project root
python backend/main.py
```

Or with uvicorn directly:

```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser at: **http://localhost:8000**

---

## Demo Mode

When `GEMINI_API_KEY` is not configured, the application runs in **Demo Mode**:

- A clearly labelled "Demo Mode" badge appears in the header and on results.
- All analysis is performed by local rule-based Python functions — no external API calls.
- The four agent functions still run sequentially with distinct responsibilities.
- All sample messages work correctly in Demo Mode.
- Results are deterministic and reproducible without an internet connection.

Demo Mode is explicitly distinguished from live AI results in the UI. It will never present rule-based results as though they came from a live AI model.

---

## Adding or Changing Supported Languages

1. **Frontend** (`frontend/index.html`): Add an `<option>` to the `#output-language` select element.
2. **Backend** (`backend/main.py`): Add the language code to the `allowed` set in `validate_language`.
3. **AI Mode**: The Gemini prompt passes the output language code; the model handles localization automatically.
4. **Demo Mode**: Results are returned in English regardless of output language selection (the AI model is what performs translation in AI Mode).

---

## Known Limitations

- **Demo Mode output language**: The rule-based agent pipeline returns results in English only. Full multilingual output requires a configured Gemini API key.
- **False negatives**: Scam messages without standard keyword patterns may not be flagged by Demo Mode.
- **False positives**: Legitimate messages that use urgent language may receive a medium risk rating.
- **Identity verification**: No analysis of the message text can verify the sender's identity. The tool makes this explicit in every result.
- **Short messages**: Messages with fewer than ~10 characters receive an "Uncertain" rating.
- **Language detection**: Demo Mode uses Unicode block matching and keyword heuristics. The AI model provides more accurate detection.

---

## Privacy Behavior

- Messages are **not stored** on the server by default. They are only held in memory for the duration of a single API request.
- No user registration, authentication, or session tracking.
- No logging of raw message content.
- In AI Mode, messages are sent to Google's Gemini API for processing. Review [Google's Privacy Policy](https://policies.google.com/privacy).
- In Demo Mode, no data leaves your local server.
- The application never requests OTPs, UPI PINs, passwords, or payment credentials.

---

## Reporting Financial Cyber Fraud (India)

- **Helpline**: 1930
- **Portal**: https://www.cybercrime.gov.in

---

## Project Structure

```
scam_saathi/
├── backend/
│   ├── main.py          # FastAPI app, /api/analyze endpoint
│   └── agents.py        # Four-agent pipeline (AI + Demo Mode)
├── frontend/
│   ├── index.html       # Single-page app shell
│   └── static/
│       ├── style.css    # Complete design system
│       └── app.js       # UI state machine + API client
├── .env.example         # Environment template (no real secrets)
├── requirements.txt     # Python dependencies
└── README.md
```
