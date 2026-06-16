# 🛡️ Intelligent Web Fuzzing Platform — OWASP Top 10

> AI-powered web vulnerability scanner covering all **10/10 OWASP Top 10:2021** categories with CNN-LSTM deep learning classification.

Diploma project — 6B06301 Cybersecurity, Astana IT University, 2025  
**Authors:** Assima Zheniskyzy  
**Supervisor:** Alua Tanirbergenova, PhD

---

## What it does

Paste a URL — the platform automatically scans for all major web vulnerabilities, classifies findings using trained AI models, and generates a PDF report.

- No manual configuration
- No proxy setup
- One command to run

---

## Features

| Feature | Details |
|---|---|
| OWASP Coverage | All 10/10 Top 10:2021 categories |
| AI Classification | CNN-LSTM hybrid (SQLi F1=99%, XSS F1=99.7%) |
| Scan Modules | 8 parallel fuzzing modules |
| Auth | SHA-256 passwords, rate-limited endpoints |
| Security Headers | HSTS, X-Frame-Options, CSP via `@after_request` |
| Export | PDF report with severity grading |
| Deployment | Docker Compose — one command |

---

## Stack

```
Backend:   Python 3.12 · Flask · Flask-Limiter
Database:  SQLite (WAL mode, CASCADE deletes)
AI/ML:     TensorFlow/Keras · scikit-learn · CNN-LSTM · MLP · Isolation Forest
Fuzzing:   requests · BeautifulSoup4
Frontend:  Jinja2 · Vanilla JS · Satoshi + Inter fonts
DevOps:    Docker · Docker Compose
```

---

## Quick Start

```bash
git clone https://github.com/yourusername/intelligent-fuzzer.git
cd intelligent-fuzzer

# Download pre-trained models (see Models section below)
# Place them in /models folder

docker compose up
```

Open `http://localhost:5000` — register, paste a URL, scan.

---

## OWASP Top 10 Coverage

| Category | Detection Method |
|---|---|
| A01 Broken Access Control | Path enumeration, 403/401 detection |
| A02 Cryptographic Failures | HTTP/TLS check, HSTS audit, key exposure scan |
| A03 Injection (SQLi, XSS) | Error-based, blind time-delay, XSS reflection + CNN-LSTM |
| A04 Insecure Design | Debug trace / stack trace leakage detection |
| A05 Misconfiguration | Exposed .env/.git, CORS wildcard, header audit |
| A06 Vulnerable Components | Server banner grabbing, X-Powered-By fingerprint |
| A07 Auth Failures | Cookie Secure/HttpOnly flags, rate-limit indicators |
| A08 Integrity Failures | SRI check on CDN scripts, JSONP endpoint scan |
| A09 Logging Failures | CSP, HSTS, X-Frame-Options presence audit |
| A10 SSRF | Internal URL injection via redirect/url/path parameters |

---

## AI Models

### Architecture — CNN-LSTM Hybrid

```
Input (char sequence, maxlen=150)
    → Embedding (32-dim)
    → Conv1D (32 filters, kernel=3)
    → MaxPooling1D (pool=2)
    → LSTM (64 units)
    → Dropout (0.2)
    → Dense (1, sigmoid)
```

### Results

| Model | Task | Accuracy | Precision | Recall | MCC |
|---|---|---|---|---|---|
| Naive Bayes | SQLi | 95.9% | 90.6% | 98.6% | 0.913 |
| Random Forest | SQLi | 99.2% | 100% | 97.8% | 0.983 |
| **CNN-LSTM (ours)** | **SQLi** | **99.0%** | **100%** | **99.0%** | **0.988** |
| Naive Bayes | XSS | 99.4% | 99.5% | 99.5% | 0.995 |
| Random Forest | XSS | 99.7% | 100% | 99.5% | 0.995 |
| **CNN-LSTM (ours)** | **XSS** | **99.7%** | **99.9%** | **99.5%** | **0.994** |

### Download pre-trained models

> Models are not included in this repo due to file size.  
> Download from Google Drive and place in `/models`:

```
models/
├── sqli_hybrid_model.h5
├── xss_hybrid_model.h5
├── tokenizer_sqli.pkl
├── tokenizer_xss.pkl
├── sensitive_mlp_model.pkl
├── vectorizer.pkl
└── anomaly_config_detector.pkl
```


---

## Project Structure

```
├── main.py                  # Flask app, routes, OWASP mapping
├── database.py              # SQLite backend
├── ai_detector.py           # CNN-LSTM and MLP inference
├── fuzzer/
│   ├── injection_logic.py   # SQLi, XSS, SSRF fuzzing
│   ├── owasp.py             # A02, A05–A09 checks
│   └── recon.py             # Header audit, path enumeration
├── templates/               # Jinja2 HTML templates
├── static/                  # CSS
├── docker-compose.yml
└── requirements.txt
```

---

## Security

This tool is intended for **authorised security testing only**.  
Do not scan targets you do not own or have explicit permission to test.

---

## License

MIT License — free to use, modify, and distribute with attribution.
